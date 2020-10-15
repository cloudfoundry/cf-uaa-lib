#--
# Cloud Foundry
# Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache License, Version 2.0 (the "License").
# You may not use this product except in compliance with the License.
#
# This product includes a number of subcomponents with
# separate copyright notices and license terms. Your use of these
# subcomponents is subject to the terms and conditions of the
# subcomponent's license, as noted in the LICENSE file.
#++

require 'set'
require 'spec_helper'
require 'uaa/token_issuer'

module CF::UAA

describe TokenIssuer do

  let(:options) { {} }

  before do
    #Util.default_logger(:trace)
    @issuer = TokenIssuer.new('http://test.uaa.target', 'test_client', 'test_secret', options)
  end

  subject { @issuer }

  describe 'initialize' do
    let(:options) { {http_proxy: 'http-proxy.com', https_proxy: 'https-proxy.com', skip_ssl_validation: true} }

    it 'sets skip_ssl_validation' do
      subject.skip_ssl_validation == true
    end
  end

  context 'with client credentials grant' do

    it 'gets a token with client credentials' do
      subject.set_request_handler do |url, method, body, headers|
        headers['content-type'].should =~ /application\/x-www-form-urlencoded/
        headers['accept'].should =~ /application\/json/
        # TODO check basic auth header
        url.should == 'http://test.uaa.target/oauth/token'
        method.should == :post
        reply = {access_token: 'test_access_token', token_type: 'BEARER',
            scope: 'logs.read', expires_in: 98765}
        [200, Util.json(reply), {'content-type' => 'application/json'}]
      end
      token = subject.client_credentials_grant('logs.read')
      token.should be_an_instance_of TokenInfo
      token.info['access_token'].should == 'test_access_token'
      token.info['token_type'].should =~ /^bearer$/i
      token.info['scope'].should == 'logs.read'
      token.info['expires_in'].should == 98765
    end

    it 'gets all granted scopes if none specified' do
      subject.set_request_handler do |url, method, body, headers|
        reply = {access_token: 'test_access_token', token_type: 'BEARER',
            scope: 'openid logs.read', expires_in: 98765}
        [200, Util.json(reply), {'content-type' => 'application/json'}]
      end
      token = subject.client_credentials_grant
      Util.arglist(token.info['scope']).to_set.should == Util.arglist('openid logs.read').to_set
    end

    it 'raises a bad response error if response content type is not json' do
      subject.set_request_handler { [200, 'not json', {'content-type' => 'text/html'}] }
      expect {subject.client_credentials_grant}.to raise_exception BadResponse
    end

    it 'raises a bad response error if the response is not proper json' do
      subject.set_request_handler { [200, 'bad json', {'content-type' => 'application/json'}] }
      expect {subject.client_credentials_grant}.to raise_exception BadResponse
    end

    it 'raises a target error if the response is 400 with valid oauth json error' do
      subject.set_request_handler { [400, '{"error":"invalid scope"}', {'content-type' => 'application/json'}] }
      expect {subject.client_credentials_grant('bad.scope')}.to raise_exception TargetError
    end
  end

  context 'with owner password grant' do

    it 'gets a token with owner password' do
      subject.set_request_handler do |url, method, body, headers|
        headers['content-type'].should =~ /application\/x-www-form-urlencoded/
        headers['accept'].should =~ /application\/json/
        # TODO check basic auth header
        url.should == 'http://test.uaa.target/oauth/token'
        method.should == :post
        reply = {access_token: 'test_access_token', token_type: 'BEARER',
            scope: 'openid', expires_in: 98765}
        [200, Util.json(reply), {'content-type' => 'application/json'}]
      end
      token = subject.owner_password_grant('joe+admin', "?joe's%password$@ ", 'openid')
      token.should be_an_instance_of TokenInfo
      token.info['access_token'].should == 'test_access_token'
      token.info['token_type'].should =~ /^bearer$/i
      token.info['scope'].should == 'openid'
      token.info['expires_in'].should == 98765
    end

    it 'gets a token with passcode' do
      subject.set_request_handler do |url, method, body, headers|
        headers['content-type'].should =~ /application\/x-www-form-urlencoded/
        headers['accept'].should =~ /application\/json/
        # TODO check basic auth header
        url.should == 'http://test.uaa.target/oauth/token'
        body.should =~ /(^|&)passcode=12345($|&)/
        body.should =~ /(^|&)grant_type=password($|&)/
        method.should == :post
        reply = {access_token: 'test_access_token', token_type: 'BEARER',
                 scope: 'openid', expires_in: 98765}
        [200, Util.json(reply), {'content-type' => 'application/json'}]
      end
      token = subject.passcode_grant('12345')
      token.should be_an_instance_of TokenInfo
      token.info['access_token'].should == 'test_access_token'
      token.info['token_type'].should =~ /^bearer$/i
      token.info['scope'].should == 'openid'
      token.info['expires_in'].should == 98765
    end

  end

  describe '#owner_password_credentials_grant' do
    it 'gets a token grant type password' do
      subject.set_request_handler do |url, method, body, headers|
        headers['content-type'].should =~ /application\/x-www-form-urlencoded/
        headers['accept'].should =~ /application\/json/
        url.should == 'http://test.uaa.target/oauth/token'
        method.should == :post
        body.split('&').should =~ ['passcode=fake-passcode', 'grant_type=password']
        reply = {access_token: 'test_access_token', token_type: 'BEARER',
          scope: 'openid', expires_in: 98765}
        [200, Util.json(reply), {'content-type' => 'application/json'}]
      end
      token = subject.owner_password_credentials_grant({passcode: 'fake-passcode'})
      token.should be_an_instance_of TokenInfo
      token.info['access_token'].should == 'test_access_token'
      token.info['token_type'].should =~ /^bearer$/i
      token.info['scope'].should == 'openid'
      token.info['expires_in'].should == 98765
    end

  end

  context 'with implicit grant' do

    it 'gets the prompts for credentials used to authenticate implicit grant' do
      subject.set_request_handler do |url, method, body, headers|
        info = { prompts: {username: ['text', 'Username'], password: ['password', 'Password']} }
        [200, Util.json(info), {'content-type' => 'application/json'}]
      end
      result = subject.prompts
      result.should_not be_empty
    end

    it 'raises a bad target error if no prompts are received' do
      subject.set_request_handler do |url, method, body, headers|
        [200, Util.json({}), {'content-type' => 'application/json'}]
      end
      expect { subject.prompts }.to raise_exception BadResponse
    end

    context '#implicit_grant_with_creds' do
      it 'gets only an access token, no openid in scope' do
        subject.set_request_handler do |url, method, body, headers|
          headers['content-type'].should =~ /application\/x-www-form-urlencoded/
          headers['accept'].should =~ /application\/json/
          url.should match 'http://test.uaa.target/oauth/authorize'
          (state = /state=([^&]+)/.match(url)[1]).should_not be_nil
          method.should == :post
          location = 'https://uaa.cloudfoundry.com/redirect/test_client#' +
              'access_token=test_access_token&token_type=bearer&' +
              "expires_in=98765&scope=logs.read&state=#{state}"
          [302, nil, {'content-type' => 'application/json', 'location' => location}]
        end

        expect(subject).to receive(:authorize_path_args).with('token', 'https://uaa.cloudfoundry.com/redirect/test_client', 'logs.read', anything)
        subject.stub(:random_state).and_return('1234')
        subject.stub(:authorize_path_args).and_return('/oauth/authorize?state=1234&scope=logs.read')

        token = subject.implicit_grant_with_creds({username: 'joe+admin', password: "?joe's%password$@ "}, 'logs.read')
        token.should be_an_instance_of TokenInfo
        token.info['access_token'].should == 'test_access_token'
        token.info['token_type'].should =~ /^bearer$/i
        Util.arglist(token.info['scope']).to_set.should == Util.arglist('logs.read').to_set
        token.info['expires_in'].should == 98765
      end

      it 'also asks for an id_token if scope contains openid' do
        subject.set_request_handler do |url, method, body, headers|
          location = 'https://uaa.cloudfoundry.com/redirect/test_client#' +
              'access_token=test_access_token&id_token=test-id_token&token_type=bearer&' +
              'expires_in=98765&scope=openid+logs.read&state=1234'
          [302, nil, {'content-type' => 'application/json', 'location' => location}]
        end

        expect(subject).to receive(:authorize_path_args).with('token id_token', 'https://uaa.cloudfoundry.com/redirect/test_client', 'openid logs.read', anything)
        subject.stub(:random_state).and_return('1234')
        subject.implicit_grant_with_creds({username: 'joe+admin', password: "?joe's%password$@ "}, 'openid logs.read')
      end
    end

    it 'rejects an access token with wrong state' do
      subject.set_request_handler do |url, method, body, headers|
        location = 'https://uaa.cloudfoundry.com/redirect/test_client#' +
            'access_token=test_access_token&token_type=bearer&' +
            'expires_in=98765&scope=openid+logs.read&state=bad_state'
        [302, nil, {'content-type' => 'application/json', 'location' => location}]
      end
      expect {token = subject.implicit_grant_with_creds(username: 'joe+admin',
          password: "?joe's%password$@ ")}.to raise_exception BadResponse
    end

    it 'asks for an id_token with openid scope' do
      uri_parts = subject.implicit_uri('http://call.back/uri_path', 'openid logs.read').split('?')
      params = Util.decode_form(uri_parts[1])
      params['response_type'].should == 'token id_token'
    end

    it "only asks for token if scope isn't openid" do
      uri_parts = subject.implicit_uri('http://call.back/uri_path').split('?')
      params = Util.decode_form(uri_parts[1])
      params['response_type'].should == 'token'
    end

  end

  context 'with auth code grant' do

    it 'gets the authcode uri to be sent to the user agent for an authcode' do
      redir_uri = 'http://call.back/uri_path'
      uri_parts = subject.authcode_uri(redir_uri, 'openid').split('?')
      uri_parts[0].should == 'http://test.uaa.target/oauth/authorize'
      params = Util.decode_form(uri_parts[1])
      params['response_type'].should == 'code'
      params['client_id'].should == 'test_client'
      params['scope'].should == 'openid'
      params['redirect_uri'].should == redir_uri
      params['state'].should_not be_nil
    end

    it 'gets an access token with an authorization code' do
      subject.set_request_handler do |url, method, body, headers|
        headers['content-type'].should =~ /application\/x-www-form-urlencoded/
        headers['accept'].should =~ /application\/json/
        # TODO check basic auth header
        url.should match 'http://test.uaa.target/oauth/token'
        method.should == :post
        reply = {access_token: 'test_access_token', token_type: 'BEARER',
            scope: 'openid', expires_in: 98765}
        [200, Util.json(reply), {'content-type' => 'application/json'}]
      end
      cburi = 'http://call.back/uri_path'
      redir_uri = subject.authcode_uri(cburi)
      state = /state=([^&]+)/.match(redir_uri)[1]
      reply_query = "state=#{state}&code=kz8%2F5gQZ2pc%3D"
      token = subject.authcode_grant(redir_uri, reply_query)
      token.should be_an_instance_of TokenInfo
      token.info['access_token'].should == 'test_access_token'
      token.info['token_type'].should =~ /^bearer$/i
      token.info['scope'].should == 'openid'
      token.info['expires_in'].should == 98765
    end

  end

end

end
