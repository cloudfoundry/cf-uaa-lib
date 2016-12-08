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

require 'spec_helper'
require 'uaa'
require 'pp'

# Example config for integration tests with defaults:
#    ENV["UAA_CLIENT_ID"] = "admin"
#    ENV["UAA_CLIENT_SECRET"] = "adminsecret"
#    ENV["UAA_CLIENT_TARGET"] = "http://localhost:8080/uaa"

module CF::UAA

# ENV['UAA_CLIENT_TARGET'] = 'http://localhost:8080/uaa'
ENV['UAA_CLIENT_TARGET'] = 'https://login.identity.cf-app.com/'
if ENV['UAA_CLIENT_TARGET']

describe 'UAA Integration:' do

  def create_test_client
    toki = TokenIssuer.new(@target, @admin_client, @admin_secret)
    cr = Scim.new(@target, toki.client_credentials_grant.auth_header, :symbolize_keys => true)
    @test_client = "test_client_#{Time.now.to_i}"
    @test_secret = '+=tEsTsEcRet~!@'
    gids = ['clients.read', 'scim.read', 'scim.write', 'uaa.resource', 'password.write']
    new_client = cr.add(:client, :client_id => @test_client, :client_secret => @test_secret,
          :authorities => gids, :authorized_grant_types => ['client_credentials', 'password'],
          :scope => ['openid', 'password.write'])
    new_client[:client_id].should == @test_client
    @username = "sam_#{Time.now.to_i}"
  end

  before :all do
    #Util.default_logger(:trace)
    @admin_client = ENV['UAA_CLIENT_ID'] || 'admin'
    @admin_secret = ENV['UAA_CLIENT_SECRET'] || 'adminsecret'
    @target = ENV['UAA_CLIENT_TARGET']
    @username = "sam_#{Time.now.to_i}"
  end

  let(:token_issuer) { TokenIssuer.new(@target, @admin_client, @admin_secret, {:skip_ssl_validation => true}) }

  it 'should report the uaa client version' do
    VERSION.should =~ /\d.\d.\d/
  end

  it 'makes sure the server is there by getting the prompts for an implicit grant' do
    prompts = token_issuer.prompts
    prompts.should_not be_nil
  end

  it 'gets a token with client credentials' do
    tkn = TokenIssuer.new(@target, @admin_client, @admin_secret).client_credentials_grant
    tkn.auth_header.should =~ /^bearer\s/i
    info = TokenCoder.decode(tkn.info['access_token'], :verify => false, :symbolize_keys => true)
    info[:exp].should be
    info[:jti].should be
  end

  context 'as a client' do

    before :all do
      create_test_client
      toki = TokenIssuer.new(@target, @test_client, @test_secret)
      @scim = Scim.new(@target, toki.client_credentials_grant.auth_header, :symbolize_keys => true)
      @user_pwd = "sam's P@55w0rd~!`@\#\$%^&*()_/{}[]\\|:\";',.<>?/"
      usr = @scim.add(:user, :username => @username, :password => @user_pwd,
          :emails => [{:value => 'sam@example.com'}],
          :name => {:givenname => 'none', :familyname => 'none'})
      @user_id = usr[:id]
    end

    after :all do
      # TODO: delete user, delete test client
    end

    it 'creates a user' do
      @user_id.should be
    end

    it 'finds the user by name' do
      @scim.id(:user, @username).should == @user_id
    end

    it 'gets the user by id' do
      user_info = @scim.get(:user, @user_id)
      user_info[:id].should == @user_id
      user_info[:username].should == @username
    end

    xit 'gets a user token by  an implicit grant' do
      #we don't support implicit_grant_with_creds.
      @toki = TokenIssuer.new(@target, 'vmc')
      token = @toki.implicit_grant_with_creds(:username => @username, :password => @user_pwd)
      token.info['access_token'].should be
      info = Misc.whoami(@target, token.auth_header)
      info['user_name'].should == @username
      contents = TokenCoder.decode(token.info['access_token'], :verify => false)
      contents['user_name'].should == @username
    end

    it "changes the user's password by name" do
      @scim.change_password(@scim.id(:user, @username), 'newpassword')[:status].should == 'ok'
    end

    it 'lists all users' do
      user_info = @scim.query(:user)
      user_info.should_not be_nil
    end

    if ENV['UAA_CLIENT_LOGIN']
      it 'should get a uri to be sent to the user agent to initiate autologin' do
        logn = ENV['UAA_CLIENT_LOGIN']
        toki = TokenIssuer.new(logn, @test_client, @test_secret)
        redir_uri = 'http://call.back/uri_path'
        uri_parts = toki.autologin_uri(redir_uri, :username => @username,
            :password => 'newpassword').split('?')
        uri_parts[0].should == "#{logn}/oauth/authorize"
        params = Util.decode_form(uri_parts[1], :sym)
        params[:response_type].should == 'code'
        params[:client_id].should == @client_id
        params[:scope].should be_nil
        params[:redirect_uri].should == redir_uri
        params[:state].should_not be_nil
        params[:code].should_not be_nil
      end
    end

    it 'deletes the user' do
      @scim.delete(:user, @user_id)
      expect { @scim.id(:user, @username) }.to raise_exception(NotFound)
      expect { @scim.get(:user, @user_id) }.to raise_exception(NotFound)
    end

    it 'complains about an attempt to delete a non-existent user' do
      expect { @scim.delete(:user, 'non-existent-user') }.to raise_exception(NotFound)
    end

  end

end end

end
