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
ENV['UAA_CLIENT_ID'] = 'admin'
ENV['UAA_CLIENT_SECRET'] = 'admin_secret'

module CF::UAA

# ENV['UAA_CLIENT_TARGET'] = 'http://localhost:8080/uaa'
ENV['UAA_CLIENT_TARGET'] = 'https://login.identity.cf-app.com/'
  if ENV['UAA_CLIENT_TARGET']
    describe 'UAA Integration:' do

      before :all do
        #Util.default_logger(:trace)
        @admin_client = ENV['UAA_CLIENT_ID'] || 'admin'
        @admin_secret = ENV['UAA_CLIENT_SECRET'] || 'adminsecret'
        @target = ENV['UAA_CLIENT_TARGET']
        @username = "sam_#{Time.now.to_i}"
        @options = {:skip_ssl_validation => true}
        @options = {:ssl_ca_file => '~/workspace/identity-cf.cert'}
        cert_store = OpenSSL::X509::Store.new
        cert_store.add_file File.expand_path('~/workspace/identity-cf.cert')
        @options = {:ssl_cert_store => cert_store}
      end

      let(:token_issuer) { TokenIssuer.new(@target, @admin_client, @admin_secret, @options) }

      let(:scim) { Scim.new(@target, token_issuer.client_credentials_grant.auth_header, @options.merge(:symbolize_keys => true)) }

      it 'should report the uaa client version' do
        expect(VERSION).to match(/\d.\d.\d/)
      end

      it 'makes sure the server is there by getting the prompts for an implicit grant' do
        expect(token_issuer.prompts).to_not be_nil
      end

      it 'gets a token with client credentials' do
        tkn = token_issuer.client_credentials_grant
        expect(tkn.auth_header).to match(/^bearer\s/i)
        info = TokenCoder.decode(tkn.info['access_token'], :verify => false, :symbolize_keys => true)
        expect(info[:exp]).to be
        expect(info[:jti]).to be
      end

      it 'complains about an attempt to delete a non-existent user' do
        expect { scim.delete(:user, 'non-existent-user') }.to raise_exception(NotFound)
      end
      
      context 'as a client' do
        before :each do
          @test_client = "test_client_#{Time.now.to_i}"
          @test_secret = '+=tEsTsEcRet~!@'
          gids = ['clients.read', 'scim.read', 'scim.write', 'uaa.resource', 'password.write']
          token_issuer = TokenIssuer.new(@target, @admin_client, @admin_secret, @options)
          scim = Scim.new(@target, token_issuer.client_credentials_grant.auth_header, @options.merge(:symbolize_keys => true))
          new_client = scim.add(:client, :client_id => @test_client, :client_secret => @test_secret,
                                :authorities => gids, :authorized_grant_types => ['client_credentials', 'password'],
                                :scope => ['openid', 'password.write'])
          expect(new_client[:client_id]).to eq(@test_client)
          @username = "sam_#{Time.now.to_i}"

          @user_pwd = "sam's P@55w0rd~!`@\#\$%^&*()_/{}[]\\|:\";',.<>?/"
          usr = scim.add(:user, :username => @username, :password => @user_pwd,
                         :emails => [{:value => 'sam@example.com'}],
                         :name => {:givenname => 'none', :familyname => 'none'})
          @user_id = usr[:id]
        end

        it 'deletes the user' do
          scim.delete(:user, @user_id)
          expect { scim.id(:user, @username) }.to raise_exception(NotFound)
          expect { scim.get(:user, @user_id) }.to raise_exception(NotFound)
        end

        context 'when user exists' do
          after :each do
            scim.delete(:user, @user_id)
            expect { scim.id(:user, @username) }.to raise_exception(NotFound)
            expect { scim.get(:user, @user_id) }.to raise_exception(NotFound)
          end

          it 'creates a user' do
            expect(@user_id).to be
          end

          it 'finds the user by name' do
            expect(scim.id(:user, @username)).to eq(@user_id)
          end

          it 'gets the user by id' do
            user_info = scim.get(:user, @user_id)
            expect(user_info[:id]).to eq(@user_id)
            expect(user_info[:username]).to eq(@username)
          end

          xit 'gets a user token by  an implicit grant' do
            #we don't support implicit_grant_with_creds.
            @token_issuer = TokenIssuer.new(@target, 'vmc')
            token = @token_issuer.implicit_grant_with_creds(:username => @username, :password => @user_pwd)
            token.info['access_token'].should be
            info = Misc.whoami(@target, token.auth_header)
            info['user_name'].should == @username
            contents = TokenCoder.decode(token.info['access_token'], :verify => false)
            contents['user_name'].should == @username
          end

          it 'lists all users' do
            expect(scim.query(:user)).to be
          end

          it "changes the user's password by name" do
            expect(scim.change_password(scim.id(:user, @username), 'newpassword')[:status]).to eq('ok')
          end

          it 'should get a uri to be sent to the user agent to initiate autologin' do
            redir_uri = 'http://call.back/uri_path'
            uri_parts = token_issuer.autologin_uri(redir_uri, :username => @username,
                                                   :password =>@user_pwd ).split('?')
            expect(uri_parts[0]).to eq("#{ENV['UAA_CLIENT_TARGET']}/oauth/authorize")
            params = Util.decode_form(uri_parts[1], :sym)
            expect(params[:response_type]).to eq('code')
            expect(params[:client_id]).to eq(@admin_client)
            expect(params[:scope]).to be_nil
            expect(params[:redirect_uri]).to eq(redir_uri)
            expect(params[:state]).to be
            expect(params[:code]).to be
          end
        end
      end
    end
  end
end