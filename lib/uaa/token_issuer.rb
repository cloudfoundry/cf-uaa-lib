#--
# Cloud Foundry 2012.02.03 Beta
# Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache License, Version 2.0 (the "License").
# You may not use this product except in compliance with the License.
#
# This product includes a number of subcomponents with
# separate copyright notices and license terms. Your use of these
# subcomponents is subject to the terms and conditions of the
# subcomponent's license, as noted in the LICENSE file.
#++

require 'securerandom'
require 'uaa/http'

module CF::UAA

# The Token class is returned by various TokenIssuer methods. It holds access
# and refresh tokens as well as token meta-data such as token type and
# expiration time. See Token#info for contents.
class Token

  # Returns a hash of information about the current token. The info hash MUST include
  # access_token, token_type and scope (if granted scope differs from requested
  # scope). It should include expires_in. It may include refresh_token, scope,
  # and other values from the auth server.
  attr_reader :info

  def initialize(info) # :nodoc:
    @info = info
  end

  # Returns a string for use in an authorization header that is constructed
  # from contents of the Token. Typically a string such as "bearer xxxx.xxxx.xxxx".
  def auth_header; "#{info['token_type']} #{info['access_token']}" end
end

# Client Apps that want to get access to resource servers on behalf of their
# users need to get tokens via authcode and implicit flows,
# request scopes, etc., but they don't need to process tokens. This
# class is for these use cases.
#
# In general most of this class is an implementation of the client pieces of
# the OAuth2 protocol. See http://tools.ietf.org/html/rfc6749
class TokenIssuer

  include Http

  # parameters:
  # [+target+] The base URL of a UAA's oauth authorize endpoint. For example
  #            the target would be \https://login.cloudfoundry.com if the
  #            endpoint is \https://login.cloudfoundry.com/oauth/authorize.
  #            The target would be \http://localhost:8080/uaa if the endpoint
  #            is \http://localhost:8080/uaa/oauth/authorize.
  # [+client_id+] The oauth2 client id. See http://tools.ietf.org/html/rfc6749#section-2.2
  # [+client_secret+] needed to authenticate the client for all grant types
  #                   except implicit.
  # [+token_target+] The base URL of the oauth token endpoint. If not specified,
  #                  +target+ is used.
  def initialize(target, client_id, client_secret = nil, token_target = nil)
    @target, @client_id, @client_secret = target, client_id, client_secret
    @token_target = token_target || target
  end

  # Allows an app to discover what credentials are required for
  # #implicit_grant_with_creds. Returns a hash of credential names with type
  # and suggested prompt value, e.g.
  #   {"username":["text","Email"],"password":["password","Password"]}
  def prompts
    reply = json_get @target, '/login'
    return reply['prompts'] if reply && reply['prompts']
    raise BadResponse, "No prompts in response from target #{@target}"
  end

  # Gets an access token in a single call to the UAA with the user
  # credentials used for authentication. The +credentials+ should
  # be an object such as a hash that can be converted to a json
  # representation of the credential name/value pairs
  # corresponding to the keys retrieved by #prompts.
  # Returns a Token.
  def implicit_grant_with_creds(credentials, scope = nil)
    # this manufactured redirect_uri is a convention here, not part of OAuth2
    redir_uri = "https://uaa.cloudfoundry.com/redirect/#{@client_id}"
    uri = authorize_path_args("token", redir_uri, scope, state = SecureRandom.uuid)

    # the accept header is only here so the uaa will issue error replies in json to aid debugging
    headers = {'content-type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json' }
    body = URI.encode_www_form(credentials.merge('source' => 'credentials'))
    status, body, headers = request(@target, :post, uri, body, headers)
    raise BadResponse, "status #{status}" unless status == 302
    req_uri, reply_uri = URI.parse(redir_uri), URI.parse(headers['location'])
    fragment, reply_uri.fragment = reply_uri.fragment, nil
    raise BadResponse, "bad location header" unless req_uri == reply_uri
    parse_implicit_params(fragment, state)
  rescue URI::Error => e
    raise BadResponse, "bad location header in reply: #{e.message}"
  end

  # Constructs a uri that the client is to return to the browser to direct
  # the user to the authorization server to get an authcode. The +redirect_uri+
  # is embedded in the returned uri so the authorization server can redirect
  # the user back to the client app.
  def implicit_uri(redirect_uri, scope = nil)
    @target + authorize_path_args("token", redirect_uri, scope)
  end

  # Gets a token via an implicit grant.
  # [+authcode_uri+] must be from a previous call to #implicit_uri and contains
  #                  state used to validate the contents of the reply from the
  #                  Authorization Server.
  # [+callback_fragment+] must be the fragment portion of the URL received by
  #                       user's browser after the Authorization Server
  #                       redirects back to the +redirect_uri+ that was given to
  #                       #implicit_uri. How the application get's the contents
  #                       of the fragment is application specific -- usually
  #                       some javascript in the page at the +redirect_uri+.
  #
  # See http://tools.ietf.org/html/rfc6749#section-4.2 .
  #
  # Returns a Token.
  def implicit_grant(implicit_uri, callback_fragment)
    in_params = Util.decode_form_to_hash(URI.parse(implicit_uri).query)
    unless in_params['state'] && in_params['redirect_uri']
      raise ArgumentError, "redirect must happen before implicit grant"
    end
    parse_implicit_params callback_fragment, in_params['state']
  end

  # A UAA extension to OAuth2 that allows a client to pre-authenticate a
  # user at the start of an authorization code flow. By passing in the
  # user's credentials (see #prompts) the Authorization Server can establish
  # a session with the user's browser without reprompting for authentication.
  # This is useful for user account management apps so that they can create
  # a user account, or reset a password for the user, without requiring the
  # user to type in their credentials again.
  def autologin_uri(redirect_uri, credentials, scope = nil)
    headers = {'content_type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json',
        'authorization' => Http.basic_auth(@client_id, @client_secret) }
    body = URI.encode_www_form(credentials)
    reply = json_parse_reply(*request(@target, :post, "/autologin", body, headers))
    raise BadResponse, "no autologin code in reply" unless reply['code']
    @target + authorize_path_args('code', redirect_uri, scope, SecureRandom.uuid, code: reply[:code])
  end

  # Constructs a uri that the client is to return to the browser to direct
  # the user to the authorization server to get an authcode. The redirect_uri
  # is embedded in the returned uri so the authorization server can redirect
  # the user back to the client app.
  def authcode_uri(redirect_uri, scope = nil)
    @target + authorize_path_args('code', redirect_uri, scope)
  end

  # Uses the instance client credentials in addition to +callback_query+
  # to get a token via the authorization code grant.
  # [+authcode_uri+] must be from a previous call to #authcode_uri and contains
  #                  state used to validate the contents of the reply from the
  #                  Authorization Server.
  # [callback_query] must be the query portion of the URL received by the
  #                  client after the user's browser is redirected back from
  #                  the Authorization server. It contains the authorization
  #                  code.
  #
  # See http://tools.ietf.org/html/rfc6749#section-4.1 .
  #
  # Returns a Token.
  def authcode_grant(authcode_uri, callback_query)
    ac_params = Util.decode_form_to_hash(URI.parse(authcode_uri).query)
    unless ac_params['state'] && ac_params['redirect_uri']
      raise ArgumentError, "authcode redirect must happen before authcode grant"
    end
    begin
      params = Util.decode_form_to_hash(callback_query)
      authcode = params['code']
      raise BadResponse unless params['state'] == ac_params['state'] && authcode
    rescue URI::InvalidURIError, ArgumentError, BadResponse
      raise BadResponse, "received invalid response from target #{@target}"
    end
    request_token('grant_type' => 'authorization_code', 'code' => authcode, 'redirect_uri' => ac_params['redirect_uri'])
  end

  # Uses the instance client credentials in addition to the +username+
  # and +password+ to get a token via the owner password grant.
  # See http://tools.ietf.org/html/rfc6749#section-4.3 .
  # Returns a Token.
  def owner_password_grant(username, password, scope = nil)
    request_token('grant_type' => 'password', 'username' => username, 'password' => password, 'scope' => scope)
  end

  # Uses the instance client credentials to get a token with a client
  # credentials grant. See http://tools.ietf.org/html/rfc6749#section-4.4
  # Returns a Token.
  def client_credentials_grant(scope = nil)
    request_token('grant_type' => 'client_credentials', 'scope' => scope)
  end

  # Uses the instance client credentials and the given +refresh_token+ to get
  # a new access token. See http://tools.ietf.org/html/rfc6749#section-6
  # Returns a Token, which may include a new refresh token as well as an access token.
  def refresh_token_grant(refresh_token, scope = nil)
    request_token('grant_type' => 'refresh_token', 'refresh_token' => refresh_token, 'scope' => scope)
  end

  private

  def parse_implicit_params(encoded_params, state)
    params = Util.decode_form_to_hash(encoded_params)
    raise BadResponse, "mismatched state" unless state && params.delete('state') == state
    raise TargetError.new(params), "error response from #{@target}" if params['error']
    raise BadResponse, "no type and token" unless params['token_type'] && params['access_token']
    exp = params['expires_in'].to_i
    params['expires_in'] = exp if exp.to_s == params['expires_in']
    Token.new params
  rescue URI::InvalidURIError, ArgumentError
    raise BadResponse, "received invalid response from target #{@target}"
  end

  # returns a CF::UAA::Token object which includes the access token and metadata.
  def request_token(params)
    if scope = Util.arglist(params.delete('scope'))
      params['scope'] = Util.strlist(scope)
    end
    headers = {'content-type' => 'application/x-www-form-urlencoded', 'accept' => 'application/json',
        'authorization' => Http.basic_auth(@client_id, @client_secret) }
    body = URI.encode_www_form(params)
    reply = json_parse_reply(*request(@token_target, :post, '/oauth/token', body, headers))
    raise BadResponse unless reply['token_type'] && reply['access_token']
    Token.new reply
  end

  def authorize_path_args(response_type, redirect_uri, scope, state = SecureRandom.uuid, args = {})
    params = args.merge('client_id' => @client_id, 'response_type' => response_type, 'redirect_uri' => redirect_uri, 'state' => state)
    params['scope'] = scope = Util.strlist(scope) if scope = Util.arglist(scope)
    params['nonce'], params['response_type'] = state, "#{response_type} id_token" if scope && scope.include?('openid')
    "/oauth/authorize?#{URI.encode_www_form(params)}"
  end

end

end
