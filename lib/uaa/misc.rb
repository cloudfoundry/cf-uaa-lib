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

require 'uaa/http'

module CF::UAA

# interfaces to UAA endpoints that are not in the context
# of an overall class of operations like SCIM resources or OAuth2 tokens.
class Misc

  class << self
    include Http
  end

  # Returns a hash of information about the user authenticated by the token in
  # the +auth_header+. It calls the +/userinfo+ endpoint and returns a hash of
  # user information as specified by OpenID Connect.
  # See: http://openid.net/connect/
  # Specifically: http://openid.net/specs/openid-connect-standard-1_0.html#userinfo_ep
  # and: http://openid.net/specs/openid-connect-messages-1_0.html#anchor9
  def self.whoami(target, auth_header) 
    json_get(target, "/userinfo?schema=openid", auth_header) 
  end

  # Returns a hash of various monitoring and status variables from the UAA.
  # Authenticates to the UAA with basic authentication. Name and pwd 
  # must be configured in the UAA.
  def self.varz(target, name, pwd) 
    json_get(target, "/varz", Http.basic_auth(name, pwd)) 
  end

  # returns a hash of basic information about the target server, including
  # version number, commit ID, and links to API endpoints.
  def self.server(target)
    reply = json_get(target, '/login')
    return reply if reply && reply["prompts"]
    raise BadResponse, "Invalid response from target #{target}"
  end

  def self.validation_key(target, client_id = nil, client_secret = nil)
    json_get(target, "/token_key", (client_id && client_secret ? Http.basic_auth(client_id, client_secret) : nil))
  end

  # Sends the token to the UAA to validate. Returns hash of values that are 
  # associated with the token. Authenticates with client_id and client_secret.
  # If audience_ids are specified, raises AuthError token is not for this
  # audience -- i.e. the token's 'aud' attribute does not contain one or more 
  # of the specified audience_ids.
  def self.decode_token(target, client_id, client_secret, token, token_type = "bearer", audience_ids = nil)
    reply = json_get(target, "/check_token?token_type=#{token_type}&token=#{token}",
        Http.basic_auth(client_id, client_secret))
    auds = Util.arglist(reply["aud"])
    if audience_ids && (!auds || (auds & audience_ids).empty?)
      raise AuthError, "invalid audience: #{auds.join(' ')}"
    end
    reply
  end

  # Returns a hash of information about the given password, including a
  # strength score and an indication of what strength it required by the UAA.
  def self.password_strength(target, password)
    json_parse_reply(*request(target, :post, '/password/score', URI.encode_www_form("password" => password),
        "content-type" => "application/x-www-form-urlencoded", "accept" => "application/json"))
  end

end

end
