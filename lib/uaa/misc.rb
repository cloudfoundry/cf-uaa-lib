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

# This class is for Web Client Apps (in the OAuth2 sense) that want
# access to authenticated user information.  Basically this class is
# an OpenID Connect client.

require 'uaa/http'

module CF::UAA

# everything is miscellaneous
#
# this class provides interfaces to UAA endpoints that are not in the context
# of an overall class of operations, like "user accounts" or "tokens". It's
# also for some apis like "change user password" or "change client secret" that
# use different forms of authentication than other operations on those types
# of resources.
class Misc

  class << self
    include Http
  end

  def self.whoami(target, auth_header) json_get(target, "/userinfo?schema=openid", auth_header) end
  def self.varz(target, name, pwd) json_get(target, "/varz", Http.basic_auth(name, pwd)) end

  def self.server(target)
    reply = json_get(target, '/login')
    return reply if reply && reply["prompts"]
    raise BadResponse, "Invalid response from target #{target}"
  end

  def self.validation_key(target, client_id = nil, client_secret = nil)
    json_get(target, "/token_key", (client_id && client_secret ? Http.basic_auth(client_id, client_secret) : nil))
  end

  # Returns hash of values from the Authorization Server that are associated
  # with the opaque token.
  def self.decode_token(target, client_id, client_secret, token, token_type = "bearer", audience_ids = nil)
    reply = json_get(target, "/check_token?token_type=#{token_type}&token=#{token}",
        Http.basic_auth(client_id, client_secret))
    auds = Util.arglist(reply["aud"])
    if audience_ids && (!auds || (auds & audience_ids).empty?)
      raise AuthError, "invalid audience: #{auds.join(' ')}"
    end
    reply
  end

  def self.password_strength(target, password)
    json_parse_reply(*request(target, :post, '/password/score', URI.encode_www_form("password" => password),
        "content-type" => "application/x-www-form-urlencoded", "accept" => "application/json"))
  end

end

end
