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

require "openssl"
require "uaa/util"

module CF::UAA

# This class is for OAuth Resource Servers.
# Resource Servers get tokens and need to validate and decode them,
# but they do not obtain them from the Authorization Server. This
# class is for resource servers which accept bearer JWT tokens.
#
# For more on JWT, see the JSON Web \Token RFC here:
# http://tools.ietf.org/id/draft-ietf-oauth-json-web-token-05.html
#
# An instance of this class can be used to decode and verify the contents
# of a bearer token. Methods of this class can validate token signatures
# with a secret or public key, and they can also enforce that the token
# is for a particular audience.
class TokenCoder

  def self.init_digest(algo) # :nodoc:
    OpenSSL::Digest::Digest.new(algo.sub('HS', 'sha').sub('RS', 'sha'))
  end

  # Takes a +token_body+ (the middle section of the JWT) and returns a signed
  # token string.
  def self.encode(token_body, skey, pkey = nil, algo = 'HS256')
    segments = [Util.json_encode64("typ" => "JWT", "alg" => algo)]
    segments << Util.json_encode64(token_body)
    if ["HS256", "HS384", "HS512"].include?(algo)
      sig = OpenSSL::HMAC.digest(init_digest(algo), skey, segments.join('.'))
    elsif ["RS256", "RS384", "RS512"].include?(algo)
      sig = pkey.sign(init_digest(algo), segments.join('.'))
    elsif algo == "none"
      sig = ""
    else
      raise ArgumentError, "unsupported signing method"
    end
    segments << Util.encode64(sig)
    segments.join('.')
  end

  # Decodes a +token+ and optionally verifies the signature. Both a secret key
  # and a public key can be provided for signature verification. The JWT
  # +token+ header indicates what signature algorithm was used and the
  # corresponding key is used to verify the signature (if +verify+ is true).
  # Returns a hash of the token contents or raises +DecodeError+.
  def self.decode(token, skey = nil, pkey = nil, verify = true)
    pkey = OpenSSL::PKey::RSA.new(pkey) unless pkey.nil? || pkey.is_a?(OpenSSL::PKey::PKey)
    segments = token.split('.')
    raise DecodeError, "Not enough or too many segments" unless [2,3].include? segments.length
    header_segment, payload_segment, crypto_segment = segments
    signing_input = [header_segment, payload_segment].join('.')
    header = Util.json_decode64(header_segment)
    payload = Util.json_decode64(payload_segment)
    return payload if !verify || (algo = header["alg"]) == "none"
    signature = Util.decode64(crypto_segment)
    if ["HS256", "HS384", "HS512"].include?(algo)
      raise DecodeError, "Signature verification failed" unless
          signature == OpenSSL::HMAC.digest(init_digest(algo), skey, signing_input)
    elsif ["RS256", "RS384", "RS512"].include?(algo)
      raise DecodeError, "Signature verification failed" unless
          pkey.verify(init_digest(algo), signature, signing_input)
    else
      raise DecodeError, "Algorithm not supported"
    end
    payload
  end

  # Creates a new token en/decoder for a service that is associated with
  # the the audience_ids, the symmetrical token validation key, and the
  # public and/or private keys. Parameters:
  # +audience_ids+:: an array or space separated strings. Should
  #                  indicate values which indicate the token is intended for this service
  #                  instance. It will be compared with tokens as they are decoded to
  #                  ensure that the token was intended for this audience.
  # +skey+:: is used to sign and validate tokens using symetrical key algoruthms
  # +pkey+:: may be a string or File which includes public and
  #          optionally private key data in PEM or DER formats. The private key
  #          is used to sign tokens and the public key is used to validate tokens.
  def initialize(audience_ids, skey, pkey = nil)
    @audience_ids, @skey, @pkey = Util.arglist(audience_ids), skey, pkey
    @pkey = OpenSSL::PKey::RSA.new(pkey) unless pkey.nil? || pkey.is_a?(OpenSSL::PKey::PKey)
  end

  # Encode a JWT token. Takes a hash of values to use as the token body.
  # Returns a signed token in JWT format (header, body, signature).
  # Algorithm may be HS256, HS384, HS512, RS256, RS384, RS512, or none --
  # assuming the TokenCoder instance is configured with the appropriate
  # key -- i.e. pkey must include a private key for the RS algorithms.
  def encode(token_body = {}, algorithm = 'HS256')
    token_body['aud'] = @audience_ids unless token_body['aud']
    token_body['exp'] = Time.now.to_i + 7 * 24 * 60 * 60 unless token_body['exp']
    self.class.encode(token_body, @skey, @pkey, algorithm)
  end

  # Returns hash of values decoded from the token contents. If the
  # token contains audience ids in the +aud+ field and they do not contain one
  # or more of the +audience_ids+ in this instance, an AuthError will be raised.
  # AuthError is raised if the token has expired.
  def decode(auth_header)
    unless auth_header && (tkn = auth_header.split).length == 2 && tkn[0] =~ /^bearer$/i
      raise DecodeError, "invalid authentication header: #{auth_header}"
    end
    reply = self.class.decode(tkn[1], @skey, @pkey)
    auds = Util.arglist(reply["aud"])
    if @audience_ids && (!auds || (auds & @audience_ids).empty?)
      raise AuthError, "invalid audience: #{auds.join(' ')}"
    end
    exp = reply["exp"]
    unless exp.is_a?(Integer) && exp > Time.now.to_i
      raise AuthError, "token expired"
    end
    reply
  end

end

end
