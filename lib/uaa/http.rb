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

require 'base64'
require 'net/http'
require 'uaa/util'

module CF::UAA

# Indicates URL for the target is bad or not accessible
class BadTarget < UAAError; end

# Error indicating the resource within the target server was not found
class NotFound < UAAError; end

# Indicates a syntax error in a response from the UAA, e.g. missing required response field.
class BadResponse < UAAError; end

# Indicates a token is malformed or expired
class InvalidToken < UAAError; end

# Indicates an error from the http client stack
class HTTPException < UAAError; end

# An application level error from the UAA which includes error info in the reply.
class TargetError < UAAError
  attr_reader :info
  def initialize(error_info = {})
    @info = error_info
  end
end

# Utility accessors and methods for objects that want to access JSON web APIs.
module Http

  # Sets the current logger instance to recieve error messages
  def logger=(logr); @logger = logr end

  # Returns the current logger or CF::UAA::Util.default_logger is none has been set.
  def logger ; @logger ||= Util.default_logger end

  # Returns true if the current logger is set to +:trace+ level
  def trace? ; @logger && @logger.respond_to?(:trace?) && @logger.trace? end

  # Sets handler for outgoing http requests. If not set, an internal cache of
  # net/http connections is used.
  # Arguments to handler are url, method, body, headers.
  def set_request_handler(&blk) @req_handler = blk end

  # Returns a string for use in an http basic authentication header
  def self.basic_auth(name, password)
    "Basic " + Base64::strict_encode64("#{name}:#{password}")
  end

  private

  def add_auth_json(auth, headers, jsonhdr = "content-type")
    headers["authorization"] = auth if auth
    headers.merge!(jsonhdr => "application/json")
  end

  def json_get(target, path = nil, authorization = nil, key_style = :none, headers = {})
    json_parse_reply(*http_get(target, path,
        add_auth_json(authorization, headers, "accept")), key_style)
  end

  def json_post(target, path, body, authorization, headers = {})
    http_post(target, path, Util.json(body), add_auth_json(authorization, headers))
  end

  def json_put(target, path, body, authorization = nil, headers = {})
    http_put(target, path, Util.json(body), add_auth_json(authorization, headers))
  end

  def json_parse_reply(status, body, headers, key_style = :none)
    unless [200, 201, 204, 400, 401, 403].include? status
      raise (status == 404 ? NotFound : BadResponse), "invalid status response: #{status}"
    end
    if body && !body.empty? && (status == 204 || headers.nil? ||
          headers["content-type"] !~ /application\/json/i)
      raise BadResponse, "received invalid response content or type"
    end
    parsed_reply = Util.json_parse(body, key_style)
    if status >= 400
      raise parsed_reply && parsed_reply["error"] == "invalid_token" ?
          InvalidToken : TargetError.new(parsed_reply), "error response"
    end
    parsed_reply
  rescue DecodeError
    raise BadResponse, "invalid JSON response"
  end

  def http_get(target, path = nil, headers = {}) request(target, :get, path, nil, headers) end
  def http_post(target, path, body, headers = {}) request(target, :post, path, body, headers) end
  def http_put(target, path, body, headers = {}) request(target, :put, path, body, headers) end

  def http_delete(target, path, authorization)
    status = request(target, :delete, path, nil, "authorization" => authorization)[0]
    unless [200, 204].include?(status)
      raise (status == 404 ? NotFound : BadResponse), "invalid response from #{path}: #{status}"
    end
  end

  def request(target, method, path, body = nil, headers = {})
    headers["accept"] = headers["content-type"] if headers["content-type"] && !headers["accept"]
    url = "#{target}#{path}"

    logger.debug { "--->\nrequest: #{method} #{url}\n" +
        "headers: #{headers}\n#{'body: ' + Util.truncate(body.to_s, trace? ? 50000 : 50) if body}" }
    status, body, headers = @req_handler ? @req_handler.call(url, method, body, headers) :
        net_http_request(url, method, body, headers)
    logger.debug { "<---\nresponse: #{status}\nheaders: #{headers}\n" +
        "#{'body: ' + Util.truncate(body.to_s, trace? ? 50000: 50) if body}" }

    [status, body, headers]

  rescue Exception => e
    e.message.replace "Target #{target}, #{e.message}"
    logger.debug { "<---- no response due to exception: #{e}" }
    raise e
  end

  def net_http_request(url, method, body, headers)
    raise ArgumentError unless reqtype = {delete: Net::HTTP::Delete,
        get: Net::HTTP::Get, post: Net::HTTP::Post, put: Net::HTTP::Put}[method]
    headers["content-length"] = body.length if body
    uri = URI.parse(url)
    req = reqtype.new(uri.request_uri)
    headers.each { |k, v| req[k] = v }
    http_key = "#{uri.scheme}://#{uri.host}:#{uri.port}"
    @http_cache ||= {}
    unless http = @http_cache[http_key]
      @http_cache[http_key] = http = Net::HTTP.new(uri.host, uri.port)
      if uri.is_a?(URI::HTTPS)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end
    end
    reply, outhdrs = http.request(req, body), {}
    reply.each_header { |k, v| outhdrs[k] = v }
    [reply.code.to_i, reply.body, outhdrs]

  rescue URI::Error, SocketError, SystemCallError => e
    raise BadTarget, "error: #{e.message}"
  rescue Net::HTTPBadResponse => e
    raise HTTPException, "HTTP exception: #{e.class}: #{e}"
  end

end

end
