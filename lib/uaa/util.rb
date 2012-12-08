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

require 'multi_json'
require "base64"
require 'logger'
require 'uri'

# :nodoc:
module CF
  # Namespace for Cloudfoundry User Account and Authentication service Ruby APIs
  module UAA end
end

class Logger # :nodoc:
  Severity::TRACE = Severity::DEBUG - 1
  def trace(progname, &blk); add(Logger::Severity::TRACE, nil, progname, &blk) end
  def trace? ; @level <= Logger::Severity::TRACE end
end

module CF::UAA

# Useful parent class. All CF::UAA exceptions are derived from this.
class UAAError < RuntimeError; end

# Indicates an authentication error
class AuthError < UAAError; end

# Indicates an error occurred decoding a token, base64 decoding, or JSON
class DecodeError < UAAError; end

# Low level helper functions useful to the UAA client APIs
class Util

  # HTTP headers and various protocol tags tend to contain '-' characters,
  # are intended to be case-insensitive, and often end up as keys in ruby
  # hashes. SCIM[http://www.simplecloud.info/] specifies that attribute
  # names are case-insensitive and this code downcases such strings using
  # this method.
  #
  # The various +styles+ convert +key+ as follows:
  # [+:undash+] to lowercase, '-' to  '_', and to a symbol
  # [+:todash+] to string, '_' to '-'
  # [+:uncamel+] uppercase to underscore-lowercase, to symbol
  # [+:tocamel+] reverse of +uncamel+
  # [+:tosym+] to symbol
  # [+:tostr+] to string
  # [+:down+] to lowercase
  # [+:none+] leave the damn key alone
  #
  # returns new key
  def self.hash_key(k, style)
    case style
    when :undash then k.to_s.downcase.tr('-', '_').to_sym
    when :todash then k.to_s.downcase.tr('_', '-')
    when :uncamel then k.to_s.gsub(/([A-Z])([^A-Z]*)/,'_\1\2').downcase.to_sym
    when :tocamel then k.to_s.gsub(/(_[a-z])([^_]*)/) { $1[1].upcase + $2 }
    when :tosym then k.to_sym
    when :tostr then k.to_s
    when :down then k.to_s.downcase
    when :none then k
    else raise ArgumentError, "unknown hash key style: #{style}"
    end
  end

  # Modifies obj in place changing any hash keys to style (see hash_key).
  # Recursively modifies subordinate hashes. Returns modified obj
  def self.hash_keys!(obj, style = :none)
    return obj if style == :none
    return obj.each {|o| hash_keys!(o, style)} if obj.is_a? Array
    return obj unless obj.is_a? Hash
    newkeys, nk = {}, nil
    obj.delete_if { |k, v|
      hash_keys!(v, style)
      newkeys[nk] = v unless (nk = hash_key(k, style)) == k
      nk != k
    }
    obj.merge!(newkeys)
  end

  # Makes a new copy of obj with hash keys to style (see hash_key).
  # Recursively modifies subordinate hashes. Returns modified obj
  def self.hash_keys(obj, style = :none)
    return obj.collect {|o| hash_keys(o, style)} if obj.is_a? Array
    return obj unless obj.is_a? Hash
    obj.each_with_object({}) {|(k, v), h|
      h[hash_key(k, style)] = hash_keys(v, style)
    }
  end

  # Takes an x-www-form-urlencoded string and returns a hash of key value pairs.
  # Useful for OAuth parameters. It raises an ArgumentError if a key occurs
  # more than once, which is a restriction of OAuth query strings.
  # OAuth parameters are case sensitive, scim parameters are case-insensitive
  # See ietf rfc 6749 section 3.1.
  def self.decode_form_to_hash(url_encoded_pairs, style = :none)
    URI.decode_www_form(url_encoded_pairs).each_with_object({}) do |p, o|
      k = hash_key(p[0], style)
      raise ArgumentError, "duplicate keys in form parameters" if o[k]
      o[k] = p[1]
    end
  rescue Exception => e
    raise ArgumentError, e.message
  end

  # Converts +obj+ to JSON
  def self.json(obj) MultiJson.dump(obj) end

  # Converts +obj+ to nicely formatted JSON
  def self.json_pretty(obj) MultiJson.dump(obj, pretty: true) end

  # Converts +obj+ to a URL-safe base 64 encoded string
  def self.json_encode64(obj = {}) encode64(json(obj)) end

  # Converts +str+ from base64 encoding of a JSON string to a (returned) hash.
  def self.json_decode64(str) json_parse(decode64(str)) end

  # encodes +obj+ as a URL-safe base 64 encoded string, with trailing padding removed.
  def self.encode64(obj) Base64::urlsafe_encode64(obj).gsub(/=*$/, '') end

  # adds proper padding to a URL-safe base 64 encoded string, and then returns the decoded string.
  def self.decode64(str)
    return unless str
    pad = str.length % 4
    str << '=' * (4 - pad) if pad > 0
    Base64::urlsafe_decode64(str)
  rescue ArgumentError
    raise DecodeError, "invalid base64 encoding"
  end

  # Parses a JSON string into the returned hash. For possible values of +style+
  # see #hask_key
  def self.json_parse(str, style = :none)
    hash_keys!(MultiJson.load(str), style) if str && !str.empty?
  rescue MultiJson::DecodeError
    raise DecodeError, "json decoding error"
  end

  def self.truncate(obj, limit = 50) # :nodoc:
    return obj.to_s if limit == 0
    limit = limit < 5 ? 1 : limit - 4
    str = obj.to_s[0..limit]
    str.length > limit ? str + '...': str
  end

  # Many parameters in these classes can be given as arrays, or as a list of
  # arguments separated by spaces or commas. This method handles the possible
  # inputs and returns an array of arguments.
  def self.arglist(arg, default_arg = nil)
    arg = default_arg unless arg
    return arg if arg.nil? || arg.respond_to?(:join)
    raise ArgumentError, "arg must be Array or space|comma delimited strings" unless arg.respond_to?(:split)
    arg.split(/[\s\,]+/).reject { |e| e.empty? }
  end

  # Reverse of arglist, puts arrays of strings into a single, space-delimited string
  def self.strlist(arg, delim = ' ')
    arg.respond_to?(:join) ? arg.join(delim) : arg.to_s if arg
  end

  # Set the default logger used by the higher level classes.
  def self.default_logger(level = nil, sink = nil)
    if sink || !@default_logger
      @default_logger = Logger.new(sink || $stdout)
      level = :info unless level
      @default_logger.formatter = Proc.new { |severity, time, pname, msg| puts msg }
    end
    @default_logger.level = Logger::Severity.const_get(level.upcase) if level
    @default_logger
  end

end

end
