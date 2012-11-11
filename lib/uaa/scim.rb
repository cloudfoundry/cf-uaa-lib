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

# This class is for apps that need to manage User Accounts.
# It provides access to the SCIM endpoints on the UAA.
class Scim

  include Http

  CLIENT_MV_ATTRIBUTES = [:scope, :authorized_grant_types, :authorities, :redirect_uri]

  def self.client_mva_to_arrays!(info)
    CLIENT_MV_ATTRIBUTES.each_with_object(info) { |v, o| o[v] = Util.arglist(o[v]) if o[v] }
  end

  def self.client_mva_to_strings!(info)
    CLIENT_MV_ATTRIBUTES.each_with_object(info) { |v, o| o[v] = Util.strlist(o[v]) if o[v] }
  end

  private

  # info is a hash structure converted to json and sent to the scim /Users endpoint
  def add_object(path, info)
    reply = json_parse_reply(*json_post(@target, path, info, @auth_header))
    return reply if reply[:id]
    raise BadResponse, "no id returned by create request to #{@target}#{path}"
  end

  # info is a hash structure converted to json and sent to the scim /Users endpoint
  def put_object(path, id, info)
    json_parse_reply(*json_put(@target, "#{path}/#{URI.encode(id)}", info,
        @auth_header, if_match: info[:meta][:version]))
  end

  # info is a hash structure converted to json and sent to the scim /Users endpoint
  #def patch_object(path, id, info, attributes_to_delete = nil)
  #  info = info.merge(meta: { attributes: Util.arglist(attributes_to_delete) }) if attributes_to_delete
  #  json_parse_reply(*json_patch(@target, "#{path}/#{URI.encode(id)}", info, @auth_header))
  #end

  # supported query keys are: attributes, filter, startIndex, count
  # output hash keys are: resources, totalResults, itemsPerPage
  def query_objects(path, query)
    query = query.reject {|k, v| v.nil? }
    query[:attributes] = Util.strlist(Util.arglist(query[:attributes]), ",") if query[:attributes]
    qstr = query.empty?? "": "?#{URI.encode_www_form(query)}"
    unless (info = json_get(@target, "#{path}#{qstr}", @auth_header)).is_a?(Hash) && info[:resources].is_a?(Array)
      raise BadResponse, "invalid reply to query of #{@target}#{path}"
    end
    info
  end

  def get_object(path, id) json_get(@target, "#{path}/#{URI.encode(id)}", @auth_header) end
  def get_object_by_name(path, name_attr, name)
    info = query_objects(path, filter: "#{name_attr} eq \"#{name}\"")
    unless info && info[:resources] && info[:resources][0] && (id = info[:resources][0][:id])
      raise NotFound, "#{name} not found in #{@target}#{path}"
    end

    # TODO: should be able to just return info[:resources][0] here but uaa does not yet return all attributes for a query
    get_object(path, id)
  end

  def all_ids(method, users)
    filter = users.each_with_object([]) { |u, o| o << "userName eq \"#{u}\" or id eq \"#{u}\"" }
    qinfo = all_pages(method, attributes: "userName,id", filter: filter.join(" or "))
    raise NotFound, "users not found in #{@target}#{path}" unless qinfo[0] && qinfo[0][:id]
    qinfo
  end

  public

  # the auth_header parameter refers to a string that can be used in an
  # authorization header. For oauth with jwt tokens this would be something
  # like "bearer xxxx.xxxx.xxxx". The Token class returned by TokenIssuer
  # provides an auth_header method for this purpose.
  def initialize(target, auth_header) @target, @auth_header = target, auth_header end

  def add_user(info) add_object("/Users", info) end
  def put_user(user_id, info) put_object("/Users", user_id, info) end
  #def patch_user(user_id, info, attributes_to_delete = nil) patch_object("/Users", user_id, info, attributes_to_delete) end
  def query_users(query) query_objects("/Users", query) end
  def get_user(user_id) get_object("/Users", user_id) end
  def get_user_by_name(name) get_object_by_name("/Users", "username", name) end
  def user_id_from_name(name) get_by_name(name)[:id] end
  def delete_user(user_id) http_delete @target, "/Users/#{URI.encode(user_id)}", @auth_header end
  def delete_user_by_name(name) delete user_id_from_name(name) end
  def add_group(info) add_object("/Groups", info) end
  def put_group(id, info, attributes_to_delete = nil) put_object("/Groups", id, info) end
  def query_groups(query) query_objects("/Groups", query) end
  def get_group(id) json_get(@target, "/Groups/#{URI.encode(id)}", @auth_header) end
  def delete_group(id) http_delete @target, "/Groups/#{URI.encode(id)}", @auth_header end
  def get_group_by_name(name) get_object_by_name("/Groups", "displayname", name) end
  def group_id_from_name(name) get_group_by_name(name)[:id] end
  def query_ids(query) query_objects("/ids/Users", query) end
  def ids_exclusive(*users) all_ids(:query_ids, users) end
  def ids(*users) all_ids(:query_users, users) end

  def change_password(user_id, new_password, old_password = nil)
    password_request = { password: new_password }
    password_request[:oldPassword] = old_password if old_password
    json_parse_reply(*json_put(@target, "/Users/#{URI.encode(user_id)}/password", password_request, @auth_header))
  end

  def change_password_by_name(name, new_password, old_password = nil)
    change_password(user_id_from_name(name), new_password, old_password)
  end

  # collects all pages of entries from a query, returns array of results. Method can be
  # any method that takes a single query arg. currently :query_users and :query_groups
  def all_pages(method, query)
    query = query.reject {|k, v| v.nil? }
    query[:startIndex], info = 1, []
    while true
      qinfo = send(method, query)
      return info unless qinfo[:resources] && !qinfo[:resources].empty?
      info.concat(qinfo[:resources])
      return info unless qinfo[:totalResults] && qinfo[:totalResults] > info.length
      raise BadResponse, "incomplete pagination data from #{@target}#{path}" unless qinfo[:startIndex] && qinfo[:itemsPerPage]
      query[:startIndex] = info.length + 1
    end
  end

  # takes a hash of fields currently supported by the uaa:
  #     client_id (required),
  #     client_secret,
  #     scope (array of strings or space or comma separated fields),
  #     authorized_grant_types (array of strings or space or comma separated fields),
  #     authorities (array of strings or space or comma separated fields),
  #     access_token_validity (integer)
  #     refresh_token_validity (integer)
  #     redirect_uri (array of strings or space or comma separated fields),
  def add_client(info)
    info = self.class.client_mva_to_arrays! Util.hash_keys(info)
    json_parse_reply *json_post(@target, "/oauth/clients", info, @auth_header)
  end

  def put_client(info)
    info = Util.hash_keys(info)
    raise ArgumentError, "a client registration put must specify a unique client id" unless info[:client_id]
    info = self.class.client_mva_to_arrays! info
    json_parse_reply *json_put(@target, "/oauth/clients/#{URI.encode(info[:client_id])}", info, @auth_header)
  end

  def get_client(id) json_get @target, "/oauth/clients/#{URI.encode(id)}", @auth_header end
  def delete_client(id) http_delete @target, "/oauth/clients/#{URI.encode(id)}", @auth_header end
  def list_clients; json_get @target, "/oauth/clients", @auth_header end

  def change_secret(client_id, new_secret, old_secret = nil)
    req = { secret: new_secret }
    req[:oldSecret] = old_secret if old_secret
    json_parse_reply(*json_put(@target, "/oauth/clients/#{URI.encode(client_id)}/secret", req, @auth_header))
  end

end

end
