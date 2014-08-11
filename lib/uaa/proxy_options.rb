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

module CF::UAA
  module ProxyOptions
    def proxy_options_for(uri)
      ssl = uri.is_a?(URI::HTTPS)
      proxy_to_use = (ssl ? https_proxy : http_proxy)

      if proxy_to_use
        proxy_to_use = "proto://#{proxy_to_use}" unless proxy_to_use =~ /:\/\//
        proxy_uri = URI.parse(proxy_to_use)
        proxy_user, proxy_password = proxy_uri.userinfo.split(/:/) if proxy_uri.userinfo
        [proxy_uri.host, proxy_uri.port, proxy_user, proxy_password]
      else
        []
      end
    end
  end
end