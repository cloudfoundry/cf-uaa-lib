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