# CloudFoundry UAA Gem
![Build status](https://github.com/cloudfoundry/cf-uaa-lib/actions/workflows/ruby.yml/badge.svg?branch=master)
[![Gem Version](https://badge.fury.io/rb/cf-uaa-lib.png)](http://badge.fury.io/rb/cf-uaa-lib)

Client gem for interacting with the [CloudFoundry UAA server](https://github.com/cloudfoundry/uaa)

For documentation see: https://rubygems.org/gems/cf-uaa-lib

## Install from rubygems

```plain
gem install cf-uaa-lib
```

## Build from source

```plain
bundle install
rake install
```

## Use the gem

```ruby
#!/usr/bin/env ruby

require 'uaa'
token_issuer = CF::UAA::TokenIssuer.new("https://uaa.cloudfoundry.com", "vmc")
puts token_issuer.prompts.inspect
token = token_issuer.implicit_grant_with_creds(username: "<your_username>", password: "<your_password>")
token_info = CF::UAA::TokenCoder.decode(token.info["access_token"]) #token signature not verified
puts token_info["user_name"]
```

## Tests

Run the tests with rake:

```plain
bundle exec rake test
```

Run the tests and see a fancy coverage report:

```plain
bundle exec rake cov
```

