# CloudFoundry UAA Gem
[![Build Status](https://travis-ci.org/cloudfoundry/cf-uaa-lib.png)](https://travis-ci.org/cloudfoundry/cf-uaa-lib)
[![Gem Version](https://badge.fury.io/rb/cf-uaa-lib.png)](http://badge.fury.io/rb/cf-uaa-lib)

Client gem for interacting with the [CloudFoundry UAA server](https://github.com/cloudfoundry/uaa)

For documentation see: https://rubygems.org/gems/cf-uaa-lib

## Install from rubygems

    $ gem install cf-uaa-lib

## Build from source

    $ bundle install
    $ gem build cf-uaa-lib.gemspec
    $ gem install cf-uaa-lib<version>.gem

## Use the gem

    #!/usr/bin/env ruby
    require 'uaa'
    token_issuer = CF::UAA::TokenIssuer.new("https://uaa.cloudfoundry.com", "vmc")
    puts token_issuer.prompts.inspect
    token = token_issuer.implicit_grant_with_creds(username: "<your_username>", password: "<your_password>")
    token_info = TokenCoder.decode(token.info["access_token"], nil, nil, false) #token signature not verified
    puts token_info["user_name"]

## Tests

Run the tests with rake:

    $ bundle exec rake test

Run the tests and see a fancy coverage report:

    $ bundle exec rake cov

