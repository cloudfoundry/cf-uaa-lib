# CloudFoundry UAA Gem

Client gem for interacting with the CloudFoundry UAA server.

Set up a local ruby environment (so sudo not required):

  `$ rvm use 1.9.2`

or

  `$ rbenv global 1.9.2-p180`

see: https://rvm.io/ or http://rbenv.org/

Build the gem

  `$ bundle install`
  `$ gem build cf-uaa-lib.gemspec`

Install it

  `$ gem install cf-uaa-lib<version>.gem`

Use the gem:

  `#!/usr/bin/env ruby`
  `require 'uaa'`
  `token_issuer = CF::UAA::TokenIssuer.new("https://uaa.cloudfoundry.com", "vmc")`
  `puts token\_issuer.prompts.inspect`
  `token = token_issuer.implicit_grant_with_creds(username: "<your_username>", password: "<your_password>")`
  `token_info = TokenCoder.decode(token.info["access_token"], nil, nil, false) #token signature not verified`
  `puts token_info["user_name"]`

## Tests

Run the tests with rake:

  `$ bundle exec rake test`

Run the tests and see a fancy coverage report:

  `$ bundle exec rake cov`

