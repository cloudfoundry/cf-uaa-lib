# -*- encoding: utf-8 -*-
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

$:.push File.expand_path("../lib", __FILE__)
require "uaa/version"

Gem::Specification.new do |s|
  s.name        = 'cf-uaa-lib'
  s.version     = CF::UAA::VERSION
  s.authors     = ['Dave Syer', 'Dale Olds', 'Joel D\'sa', 'Vidya Valmikinathan', 'Luke Taylor']
  s.email       = ['dsyer@vmware.com', 'olds@vmware.com', 'jdsa@vmware.com', 'vidya@vmware.com', 'ltaylor@vmware.com']
  s.homepage    = 'https://github.com/cloudfoundry/cf-uaa-lib'
  s.summary     = %q{Client library for CloudFoundry UAA}
  s.description = %q{Client library for interacting with the CloudFoundry User Account and Authorization (UAA) server.  The UAA is an OAuth2 Authorization Server so it can be used by webapps and command line apps to obtain access tokens to act on behalf of users.  The tokens can then be used to access protected resources in a Resource Server.  This library is for use by UAA client applications or resource servers.}

  s.rubyforge_project = "cf-uaa-lib"

  s.license       = "Apache-2.0"
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split('\n').map{ |f| File.basename(f) }
  s.require_paths = ['lib']

  # dependencies
  s.add_dependency 'multi_json', '>= 1.12.1', '< 1.16'
  s.add_dependency 'httpclient', '~> 2.8', '>= 2.8.2.4'

  s.add_development_dependency 'bundler', '~> 1.14'
  s.add_development_dependency 'rake', '~> 10.3', '>= 10.3.2'
  s.add_development_dependency 'rspec', '>= 2.14.1', '~> 3.10'
  s.add_development_dependency 'simplecov', '~> 0.19.0'
  s.add_development_dependency 'simplecov-rcov', '~> 0.2.3'
  s.add_development_dependency 'ci_reporter', '~> 1.9', '>= 1.9.2'
  s.add_development_dependency 'json_pure', '~> 1.8', '>= 1.8.1'

end
