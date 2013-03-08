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

require 'spec_helper'
require 'uaa/misc'

module CF::UAA

describe Misc do

  include SpecHelper

  before :all do
    #Util.default_logger(:trace)
  end

  it "gets server info" do
    Misc.set_request_handler do |url, method, body, headers|
      url.should == "https://uaa.cloudfoundry.com/login"
      method.should == :get
      headers["content-type"].should be_nil
      headers["accept"].gsub(/\s/, '').should =~ /application\/json;charset=utf-8/i
      [200, '{"commit_id":"12345","prompts":["one","two"]}', {"content-type" => "application/json"}]
    end
    result = Misc.server("https://uaa.cloudfoundry.com")
    result["prompts"].should_not be_nil
    result["commit_id"].should_not be_nil
  end

  it "gets UAA target" do
    Misc.set_request_handler do |url, method, body, headers|
      url.should == "https://login.cloudfoundry.com/login"
      method.should == :get
      headers["content-type"].should be_nil
      headers["accept"].gsub(/\s/, '').should =~ /application\/json;charset=utf-8/i
      [200, '{"links":{"uaa":"https://uaa.cloudfoundry.com"},"prompts":["one","two"]}', {"content-type" => "application/json"}]
    end
    result = Misc.discover_uaa("https://login.cloudfoundry.com")
    result.should == "https://uaa.cloudfoundry.com"
  end

end

end
