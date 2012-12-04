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
require 'uaa/http'
require 'uaa/version'

module CF::UAA

describe Http do

  include Http
  include SpecHelper

  it "sets a request handler" do
    set_request_handler do |req|
      [200, "body", {"content-type" => "text/plain"}]
    end
    status, body, resp_headers = http_get("http://example.com")
    status.should == 200
    body.should == "body"
    resp_headers["content-type"].should == "text/plain"
  end

end

end
