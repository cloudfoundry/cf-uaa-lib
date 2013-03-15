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

    before do
      Misc.set_request_handler do |url, method, body, headers|
        url.should == target_url
        method.should == :get
        headers["content-type"].should be_nil
        headers["accept"].gsub(/\s/, '').should =~ /application\/json;charset=utf-8/i
        [200, response_body, {"content-type" => "application/json"}]
      end
    end

    describe "getting server info" do
      let(:target_url) { "https://uaa.cloudfoundry.com/login" }
      let(:response_body) { '{"commit_id":"12345","prompts":["one","two"]}' }

      it "gets server info" do
        result = Misc.server("https://uaa.cloudfoundry.com")
        result["prompts"].should_not be_nil
        result["commit_id"].should_not be_nil
      end

      context "with symbol keys" do
        around do |example|
          CF::UAA::Misc.symbolize_keys = true
          example.call
          CF::UAA::Misc.symbolize_keys = false
        end

        it "gets server info" do
          result = Misc.server("https://uaa.cloudfoundry.com")
          result[:prompts].should_not be_nil
          result[:commit_id].should_not be_nil
        end
      end
    end

    describe "getting UAA target" do
      let(:target_url) { "https://login.cloudfoundry.com/login" }
      let(:response_body) { '{"links":{"uaa":"https://uaa.cloudfoundry.com"},"prompts":["one","two"]}' }

      it "gets UAA target" do
        result = Misc.discover_uaa("https://login.cloudfoundry.com")
        result.should == "https://uaa.cloudfoundry.com"
      end

      context "when there is no 'links' key present" do
        let(:response_body) { '{ "prompts" : ["one","two"]} ' }

        it "returns the login url" do
          result = Misc.discover_uaa("https://login.cloudfoundry.com")
          result.should == "https://login.cloudfoundry.com"
        end
      end

      context "with symbol keys" do
        around do |example|
          CF::UAA::Misc.symbolize_keys = true
          example.call
          CF::UAA::Misc.symbolize_keys = false
        end

        it "gets UAA target" do
          result = Misc.discover_uaa("https://login.cloudfoundry.com")
          result.should == "https://uaa.cloudfoundry.com"
        end
      end
    end
  end
end
