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

  class HttpTest
    include Http

    public :http_get
  end

  let(:http_instance) { HttpTest.new }

  it "sets a request handler" do
    http_instance.set_request_handler do |url, method, body, headers|
      [200, "body", {"content-type" => "text/plain"}]
    end
    status, body, resp_headers = http_instance.http_get("http://example.com")
    status.should == 200
    body.should == "body"
    resp_headers["content-type"].should == "text/plain"
  end

  it "utilizes proxy settings if given" do
    reply_double = double('http reply', each_header: {}).as_null_object
    http_double = double('http', request: reply_double, new: nil)
    Net::HTTP.stub(:new).and_return(http_double)
    http_instance.http_proxy = 'user:password@http-proxy.example.com:1234'
    http_instance.https_proxy = 'user:password@https-proxy.example.com:1234'

    http_instance.http_get("http://example.com")

    expect(Net::HTTP).to have_received(:new).with(anything, anything, 'http-proxy.example.com', 1234, 'user', 'password')
  end

  it "raises an SSLException when the certificate is not valid" do
    http_double = double('http').as_null_object
    Net::HTTP.stub(:new).and_return(http_double)
    http_double.stub(:request).and_raise(OpenSSL::SSL::SSLError)

    expect { http_instance.http_get("https://example.com") }.to raise_error(CF::UAA::SSLException)
  end

  it "skips ssl validation if requested" do
    http_double = double('http').as_null_object
    Net::HTTP.stub(:new).and_return(http_double)
    http_double.stub(:verify_mode=)

    http_instance.http_get("https://example.com")
    expect(http_double).not_to have_received(:verify_mode=)

    http_instance.skip_ssl_validation = true
    http_instance.http_get("https://uncached.example.com")
    expect(http_double).to have_received(:verify_mode=).with(OpenSSL::SSL::VERIFY_NONE)
  end

  it "passes ssl certificate file if provided" do
    http_double = double('http').as_null_object
    Net::HTTP.stub(:new).and_return(http_double)

    http_instance.ssl_ca_file = "/fake-ca-file"
    http_instance.http_get("https://uncached.example.com")

    expect(http_double).to have_received(:ca_file=).with("/fake-ca-file")
    expect(http_double).to have_received(:verify_mode=).with(OpenSSL::SSL::VERIFY_PEER)
  end
end

end
