# frozen_string_literal: true

require "spec_helper"
RSpec.describe "downloaded RFC 8427 examples" do
  Dir[File.expand_path("../tmp/rfc/fixtures/*.json", __dir__)].each do |path|
    it "roundtrips #{File.basename(path)} without discarding inconsistent fields" do
      source = File.read(path)
      message = DNSJSON.parse(source)
      expect(JSON.parse(message.to_json)).to eq(JSON.parse(source))
      if path.include?("query")
        parsed = DNSJSON.from_wire(message.to_wire)
        expect(parsed["ID"]).to eq(message["ID"])
        expect(parsed["QNAME"].delete_suffix(".")).to eq(message["QNAME"].delete_suffix("."))
      end
    end
  end
end
