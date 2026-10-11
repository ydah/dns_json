# frozen_string_literal: true

require "spec_helper"
require_relative "support/rdata_cases"

RSpec.describe DNSJSON::RData do
  RDATA_CASES.each do |type, text|
    it "roundtrips #{DNSJSON::RData::FORMATS[type]} through independently specified text and wire" do
      bytes = described_class.encode(type, text)
      expect(described_class.decode(type, bytes, 0, bytes.bytesize)).to eq(text)
      data = { "ID" => 100, "QNAME" => "test.", "QTYPE" => type, "QCLASS" => 1,
               "answerRRs" => [{ "NAME" => "test.", "TYPE" => type, "CLASS" => 1, "TTL" => 10, "rdata#{DNSJSON::RData::FORMATS[type]}" => text }] }
      wire = DNSJSON::Message.new(data).to_wire
      parsed = DNSJSON.from_wire(wire)
      expect(parsed).not_to be_malformed
      expect(parsed["answerRRs"].first["rdata#{DNSJSON::RData::FORMATS[type]}"]).to eq(text)
      expect(DNSJSON.parse(parsed.to_json).to_wire).to eq(wire)
    end
  end
  it "supports every IPSECKEY gateway form" do
    ["0 0 0 . .", "10 1 2 192.0.2.1 AQID", "10 2 2 2001:db8::1 AQID"].each do |text|
      bytes = described_class.encode(45, text)
      expect(described_class.decode(45, bytes, 0, bytes.bytesize)).to eq(text)
    end
  end
  it "preserves arbitrary TXT octets through ASCII JSON, including split strings" do
    bytes = "\x03a\xffb\x02cd".b
    text = described_class.decode(16, bytes, 0, bytes.bytesize)
    expect(text).to eq("aÿbcd")
    expect(described_class.encode(16, text)).to eq("\x05a\xffbcd".b)
    expect(described_class.encode(16, "a" * 600).bytesize).to eq(603)
    expect(described_class.encode(16, "")).to eq("\0")
    quoted = "#{DNSJSON::RData.quote("one\x00\xff\"\\".b)} \"two\""
    encoded = described_class.encode(99, quoted)
    expect(described_class.encode(99, described_class.decode(99, encoded, 0, encoded.bytesize))).to eq(encoded)
  end
  it "handles empty NSEC3 salt, all bitmap windows and base32 residual bits" do
    ["1 1 0 - 00", "1 0 0 - 0010 TYPE0 TYPE255 TYPE256 TYPE65535"].each do |text|
      bytes = described_class.encode(50, text)
      decoded = described_class.decode(50, bytes, 0, bytes.bytesize)
      expect(described_class.encode(50, decoded)).to eq(bytes)
    end
    20.times do |size|
      bytes = Random.new(size).bytes(size)
      next if size.zero?

      expect(described_class.base32_decode(described_class.base32_encode(bytes))).to eq(bytes)
    end
  end
  it "rejects malformed presentations and unsafe ranges" do
    [[1, "::1"], [1, "192.0.2.0/24"], [28, "abc"], [15, "-1 test."], [15, "65536 test."], [15, "10"],
     [15, "10 test. excess"], [48, "1 3 8 ***"], [52, "1 2 3 ABC"], [45, "1 9 0 . ."], [45, "1 0 0 invalid ."],
     [46, "A 8 2 60 wrong 0 1 x. AA=="], [46, "A 8 2 60 20250230000000 0 1 x. AA=="],
     [99, "unquoted"], [99, '"unclosed'], [99, '"\\999"'], [99, '"\\'], [65_000, "x"], [16, nil]].each do |type, text|
      expect { described_class.encode(type, text) }.to raise_error(DNSJSON::ConversionError)
    end
    expect { described_class.base32_decode("Z") }.to raise_error(DNSJSON::ConversionError)
    expect { described_class.base32_decode("01") }.to raise_error(DNSJSON::ConversionError)
  end
  it "rejects truncated and noncanonical binary RDATA" do
    [[1, "a"], [28, "x"], [15, "\0"], [16, "\x03ab"], [5, "\0extra"], [45, "\x01\x09\x01"],
     [47, "\0\0\x01\0"], [47, "\0\0\x21"], [47, "\0\0"], [47, "\0\0\x01\x80\0\x01\x80"]].each do |type, bytes|
      expect { described_class.decode(type, bytes.b, 0, bytes.bytesize) }.to raise_error(DNSJSON::ConversionError)
    end
    expect(described_class.decode(65_000, "opaque", 0, 6)).to be_nil
  end
  it "accepts numeric DNSSEC times and rejects oversize data" do
    bytes = described_class.encode(46, "TYPE65000 8 0 0 0 1 0 . AQ==")
    expect(described_class.decode(46, bytes, 0, bytes.bytesize)).to include("19700101000000", "19700101000001")
    expect { described_class.encode(61, ["a" * 65_536].pack("m0")) }.to raise_error(DNSJSON::ConversionError, /65535/)
  end
end
