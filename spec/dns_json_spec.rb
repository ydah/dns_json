# frozen_string_literal: true

require "spec_helper"
RSpec.describe DNSJSON do
  it "rejects impossible timestamps, invalid input types and unsafe limit settings" do
    ["2026-02-30T12:00:00Z", "2026-01-01T24:00:00Z", "2026-01-01T00:00:00+24:00"].each do |date|
      expect { DNSJSON::Message.new({ "dateString" => date }) }.to raise_error(DNSJSON::ValidationError)
    end
    expect { DNSJSON.parse(nil) }.to raise_error(DNSJSON::ParseError)
    expect { DNSJSON.from_wire(nil) }.to raise_error(DNSJSON::ParseError)
    [{ max_depth: 0 }, { max_bytes: -1 }, { max_records: "1" }, { unknown: 1 }].each do |limits|
      expect { DNSJSON.parse("{}", **limits) }.to raise_error(ArgumentError)
      expect { DNSJSON::Message.new({}, **limits) }.to raise_error(ArgumentError)
    end
  end
  let(:query) { DNSJSON::Message.new({ "ID" => 4123, "QNAME" => "alpha.test.", "QTYPE" => 1, "QCLASS" => 1, "RD" => true }) }
  let(:wire) { query.to_wire }
  def rr(type, text)
    { "NAME" => "alpha.test.", "TYPE" => type, "CLASS" => 1, "TTL" => 60, "rdata#{DNSJSON::RData::FORMATS.fetch(type)}" => text }
  end
  it "roundtrips wire bytes and unknown JSON members" do
    parsed = DNSJSON.from_wire(wire)
    expect(parsed).not_to be_malformed
    expect(DNSJSON.parse(parsed.to_json).to_wire).to eq(wire)
    data = query.to_h.merge("vendor" => { "nested" => [false, nil, "hello"] })
    expect(DNSJSON.parse(DNSJSON::Message.new(data).to_json).to_h).to eq(data.merge("RD" => 1))
    expect(parsed["compressedQNAME"]).to eq("length" => 12, "isCompressed" => 0)
  end
  it "agrees with resolv on query flags, names and answers" do
    external = Resolv::DNS::Message.new(76)
    external.rd = 1
    external.add_question("unit.test", Resolv::DNS::Resource::IN::A)
    external.add_answer("unit.test", 90, Resolv::DNS::Resource::IN::A.new("198.51.100.17"))
    parsed = DNSJSON.from_wire(external.encode)
    expect(parsed).not_to be_malformed
    expect(parsed["QNAME"]).to eq("unit.test.")
    expect(parsed["answerRRs"].first["rdataA"]).to eq("198.51.100.17")
    expect(parsed["answerRRs"].first["compressedNAME"]["isCompressed"]).to eq(1)
    rebuilt = parsed.to_h.reject { |k, _| k.end_with?("HEX") }
    decoded = Resolv::DNS::Message.decode(DNSJSON::Message.new(rebuilt).to_wire)
    expect(decoded.answer.first.last.address.to_s).to eq("198.51.100.17")
  end
  it "decodes compressed RDATA against the whole message and rebuilds without stale offsets" do
    external = Resolv::DNS::Message.new(7)
    external.add_question("mail.test", Resolv::DNS::Resource::IN::MX)
    external.add_answer("mail.test", 5, Resolv::DNS::Resource::IN::MX.new(10, Resolv::DNS::Name.create("mx.mail.test")))
    parsed = DNSJSON.from_wire(external.encode)
    expect(parsed["answerRRs"].first["rdataMX"]).to eq("10 mx.mail.test.")
    data = parsed.to_h
    data.delete("messageOctetsHEX")
    expect(Resolv::DNS::Message.decode(DNSJSON::Message.new(data).to_wire).answer.first.last.exchange.to_s).to eq("mx.mail.test")
  end
  it "preserves TTL signed values and explicitly inconsistent counts/lengths" do
    data = query.to_h.merge("ANCOUNT" => 1, "answerRRs" => [rr(1, "192.0.2.7").except("rdataA").merge("RDATAHEX" => "C0000207", "TTL" => -1, "RDLENGTH" => 2)])
    parsed = DNSJSON.from_wire(DNSJSON::Message.new(data).to_wire)
    expect(parsed).to be_malformed
    expect(parsed["answerRRs"].first["TTL"]).to eq(-1)
    expect(parsed.problems.map(&:reason).join).to include("address length", "trailing")
  end
  it "retains all truncated headers without exceptions" do
    12.times do |size|
      source = wire.byteslice(0, size)
      parsed = DNSJSON.from_wire(source)
      expect(parsed).to be_malformed
      expect(parsed.to_wire).to eq(source)
      expect(parsed["headerOctetsHEX"]).to eq(DNSJSON.hex(source))
    end
  end
  it "reports zero questions and oversized counts" do
    parsed = DNSJSON.from_wire([1, 0, 0, 65_535, 0, 0].pack("n6"))
    expect(parsed.problems.map(&:reason).join).to include("zero questions", "truncated name")
  end
  it "retains truncated RDATA and undecodable sections" do
    source = DNSJSON::Message.new(query.to_h.merge("answerRRs" => [rr(1, "192.0.2.7")])).to_wire
    parsed = DNSJSON.from_wire(source.byteslice(0...-2))
    expect(parsed.problems.map(&:reason)).to include("RDLENGTH exceeds available RDATA")
    expect(parsed.to_wire).to eq(source.byteslice(0...-2))
    short = DNSJSON.from_wire(wire.byteslice(0...-2))
    expect(short["questionOctetsHEX"]).to eq(DNSJSON.hex(wire.byteslice(12...-2)))
  end
  it "handles pointer loops, forward pointers, reserved labels and truncation" do
    ["\xc0\x0c", "\xc0\xff", "\xc0", "\x40", "\x3fX", "\x01a\xc0\x0c"].each do |name|
      source = wire.byteslice(0, 12) + name.b
      parsed = DNSJSON.from_wire(source)
      expect(parsed).to be_malformed
      expect(parsed.to_wire).to eq(source)
    end
    expect { DNSJSON::Wire::Name.read("\0\xc0\0".b, 1, max_pointers: 0) }.to raise_error(DNSJSON::ConversionError, /max_pointers/)
  end
  it "enforces configured input, record, depth and output limits" do
    expect { DNSJSON.from_wire(wire, max_bytes: 2) }.to raise_error(DNSJSON::LimitError)
    expect(DNSJSON.from_wire(wire, max_records: 0)).to be_malformed
    expect { DNSJSON.parse("{}", max_json_bytes: 1) }.to raise_error(DNSJSON::LimitError)
    expect { DNSJSON.parse('{"x":{"y":{"z":{}}}}', max_depth: 2) }.to raise_error(DNSJSON::ParseError)
    expect { DNSJSON::Message.new({ "x" => [1, 2] }, max_records: 1) }.to raise_error(DNSJSON::LimitError)
    expect { DNSJSON::Message.new({ "x" => { "y" => {} } }, max_depth: 1) }.to raise_error(DNSJSON::LimitError)
    expect { DNSJSON::Message.new(query.to_h, max_bytes: 12).to_wire }.to raise_error(DNSJSON::LimitError)
    expect { DNSJSON::Message.new(query.to_h, max_records: 0).to_wire }.to raise_error(DNSJSON::LimitError)
  end
  it "fuzzes random and mutated wire packets without exceptions or loss" do
    random = Random.new(402)
    1500.times do |i|
      bytes = i.even? ? random.bytes(random.rand(300)) : wire.dup.tap { |b| random.rand(1..4).times { b.setbyte(random.rand(b.bytesize), random.rand(256)) } }
      parsed = DNSJSON.from_wire(bytes)
      expect(DNSJSON.parse(parsed.to_json).to_wire).to eq(bytes)
    end
  end
  it "roundtrips randomly generated bounded names and records" do
    random = Random.new(800)
    200.times do
      labels = Array.new(random.rand(1..4)) { random.bytes(random.rand(1..30)) }
      name = DNSJSON::Wire::Name.display(labels)
      expect(DNSJSON::Wire::Name.encode(name)).to eq(DNSJSON::Wire::Name.pack(labels))
      data = query.to_h.merge("QNAME" => name, "ID" => random.rand(65_536), "answerRRs" => [rr(1, "10.#{random.rand(256)}.0.1")])
      encoded = DNSJSON::Message.new(data).to_wire
      expect(DNSJSON.parse(DNSJSON.from_wire(encoded).to_json).to_wire).to eq(encoded)
    end
  end
  it "escapes names according to verified erratum 5439 without HEX ambiguity" do
    name = "a\\.b.\\\\.\\000\\255."
    encoded = DNSJSON::Wire::Name.encode(name)
    expect(DNSJSON::Wire::Name.display(DNSJSON::Wire::Name.read(encoded, 0).first)).to eq(name)
    expect(DNSJSON.parse(DNSJSON::Message.new(query.to_h.merge("QNAME" => name)).to_json).to_wire).to include(encoded)
    expect(DNSJSON::Wire::Name.encode(".")).to eq("\0")
    expect(DNSJSON::Wire::Name.display([])).to eq(".")
    max = ["a" * 63, "b" * 63, "c" * 63, "d" * 61]
    expect(DNSJSON::Wire::Name.pack(max).bytesize).to eq(255)
    ["a..b", "a\\", "a\\999", "a" * 64, (["a" * 63] * 5).join("."), "é"].each do |invalid|
      expect { DNSJSON::Wire::Name.encode(invalid) }.to raise_error(DNSJSON::ConversionError)
    end
    expect { DNSJSON::Wire::Name.read("#{([63].pack("C") + ("a" * 63)) * 5}\0", 0) }.to raise_error(DNSJSON::ConversionError)
  end
  it "requires fields for reconstruction but prefers messageOctetsHEX" do
    expect(DNSJSON::Message.new({ "messageOctetsHEX" => "00" }).to_wire).to eq("\0")
    expect { DNSJSON::Message.new.to_wire }.to raise_error(DNSJSON::ConversionError, /ID/)
    expect { DNSJSON::Message.new(query.to_h.merge("QTYPE" => nil), strict: false).to_wire }.to raise_error(DNSJSON::ValidationError)
    named = query.to_h.except("QTYPE", "QCLASS").merge("QTYPEname" => "TYPE65000", "QCLASSname" => "CLASS200")
    expect(DNSJSON.from_wire(DNSJSON::Message.new(named).to_wire)["QTYPE"]).to eq(65_000)
    expect { DNSJSON::Registry.number("bad") }.to raise_error(DNSJSON::ConversionError)
    expect { DNSJSON::Message.new(query.to_h.merge("QNAMEHEX" => "0000")).to_wire }.to raise_error(DNSJSON::ConversionError)
  end
  it "expands rrSet and retains unsupported record bytes" do
    record = { "NAME" => ".", "TYPE" => 65_000, "CLASS" => 1, "TTL" => 0, "rrSet" => [{ "RDATAHEX" => "AB" }, { "RDATAHEX" => "CD" }] }
    parsed = DNSJSON.from_wire(DNSJSON::Message.new(query.to_h.merge("answerRRs" => [record])).to_wire)
    expect(parsed["ANCOUNT"]).to eq(2)
    expect(parsed["answerRRs"].map { |r| r["RDATAHEX"] }).to eq(%w[AB CD])
  end
  it "outputs ASCII and decimal dates, retaining precise float values" do
    [0.000000001, 1e30, 123.75].each do |number|
      text = DNSJSON::Message.new({ "dateSeconds" => number, "comment" => "測定" }).to_json
      expect(text).to be_ascii_only
      expect(text.split(",").first).not_to match(/\d[eE][+-]?\d/)
      expect(DNSJSON.parse(text)["dateSeconds"]).to eq(number)
    end
    parsed = DNSJSON.from_wire(wire, date: Time.utc(2025, 2, 3))
    expect(parsed["dateString"]).to eq("2025-02-03T00:00:00.000000Z")
    expect { DNSJSON.from_wire(wire, date: -1) }.to raise_error(ArgumentError)
  end
  it "rejects invalid JSON members with pointers, while lenient parsing records warnings" do
    { "ID" => -1, "Opcode" => 16, "QR" => 3, "TTL" => 2_147_483_648, "dateSeconds" => -1, "dateString" => "oops",
      "comment" => 7, "NAMEHEX" => "ff", "answerRRs" => [3], "compressedNAME" => [] }.each do |key, value|
      json = JSON.generate({ key => value })
      expect { DNSJSON.parse(json) }.to raise_error(DNSJSON::ValidationError) { |e| expect(e.pointer).to eq("/#{key}") }
      object = DNSJSON.parse(json, strict: false)
      expect(object.warnings.length).to be >= 1
      expect { object.to_json }.to raise_error(DNSJSON::ValidationError)
    end
    expect { DNSJSON.parse('{"ID":1,"ID":2}') }.to raise_error(DNSJSON::ParseError)
    expect { DNSJSON.parse("[]") }.to raise_error(DNSJSON::ParseError)
    expect { DNSJSON.parse("!") }.to raise_error(DNSJSON::ParseError)
    expect { DNSJSON.parse('{"comment":"é"}') }.to raise_error(DNSJSON::ParseError)
    expect { DNSJSON::Message.new({ "x" => Float::INFINITY }) }.to raise_error(DNSJSON::ValidationError)
    expect { DNSJSON::Message.new({ "x" => Object.new }) }.to raise_error(DNSJSON::ValidationError)
  end
  it "does not mutate caller input through to_h" do
    data = query.to_h
    model = DNSJSON::Message.new(data)
    model.to_h["QNAME"].replace("evil")
    expect(model["QNAME"]).to eq("alpha.test.")
    expect(data["QNAME"]).to eq("alpha.test.")
  end
end

RSpec.describe "format boundaries" do
  it "rejects exponent and signed decimal dateSeconds at its actual pointer" do
    expect { DNSJSON.parse('{"queryMessage":{"dateSeconds":1e3}}') }.to raise_error(DNSJSON::ValidationError) { |e| expect(e.pointer).to eq("/queryMessage/dateSeconds") }
    expect { DNSJSON.parse('{"dateSeconds":-0.0}') }.to raise_error(DNSJSON::ValidationError)
    expect(DNSJSON.parse('{"dateSeconds":1e3}', strict: false).warnings.length).to eq(1)
    expect(DNSJSON.parse('{"extension":{"dateSeconds":1e3,"ID":"anything"}}')["extension"]).to eq("dateSeconds" => 1000.0, "ID" => "anything")
  end
  it "limits cyclic application objects before copying" do
    data = {}
    data["cycle"] = data
    expect { DNSJSON::Message.new(data) }.to raise_error(DNSJSON::LimitError)
  end
  it "exports typed accessors and keeps subnormal date values exact" do
    message = DNSJSON::Message.new({ "ID" => 3, "dateSeconds" => 5e-324 })
    expect(message.id).to eq(3)
    expect(DNSJSON.parse(message.to_json)["dateSeconds"]).to eq(5e-324)
  end
end
