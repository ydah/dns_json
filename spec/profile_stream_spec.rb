# frozen_string_literal: true

require "spec_helper"
RSpec.describe "profiles, pairs and sequences" do
  let(:message) { DNSJSON::Message.new({ "ID" => 5, "QR" => true, "QNAME" => "q.test.", "QTYPE" => 1, "QCLASS" => 1 }) }
  it "selects groups and normalizes one-bit flags" do
    profile = DNSJSON::Profile.new(include: [:header], one_bit_as: :boolean)
    expect(JSON.parse(message.to_json(profile: profile))).to eq("ID" => 5, "QR" => true)
    expect { DNSJSON::Profile.new(include: [:wrong]) }.to raise_error(ArgumentError)
    expect { DNSJSON::Profile.new(one_bit_as: :wrong) }.to raise_error(ArgumentError)
    profile = DNSJSON::Profile.new(required: ["ID"], prohibited: ["secret"])
    expect { DNSJSON.parse("{}", profile: profile) }.to raise_error(DNSJSON::ValidationError, /requires/)
    expect { DNSJSON.parse('{"ID":1,"secret":2}', profile: profile) }.to raise_error(DNSJSON::ValidationError, /prohibits/)
    expect(JSON.parse(DNSJSON::Message.new({ "ID" => 1, "secret" => 2 }).to_json(profile: profile))).to eq("ID" => 1)
  end
  it "removes ECS and all captured bytes or arbitrary metadata from privacy output" do
    data = message.to_h.merge("sourceAddress" => "private", "comment" => "private", "questionSecret" => "private", "rdataSecret" => "private",
                              "additionalRRs" => [{ "TYPE" => 41, "RDATAHEX" => "0008000800011800C00002" }],
                              "answerRRs" => [], "authorityRRs" => [], "messageOctetsHEX" => "AB", "vendor" => { "secret" => "private" })
    text = DNSJSON::Message.new(data).to_json(profile: DNSJSON::Profile::PRIVACY)
    expect(text).not_to include("HEX", "private", "additional", "ID")
    expect(text).to include("QNAME", "answerRRs", "authorityRRs")
  end
  it "roundtrips pairs with optional sides and extensions" do
    pair = DNSJSON::Pair.new({ "correlation" => "ok" }, query: message, response: message)
    parsed = DNSJSON.parse(pair.to_json)
    expect(parsed).to be_a(DNSJSON::Pair)
    expect(parsed.query["ID"]).to eq(5)
    expect(parsed.response["ID"]).to eq(5)
    expect(parsed["correlation"]).to eq("ok")
    expect(DNSJSON::Pair.new.query).to be_nil
    expect { pair.to_wire }.to raise_error(DNSJSON::ConversionError)
  end
  it "reads and writes incremental JSON text sequences" do
    io = StringIO.new
    writer = DNSJSON::Stream::Writer.new(io)
    expect(writer << message << DNSJSON::Pair.new(query: message)).to equal(writer)
    expect(io.string).to start_with("\x1e")
    io.rewind
    reader = DNSJSON::Stream::Reader.new(io)
    expect(reader.each.map(&:class)).to eq([DNSJSON::Message, DNSJSON::Pair])
    expect(reader.problems).to be_empty
  end
  it "recovers from bad and overlong elements and limits buffered memory" do
    io = StringIO.new("garbage\x1e{broken\n\x1e#{"x" * 100}\x1e{}\n\x1e\x1e{}")
    reader = DNSJSON::Stream::Reader.new(io, max_json_bytes: 20)
    expect(reader.to_a.map(&:to_h)).to eq([{}, {}])
    expect(reader.problems.length).to eq(3)
    reader = DNSJSON::Stream::Reader.new(StringIO.new("\x1e!"), strict: true)
    expect { reader.to_a }.to raise_error(DNSJSON::ParseError)
  end
  it "handles chunk boundaries without using line length as a memory bound" do
    io = StringIO.new("\x1e#{JSON.generate({ "comment" => "x" * 9000 })}\n\x1e{}\n")
    expect(DNSJSON::Stream::Reader.new(io).to_a.length).to eq(2)
    expect(DNSJSON::Stream::Reader.new(StringIO.new(" \n")).to_a).to eq([])
  end
end

RSpec.describe "output resource bounds" do
  it "caps retained stream problems while continuing to read" do
    reader = DNSJSON::Stream::Reader.new(StringIO.new("#{"\x1e!" * 20}\x1e{}"), max_problems: 3)
    expect(reader.to_a.length).to eq(1)
    expect(reader.problems.length).to eq(3)
    expect(reader.dropped_problems).to eq(17)
    expect { DNSJSON::Stream::Reader.new(StringIO.new, max_problems: -1) }.to raise_error(ArgumentError)
  end
  it "checks JSON output size and rrSet expansion before allocation" do
    expect { DNSJSON::Message.new({ "comment" => "abcdef" }, max_json_bytes: 5).to_json }.to raise_error(DNSJSON::LimitError)
    data = { "ID" => 1, "answerRRs" => [{ "rrSet" => [{}, {}] }, { "rrSet" => [{}, {}] }] }
    expect { DNSJSON::Message.new(data, max_records: 2).to_wire }.to raise_error(DNSJSON::LimitError)
  end
end

RSpec.describe "extension preservation" do
  it "does not reinterpret member names inside arbitrary extensions" do
    value = { "extension" => { "QR" => "custom", "answerRRs" => "custom", "QNAME" => [1] } }
    expect(DNSJSON.parse(DNSJSON::Message.new(value).to_json).to_h).to eq(value)
  end
  it "propagates exceptions raised by a stream consumer" do
    reader = DNSJSON::Stream::Reader.new(StringIO.new("\x1e{}"))
    expect { reader.each { |message| raise DNSJSON::ConversionError, "caller error" if message } }.to raise_error(DNSJSON::ConversionError, "caller error")
  end
end
