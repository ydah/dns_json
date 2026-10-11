# frozen_string_literal: true

require_relative "../lib/dns_json"
require "objspace"
record = { "NAME" => ".", "TYPE" => 1, "CLASS" => 1, "TTL" => 0, "rdataA" => "192.0.2.9" }
message = DNSJSON::Message.new({ "ID" => 1, "QNAME" => ".", "QTYPE" => 1, "QCLASS" => 1, "answerRRs" => Array.new(4095, record) })
wire = message.to_wire
start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
10.times do
  parsed = DNSJSON.from_wire(wire)
  raise "roundtrip failed" unless DNSJSON.parse(parsed.to_json).to_wire == wire
end
elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
heap = ObjectSpace.memsize_of_all
puts JSON.generate(ruby: RUBY_DESCRIPTION, bytes: wire.bytesize, records: 4096, iterations: 10, seconds: elapsed.round(3), ruby_heap_bytes: heap)
