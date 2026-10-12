<h1 align="center">dns_json</h1>

<p align="center">DNS wire messages and RFC 8427 JSON, with malformed-packet diagnostics.</p>

<p align="center">
  <a href="https://rubygems.org/gems/dns_json"><img src="https://img.shields.io/gem/v/dns_json" alt="Gem version"></a>
  <a href="https://github.com/ydah/dns_json/actions/workflows/main.yml"><img src="https://github.com/ydah/dns_json/actions/workflows/main.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://www.ruby-lang.org/"><img src="https://img.shields.io/badge/Ruby-%3E%3D%203.3-CC342D?logo=ruby&amp;logoColor=white" alt="Ruby 3.3 or later"></a>
  <a href="LICENSE.txt"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"></a>
</p>

<p align="center">
  <a href="https://ydah.github.io/dns_json/">Website</a> &middot;
  <a href="#installation">Installation</a> &middot;
  <a href="#quick-start">Quick start</a> &middot;
  <a href="#wire-reconstruction-and-names">Wire reconstruction and names</a> &middot;
  <a href="#development">Development</a> &middot;
  <a href="#license">License</a>
</p>

Read and write DNS messages as [RFC 8427](https://www.rfc-editor.org/rfc/rfc8427) JSON, including malformed packets used for diagnostics.

## Installation

Add the gem to your Gemfile:

```ruby
gem "dns_json"
```

Then run `bundle install`.

Requires Ruby 3.3 or later and `json` >= 2.19.4, < 4.

## Quick start

```ruby
require "dns_json"

query = DNSJSON::Message.new({
  "ID" => 1042, "RD" => 1, "QNAME" => "service.test.",
  "QTYPE" => 28, "QCLASS" => 1
})
packet_bytes = query.to_wire
message = DNSJSON.from_wire(packet_bytes, date: Time.now)

message.qname       # => "service.test."
message.malformed?  # => false
message.problems    # => [] (malformed input reports byte offsets and reasons)
message.to_json(profile: DNSJSON::Profile::LOGGING)
DNSJSON.parse(message.to_json).to_wire == packet_bytes # => true
```

`Message` and `RR` expose members through `[]`; `to_h` returns a deep copy. All RFC members are optional, and unknown members survive JSON round trips. Use `parse(..., strict: false)` to inspect invalid values through `warnings` with JSON Pointers; serialization always validates. JSON uses ASCII with escaped Unicode, and duplicate object keys are rejected.

| Supported | Scope |
| --- | --- |
| Wire decoding | Headers, questions and RR sections; compressed names; partial/malformed packets with diagnostics and original octets |
| Wire encoding | Original bytes when `messageOctetsHEX` exists; otherwise uncompressed structured reconstruction, including rrSet expansion |
| RDATA | All types with fields defined in [RFC 8427 §2.3](https://www.rfc-editor.org/rfc/rfc8427#section-2.3), plus DS |
| Other RR types | Numeric/IANA names and opaque `RDATAHEX` |
| Pairs and streams | §3 query/response pairs and §4 RFC 7464 JSON text sequences |
| Profiles | Member groups, mandatory/prohibited members, boolean or numeric one-bit values, privacy preset |
| Not included | DNS resolution, DNSSEC verification, IDN U-label conversion, pcap, DNS Update-specific JSON, semantic validation of cryptographic key material |

## Wire reconstruction and names

`messageOctetsHEX` overrides structured fields, including for malformed packets. To edit a packet, copy it with `to_h`, remove that member, make your changes, then create a new `Message`.

Without original bytes, supply ID, each record's name/type/class, and answer TTL/RDATA. Flags default to zero; counts default to section lengths unless supplied. `NAMEHEX`/`QNAMEHEX` override display names and must contain an uncompressed whole name.

Structured `rdata*` overrides `RDATAHEX` and recalculates RDLENGTH. Raw `RDATAHEX` retains an explicit RDLENGTH and may contain compression offsets that cannot safely be relocated; retain whole-message HEX for exact reproduction. `rrOctetsHEX`, header and section octets are diagnostic only.

Names use DNS escapes for literal dots, backslashes and nonprintable/high octets ([erratum 5439](https://www.rfc-editor.org/errata/eid5439)). Relative names become absolute; root is `.`. Compression pointers must point backward, loops are rejected, and expanded names are limited to 255 octets.

TXT joins wire character-strings into one string; original HEX preserves their boundaries. Encoding splits text into chunks of at most 255 octets, mapping octets to U+0000–U+00FF. SPF uses quoted DNS presentation strings. Undecodable RDATA remains HEX with a diagnostic.

One-bit output defaults to 0/1; boolean input is accepted. TTL uses a signed 32-bit range. `dateSeconds` is nonnegative and emitted without an exponent.

## Profiles, pairs and streams

```ruby
profile = DNSJSON::Profile.new(
  include: %i[header question answer rdata hex],
  required: %w[QNAME], prohibited: %w[comment], one_bit_as: :boolean
)
message.to_json(profile: profile)
message.to_json(profile: DNSJSON::Profile::PRIVACY)

pair = DNSJSON::Pair.new(query: query, response: message)
DNSJSON::Stream::Writer.new(io) << pair
DNSJSON::Stream::Reader.new(io).each { |entry| puts entry.to_json }
```

Groups: `header`, `question`, `answer`, `authority`, `additional`, `rdata`, `hex`, `metadata`, `extensions`. `FULL` retains all groups; `LOGGING` omits HEX. `PRIVACY` omits all raw bytes, additional records (including EDNS Client Subnet), ID, metadata and extensions. Query names and answer addresses remain visible; this is not anonymization.

Sequence readers process input incrementally, skip malformed elements by default, and expose `problems` (element indexes, not byte offsets). `strict: true` stops on the first invalid element. Error storage is capped at `max_problems: 1000`, with excess counted in `dropped_problems`.

Limits are configurable on `parse`, `from_wire`, and model construction: `max_bytes: 65_535`, `max_records: 4096`, `max_pointers: 128`, `max_json_bytes: 4_194_304`, `max_depth: 32`. Limits raise `LimitError`; reaching the record or pointer bound while decoding wire data instead returns a malformed message and preserves the original bytes. A JSON sequence has a per-element size bound.

## Development

```sh
bundle install
bundle exec rake test
COVERAGE=1 bundle exec rake test
bundle exec rbs -I sig validate
bundle exec ruby script/benchmark.rb
```

The first test run downloads checksum-pinned RFC fixtures into ignored `tmp/` directories and requires network access.

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/ydah/dns_json/issues). See [Development](#development) for the checks to run before submitting a change. Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Released under the [MIT License](LICENSE.txt).
