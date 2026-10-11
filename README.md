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

## Features

- Decode DNS wire messages, inspect diagnostics, and preserve original packet bytes.
- Build structured messages with RFC RDATA fields, output profiles, and JSON text sequences.
- Bound parsing and validation without performing DNS resolution.

## Installation

Add the gem to your Gemfile:

```ruby
gem "dns_json"
```

Then run `bundle install`.

Requires Ruby 3.3 or later and `json` 2.19.4 or later, below version 4. CI tests CRuby, JRuby, and TruffleRuby. No other gem from this format family is required.

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

`Message` and `RR` wrap a Hash; `[]` accesses any member and `to_h` returns a deep copy. Unknown extension members survive the default JSON roundtrip. All RFC members are optional. `parse(..., strict: false)` retains invalid values and provides `warnings` with JSON Pointers; serialization validates strictly. JSON input and output use ASCII, with escaped Unicode in string values. Duplicate object keys are rejected on both json 2.x and 3.x.

| Supported | Scope |
| --- | --- |
| Wire decoding | Headers, questions and RR sections; compressed names; partial/malformed packets with diagnostics and original octets |
| Wire encoding | Original bytes when `messageOctetsHEX` exists; otherwise uncompressed structured reconstruction, including rrSet expansion |
| RDATA | Every member in RFC 8427 §2.3: A, AAAA, CNAME, DNAME, NS, PTR, TXT, CDNSKEY, CDS, CSYNC, DNSKEY, HIP, IPSECKEY, KEY, MX, NSEC, NSEC3, NSEC3PARAM, OPENPGPKEY, RRSIG, SMIMEA, SPF, SRV, SSHFP, TLSA; also DS |
| Other RR types | Numeric/IANA names and opaque `RDATAHEX` |
| Pairs and streams | §3 query/response pairs and §4 RFC 7464 JSON text sequences |
| Profiles | Member groups, mandatory/prohibited members, boolean or numeric one-bit values, privacy preset |
| Not included | DNS resolution, DNSSEC verification, IDN U-label conversion, pcap, DNS Update-specific JSON, semantic validation of cryptographic key material |

## Wire reconstruction and names

`messageOctetsHEX` always wins, including for malformed packets. To construct an edited packet, obtain `to_h`, remove that member, make your changes, then create a new `Message`. Header flags default to zero; counts default to section lengths but explicitly supplied counts are retained. ID, each record's name/type/class, and answer TTL/RDATA must be provided. `NAMEHEX`/`QNAMEHEX` take precedence over display names and must contain an uncompressed whole name.

Structured `rdata*` takes precedence over `RDATAHEX` and recalculates RDLENGTH, avoiding stale compression offsets. With opaque RDATAHEX, explicit RDLENGTH is preserved. Unknown raw RDATA can contain compression offsets that cannot safely be relocated; retain the whole-message HEX for exact reproduction. Standalone `rrOctetsHEX`, header and section octets are diagnostics, not reconstruction overrides.

Names implement [verified erratum 5439](https://www.rfc-editor.org/errata/eid5439): literal dots and backslashes within labels use DNS backslash escaping before JSON encoding. Nonprintable/high octets use decimal DNS escapes. Ordinary JSON parsing therefore keeps label boundaries intact. The original RFC text's `\u002E` rule was ambiguous and is superseded by this correction. HEX remains available for exact inspection. Relative display names are accepted and emitted as absolute names; root is `.`. Pointer traversal accepts backward references only, rejects loops and limits expanded names to 255 octets.

TXT uses a single text string as specified in §2.3. Multiple wire character-strings are joined; individual boundaries remain available in the original HEX. Encoding splits text into chunks of at most 255 octets. Octets map to U+0000–U+00FF, escaped in JSON. SPF uses quoted DNS presentation strings. RDATA that cannot be decoded is retained as HEX with a diagnostic.

One-bit output defaults to numeric 0/1, matching §1.1 and the RFC examples. Boolean input is also accepted because §2.1 uses that terminology. TTL follows §2.2's signed 32-bit range. `dateSeconds` is nonnegative and emitted without an exponent. The section 5.2 example's inconsistent ANCOUNT is retained (erratum 5570 is held for update).

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

RFC text, extracted examples and notices are downloaded only into ignored `tmp/`. No RFC excerpts, fixtures or third-party implementation source are distributed in Git or the gem. `script/sources.json` pins SHA-256 checksums; fixture generation tests §5.1, §5.2 and its rrSet alternative. The malformed optional fragment examples in §5.1 are not standalone JSON documents; equivalent combinations are covered by independently authored tests. `data/*.yml` contains independently maintained property/RDATA metadata and IANA type identifier facts. Run `script/update_registry.rb` to check the pinned registry; audit a new source and update the checksum before `--write`.

Tests include all RDATA forms, a Ruby standard-library `resolv` oracle, random packets and names, truncation, pointer loops, resource bounds, and JSON validation. CI covers supported CRuby versions plus head, JRuby and TruffleRuby on Ubuntu/macOS, json 2/3, coverage, syntax checks, RBS and standard-library interoperability.

A `v*` tag runs `.github/workflows/release.yml` with the GitHub environment `release`, validates/builds the gem, publishes through RubyGems Trusted Publishing, then creates the GitHub release from CHANGELOG. Initial RubyGems publication and Trusted Publishing setup require the owner's action before tagging.

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/ydah/dns_json/issues). See [Development](#development) for the checks to run before submitting a change. Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

MIT; see [LICENSE.txt](LICENSE.txt).

Additional dependencies must offer the MIT license, including development and comparison tools. The Ruby runtime and its standard libraries are exceptions to this policy. Reference documents and registry facts are test/specification inputs, not dependency implementations. See [implementation provenance](docs/provenance.md) for the scope and limits of the source audit.
