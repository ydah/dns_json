# Security

Report vulnerabilities privately at https://github.com/ydah/dns_json/security/advisories/new.

Treat captured DNS packets as untrusted. The reader bounds packet length, record count, expanded names, compression traversal, JSON nesting, and sequence buffers. It returns diagnostics for malformed packets. Input size violations raise `DNSJSON::LimitError`; malformed wire data within the limits is preserved byte for byte.

This library performs no network requests during use, DNS resolution, DNSSEC validation, or packet transmission. JSON fields can intentionally disagree. `messageOctetsHEX` takes precedence over all other wire representations. Do not authorize a packet using one representation and then transmit another.

The privacy profile excludes raw HEX, additional records (including EDNS Client Subnet), message identifiers, comments and unknown metadata. It retains query names and answer addresses and therefore is not an anonymizer. Apply your own retention and access policy.

Dependency changes must satisfy the MIT-only additional-dependency policy. The Ruby runtime and standard libraries are excepted. Consult the actual license files as well as package metadata; do not infer implementation provenance from packaging exclusions.
