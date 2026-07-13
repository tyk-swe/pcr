# Changelog

## Unreleased

### Changed

- Simplified neighbor-response parsing and capture evidence retention, released
  capture queue locks before notifying waiters, and marked builder-style return
  values as must-use.
- Refreshed direct and locked dependencies, moved the development toolchain to
  Rust 1.97 while retaining an explicit Rust 1.96 minimum-version check, and
  updated pinned CI actions and tools.
- Made nightly fuzz corpus caching persist new inputs across runs and aligned
  the development documentation with the checks CI actually runs.
- Reduced the repository to Rust code, tests, schemas, compact documentation,
  and one cross-platform CI workflow.
- Consolidated the library and binary into one `packetcraftr` Cargo package,
  removing the four internal packages.
- Redesigned the Rust API around the canonical `packet`, `protocol`, `capture`,
  `net`, `session`, `client`, `workflow`, `output`, and `error` namespaces. This
  is an intentional breaking Rust API change.
- Split packet capture, live networking, client, workflow, and output code by
  responsibility and enforced the domain dependency direction in tests.
- Kept CLI commands, flags, exit-code behavior, feature behavior, schemas,
  serialized output, packet bytes, and runtime ordering unchanged.

### Removed

- Removed release and qualification machinery, generated API snapshots,
  helper tooling, fixture provenance policy, duplicated package files, and
  redundant documentation.
- Removed the internal package facades, flat root exports, legacy `core`,
  `protocols`, `io`, and `tools` module paths, and the library-owned CLI entry
  point.

## 0.2.0 - 2026-07-11

- Added the packet model, protocol registry, builder, dissector, and versioned
  packet/output documents.
- Added Ethernet, VLAN, ARP, IPv4, IPv6 extensions, ICMP, TCP, UDP, raw,
  padding, malformed, and common capture-link codecs.
- Added bounded PCAP/PCAPNG I/O, replay, route and neighbor planning, native
  Layer 2/3 providers, and injectable provider traits.
- Added the `build`, `dissect`, `plan`, `send`, `exchange`, `capture`, `read`,
  `replay`, `scan`, `traceroute`, `dns`, `fuzz`, `interfaces`, and `routes`
  commands.
- Added typed errors, finite resource limits, traffic policy, deterministic
  fuzzing, and bounded fragment/TCP reassembly.

## 0.1.0

- Initial implementation.
