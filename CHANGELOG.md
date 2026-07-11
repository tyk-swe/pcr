# Changelog

## Unreleased

### Changed

- Reduced the repository to Rust code, tests, schemas, compact documentation,
  and one cross-platform CI workflow.

### Removed

- Removed release and qualification machinery, generated API snapshots,
  helper tooling, fixture provenance policy, duplicated package files, and
  redundant documentation.

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
