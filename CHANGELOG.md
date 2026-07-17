# Changelog

All notable changes to PacketcraftR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added tag-driven GitHub Releases with full and pcap-free binary archives for
  Linux x86-64, macOS x86-64 and Arm64, and Windows x86-64, plus SHA-256
  checksums for every release asset.
- Added `ReaderOptions`, `PcapOptions`, and `PcapNgOptions` for named offline
  capture resource and format configuration.

### Changed

- Reduced packet build and decode allocations by composing checksums across
  byte slices and preserving decoder fallback bytes without copying them.
- Reused passive route decisions within one exchange, stopped preparation from
  starting additional work after its deadline, and localized TCP and fragment
  reassembly updates to the affected pending ranges.
- Made packet assembly grow amortized-contiguously and patched resolved MAC
  addresses directly into built-in Ethernet frames while retaining full rebuilds
  for external codecs.
- Kept bounded TCP retransmission history in a ring buffer so long-lived streams
  no longer copy the retained history for every small in-order segment.
- Clarified traceroute probe identity, timeout, rate, policy, and output-format
  behavior in CLI help.
- Simplified offline capture construction to one default and one options path
  per format, and consolidated PCAPNG interface configuration around the full
  `Interface` description. Existing capture bytes and validation behavior are
  preserved.
- Simplified workflow extension traits to use `workflow::BoundaryError` and
  `workflow::Stats` directly. DNS remains UDP-only and output-v1 continues to
  emit the required `"transport": "udp"` field.

### Removed

- **Breaking:** Removed the forwarding `Reader::read_frame` and `Writer::write`
  methods; use `next_frame` and `write_frame` respectively.
- **Breaking:** Removed the legacy `workflow::clock::System`, `session::Limits`,
  `session::fragment::Key`, and Boolean `ResolvedTarget::address_for_family`
  names; use `SystemClock`, `ReassemblyLimits`, `DatagramKey`, and
  `address_for_version(IpVersion)`.
- **Breaking:** Removed positional offline capture constructor permutations.
  Use `Reader::with_options`, `Writer::pcap_with_options`,
  `Writer::pcapng_with_options`, and `Writer::add_interface_description`.
- **Breaking:** Removed `output::network::plan::LinkType`; route output decisions
  now expose their unchanged serialized numeric link type as `u32`.
- **Breaking:** Removed the fixed `workflow::dns::Transport` and the transport
  field from `workflow::dns::Result`; the executable workflow remains UDP-only.
- **Breaking:** Removed workflow-local authorization/execution error aliases and
  `workflow::fuzz::ExecutionStats`; use `workflow::BoundaryError` and
  `workflow::Stats`.
- **Breaking:** Removed `net::route::Id`; use `net::interface::Id`. Removed
  `net::route::{Capability, Mode, MacAddress}`; use the corresponding
  `net::link` names.
- **Breaking:** Removed the resolved-address limit constants from
  `client::target`; use `client::policy::{DEFAULT_MAX_RESOLVED_ADDRESSES,
  MAX_RESOLVED_ADDRESSES}`.

### Fixed

- Corrected the packet schema documentation to reference the canonical
  `packet::field::Value` Rust path.
- Preserved per-hop network-layer identity across multi-attempt traceroutes,
  matched quoted ICMP errors with monotonic capture timing, rejected zero
  traceroute ports, and reused live client state across hops.
- Enforced finite PCAPNG section boundaries, rejected raw IPv4/IPv6 replay when
  the capture link type disagrees with the packet version, and made protocol
  binding priority winners consistent for both decoding and packet building.

## [0.3.0] - 2026-07-14

### Changed

- **Breaking:** Reorganized the Rust library API under the canonical `capture`,
  `client`, `error`, `net`, `output`, `packet`, `protocol`, `session`, and
  `workflow` domains, replacing the broad top-level facade re-exports and the
  library-owned CLI entry point.
- Consolidated the multi-crate workspace into one Rust 2024 package while
  retaining Rust 1.96 as the minimum supported version and preserving the
  portable, default, and complete feature profiles.
- Preserved the CLI command set and versioned packet and output contracts while
  consolidating command execution, validation, error mapping, and rendering.

### Fixed

- Hardened packet construction and dissection, tunneled response matching,
  workflow evidence validation, capture deadlines, neighbor caching, and TCP
  reassembly so malformed or inconsistent inputs fail closed.
- Improved classic PCAP and PCAPNG validation, interoperability, timestamp
  handling, and failure atomicity, including compatible PCAPNG 1.2 sections.
- Prevented structured CLI parse errors from panicking on non-UTF-8 Unix
  arguments and stopped command inference at the `--` end-of-options marker.
- Tightened native route and capture feature gating, Windows adapter parsing,
  numeric interface validation, and portable interface enumeration.

## [0.2.0] - 2026-07-11

### Added

- Established the original PacketcraftR packet, capture, native networking,
  session, workflow, library, and CLI baseline.

[Unreleased]: https://github.com/tyk-swe/pcr/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/tyk-swe/pcr/compare/4754e3934284cff8f407ae5b4a2a21ed99ac6045...v0.3.0
[0.2.0]: https://github.com/tyk-swe/pcr/tree/4754e3934284cff8f407ae5b4a2a21ed99ac6045
