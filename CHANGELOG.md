# Changelog

All notable changes to PacketcraftR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added tag-driven GitHub Releases with full and pcap-free binary archives for
  Linux x86-64, macOS x86-64 and Arm64, and Windows x86-64, plus SHA-256
  checksums for every release asset.

### Changed

- Reduced packet build and decode allocations by composing checksums across
  byte slices and preserving decoder fallback bytes without copying them.
- Clarified traceroute probe identity, timeout, rate, policy, and output-format
  behavior in CLI help.

### Fixed

- Preserved per-hop network-layer identity across multi-attempt traceroutes,
  matched quoted ICMP errors with monotonic capture timing, rejected zero
  traceroute ports, and reused live client state across hops.

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
