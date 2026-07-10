# Changelog

All notable changes to PacketcraftR are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and released versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The v0.2 alpha series is intentionally breaking; compatibility is frozen only at beta.

## 0.2.0-alpha.1 - Unreleased

### Added

- Began the public, runtime-neutral packet kernel: arbitrary ordered packets, object-safe layers, reflective schemas and values, wire-value intent, layouts, diagnostics, an immutable protocol registry, generic building, and bounded dissection.
- Added raw, padding, and malformed-layer representations so unknown or invalid bytes remain visible.
- Added runtime-neutral captured-frame metadata with fallible, length-validating constructors as the basis for streaming PCAP and PCAPNG work.
- Added pure-Rust streaming classic PCAP/PCAPNG I/O, multiple PCAPNG interfaces, replay timing calculations, open numeric link types, and Ethernet/RAW/NULL/LOOP/SLL/SLL2 roots.
- Added bounded fragment and TCP reassembly stages, lazy packet-template expansion, passive route planning, gateway-aware neighbor materialization, and a high-level injectable `Client` with coordinated exchange.
- Added the breaking v0.2 `build`, `dissect`, `read`, and `interfaces` CLI workflows, versioned output envelopes, whole-frame hex/raw output, and packet-expression plus JSON/YAML inputs.
- Added built-in Ethernet, stacked VLAN, ARP, IPv4/IPv6, IPv6 extension/SRH, ICMPv4/v6, TCP, and UDP codecs with reflective fields and response matchers.
- Added repository metadata, an architecture decision record set, a platform/capability matrix, a fixture provenance policy, a migration guide, a security policy, and feature-matrix CI.
- Added typed RFC 8754 Segment Routing Header handling for IPv6 routing type 4.
- Added deterministic lifecycle coverage requiring reply capture to report readiness before the first send.
- Added an enforceable component/native-adapter architecture, platform-neutral interface/capture/L2/L3 provider seams, checked transmission-frame dispatch, and external-provider compile coverage.
- Added passive native route, interface, source-address, next-hop, and MTU providers behind `native-route`: route netlink on Linux, routing sockets plus native interface APIs on macOS, and IP Helper on Windows. Selection reasons and unsupported preferences use platform-neutral typed values/errors.

### Changed

- Set the v0.2 MSRV to Rust 1.96 and retained the `packetcraftr` crate and binary names.
- Reply capture now uses a bounded three-second window when no explicit timeout is supplied.
- Listener events retain complete captured bytes; display truncation is presentation metadata only.
- Coordinated exchange arms and awaits its owned capture session before sending, and shuts it down on readiness, send, capture, decode, timeout, and success paths.
- Route-selected IP sources and resolved/interface-owned MAC addresses are materialized into the exact transmitted frame while spoofed packet sources remain distinct from neighbor-resolution sources.
- Route planning can pass an interface-owned source preference through compatible providers; legacy injected providers retain source compatibility and fail explicitly if they cannot honor the preference.
- Synthesized Ethernet envelopes are built and included in traffic-policy byte accounting before neighbor discovery; post-resolution edits must remain fixed-width.
- Route MTU enforcement now measures the actual built network-layer byte span instead of trusting permissive length fields, and rejects oversized packets before neighbor discovery or live I/O.
- Destination-free Ethernet/custom-EtherType and complete ARP packets now use explicit passive interface selection without fake IP lookups or neighbor traffic.
- Exchange passes frame-count, aggregate-byte, and snap-length limits to capture backends and retains bounded decode failures as complete raw capture records for packet evidence.
- Live backends must report a complete send and internally consistent optional wire bytes. Partial sends are typed failures, and exchange preserves both the operation and capture-shutdown errors when both occur.

### Fixed

- Removed the receive path that could drain and discard Layer 2 frames.
- Rejected IPv6 routing type 0 and unsupported generic routing headers before transmission.
- Rejected legacy ARP, VLAN, PPPoE, and custom-EtherType combinations when the fixed builder could only relabel IP bytes.
- Fixed no-default-feature linting regressions.
- Preserved Ethernet padding and malformed layers for byte-exact rebuilds without including padding in IP lengths or transport checksums; explicit padding boundaries now reject unsupported ownership in strict mode and require live opt-in for network/datagram trailers.
- Bounded PCAPNG interface tables, metadata-only block runs, and exchange response/undecoded-byte retention; rejected checksum-failed correlations and applied traffic policy before template materialization.
- Preserved IPv4/TCP reserved bits in permissive mode and stopped initial fragments from being misdecoded as complete transport segments.
- Closed the strict-build bypass that allowed `Raw` bytes behind a discriminator registered to a typed child; unknown discriminators still preserve opaque payloads, while permissive mismatches produce diagnostics and require live opt-in.
- Required decode-only link multiplexers to admit their concrete result explicitly, so raw-IP captures continue dissection and binding through the decoded IPv4 or IPv6 layer.
- Rejected inconsistent capture-record lengths before dissection, prior fragments extending beyond a later final datagram length, and unbounded sparse TCP segment queues; TCP sequence tracking now remains bounded across the 32-bit wrap boundary.
- Retained a bounded tail of emitted TCP bytes so contradictory retransmissions remain detectable without unbounded flow memory, with the history charged to per-flow and aggregate limits.
- Added checked PCAPNG `if_tsoffset` writing so explicitly offset interfaces round-trip valid pre-Unix-epoch timestamps in either byte order.

### Removed

- The v0.1 flag-heavy CLI, private fixed packet pipeline, and public `run_cli` façade.
- The v0.1 rules engine, daemon, external-command actions, REPL, embedded Prometheus endpoint, and per-tool feature maze.
- Legacy DNS/scan/traceroute/fuzz implementations that bypassed the shared packet, exchange, and session APIs.

## 0.1.0

The original private, fixed-pipeline release. Historical changes predate this changelog. Critical fixes are maintained on `release/0.1` only until the v0.2 release-candidate stage.
