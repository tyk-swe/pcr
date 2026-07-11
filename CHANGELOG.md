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
- Added native Layer 2 capture and injection behind `native-layer2`: libpcap on Linux/macOS and a securely runtime-loaded, pinned Npcap ABI on Windows x86_64 MSVC. Capture sessions own their worker and handle, expose an explicit readiness barrier, enforce frame/byte queue bounds, preserve native timestamps/link types/interface metadata and complete captured bytes, report native/queue loss, and join every shutdown path.
- Added injectable and system-composed active neighbor resolution with gateway-aware IPv4 ARP and IPv6 NDP, exact VLAN/interface correlation, finite attempts and timeouts, bounded captured evidence, joined capture cleanup, and a bounded finite-lifetime cache.
- Added `native-layer3` and `SystemLayer3Io` raw IPv4/IPv6 transmission on Linux, macOS, and Windows with route-selected path binding, exact-frame validation, typed platform/privilege failures, and complete-write reporting.
- Added a stable `ClassifiedError` taxonomy for live capability, dependency, privilege, policy, timeout/runtime I/O, partial-send, and invariant failures, including CLI exit classes and remediation.
- Added policy-gated, bounded, injectable hostname resolution through `LiveTarget`, `HostnameResolver`, and opaque `ResolvedTarget` values.
- Added public typed aggregate/stream output envelopes, typed result contracts for every v0.2 command, an explicit command/format capability matrix, and command-specific JSON Schema validation with negative fixtures.
- Added passive `plan` and interface-bound `routes` CLI workflows plus policy-gated `send`, finite live `capture`, and capture-ready `exchange` workflows. They share exclusive packet inputs, explicit route/link constraints, traffic and capture budgets, typed JSON/NDJSON results, and exact hex/raw/PCAP/PCAPNG output where applicable.
- Added a 21-file authoritative fixture corpus with strict `packetcraftr.fixture-provenance/v1` sidecars, hash-first read-only tests, schema/source/license/review validation, and full pull-request/push-range enforcement for binary, capture, JSON/YAML, expected-result, and malformed fixtures.
- Published the versioned `packetcraftr.protocol-support/v1` manifest and stable documentation for all 22 built-in codecs, nine numeric capture roots, four matchers, and 14 CLI workflow obligations; extended the authoritative corpus to every root and both BSD NULL byte orders.
- Added aggregate-bounded capture writers, public PCAP/PCAPNG interface timestamp metadata, streaming metadata-preserving `read` capture output, and a policy-gated `replay` workflow with injectable timing/transmission, exact wire evidence, finite speed/rate/resource limits, and typed unsupported-root/partial-send failures.
- Added a bounded structured `dns` workflow and CLI over the shared policy and capture-ready exchange seams: IPv4/IPv6 UDP queries, independent retry-time hostname/every-answer authorization, exact tuple/transaction/question correlation, bounded compression and RDATA decoding, question-relevant record filtering, rejected-record audit evidence, terminal-safe TXT display with exact hex, and typed text/JSON/NDJSON results.
- Added deterministic bounded field-aware `fuzz`: offline-by-default reflective boundary/random/bit-flip/malformed mutation, direct case-index reproduction, finite shrink data and allocation/wire/evidence/duration limits, bounded build/dissection results, explicit live and malformed double opt-ins, complete traffic-policy preauthorization, capture-ready `Client::exchange` execution, and typed text/JSON/NDJSON evidence.
- Completed the all-command output conformance pass: typed success/error goldens for all 14 commands, closed route/plan schemas, sequenced per-item and terminal stream failures, complete-frame parity across raw/hex/NDJSON/PCAP/PCAPNG, terminal-safe text, and broken-pipe coverage for every output family.
- Extracted synchronized, unpublished core, protocol, I/O, and session implementation crates behind unchanged `packetcraftr` façade paths, with an enforced acyclic dependency graph and buildable GitHub Release workspace archives.
- Added a warning-free public Rust API guide, compile-tested portable/live extension examples, semantic `FailureCategory` recovery classes, typed capture-evidence completeness and receiver-drop counters, and a rustdoc-derived beta façade baseline enforced in CI.
- Added the reviewed v0.2 CLI contract, exact help/parse/version goldens, packet-schema negative fixtures, a shipped YAML packet example, and a digest gate covering CLI grammar, exit classes, packet/output schemas, and mapping documentation.
- Public API baseline: `sha256:319ac1647b8e40e9453178e418c40a26bfab98914df425b6e2c7dab1b8941762` (reviewed for the v0.2 beta freeze).
- CLI/schema baseline: `sha256:2f28da6eb04772bd2e9d021b71799f707d3f63e103be9af75f4d5a8f4eb2f269` (reviewed for the v0.2 beta freeze).

### Changed

- Set the v0.2 MSRV to Rust 1.96 and retained the `packetcraftr` crate and binary names.
- Reply capture now uses a bounded three-second window when no explicit timeout is supplied.
- Listener events retain complete captured bytes; display truncation is presentation metadata only.
- Coordinated exchange arms and awaits its owned capture session before sending, and shuts it down on readiness, send, capture, decode, timeout, and success paths.
- Route-selected IP sources and resolved/interface-owned MAC addresses are materialized into the exact transmitted frame while spoofed packet sources remain distinct from neighbor-resolution sources.
- Neighbor materialization now carries the complete interface-owned source/MAC, next hop, VLAN stack, MTU, and link type to rich resolvers, and retains resolution attempts, capture records, truncation state, cache state, and backend statistics with the materialized route.
- Route planning can pass an interface-owned source preference through compatible providers; legacy injected providers retain source compatibility and fail explicitly if they cannot honor the preference.
- Synthesized Ethernet envelopes are built and included in traffic-policy byte accounting before neighbor discovery; post-resolution edits must remain fixed-width.
- Route MTU enforcement now measures the actual built network-layer byte span instead of trusting permissive length fields, and rejects oversized packets before neighbor discovery or live I/O.
- Destination-free Ethernet/custom-EtherType and complete ARP packets now use explicit passive interface selection without fake IP lookups or neighbor traffic.
- Exchange passes frame-count, aggregate-byte, and snap-length limits to capture backends and retains bounded decode failures as complete raw capture records for packet evidence.
- Live backends must report a complete send and internally consistent optional wire bytes. Partial sends are typed failures, and exchange preserves both the operation and capture-shutdown errors when both occur.
- Raw Layer 3 sends reject route/destination/MTU mismatches and IPv4 values that a target kernel would rewrite. macOS converts only its private submission copy's length/fragment fields to host order while retaining the final built bytes as wire evidence.
- Exchange validates timeout and capture/retention limits before route or live side effects, and all retained evidence classes share one aggregate frame ceiling.
- Human CLI output escapes terminal and bidi controls while JSON preserves structured strings through JSON escaping.
- Aggregate JSON and streaming NDJSON are now distinct formats. Every NDJSON success or terminal-error record carries a frozen zero-based sequence, while aggregate envelopes cannot carry one; `build`, `dissect`, `read`, and `interfaces` now render exclusively from typed results.
- Live CLI policy and limit validation now precedes resolver, route, neighbor, capture, or transmission work as applicable; capture and exchange retain readiness, loss, timeout, and cleanup evidence through the shared classified-error contract.
- Exchange results retain timestamped exact sent-frame evidence; PCAPNG output preserves mixed raw-send and captured-response link types as separate interfaces, while classic PCAP rejects an unrepresentable mixed stream.
- Froze `FieldSchema::required` as an after-defaults reflective invariant enforced for built-in and external codecs at construction, materialization, and decode boundaries; capture receiver loss is no longer misclassified as queue overflow.
- Froze `packetcraftr.packet/v1` JSON/YAML mapping and CLI parser behavior: packet bytes are capped before decoding, layers are streamed under a finite ceiling, recursive field lists have an absolute ceiling, and duplicates, aliases, custom tags, and multi-document YAML are rejected before an unbounded generic tree can be built.

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
- Preserved typed native I/O causes through neighbor resolution and preserved both operation and cleanup errors without flattening either into incidental text.

### Removed

- The v0.1 flag-heavy CLI, private fixed packet pipeline, and public `run_cli` façade.
- The v0.1 rules engine, daemon, external-command actions, REPL, embedded Prometheus endpoint, and per-tool feature maze.
- Legacy DNS/scan/traceroute/fuzz implementations that bypassed the shared packet, exchange, and session APIs.
- Alpha-only provider reexports from `packetcraftr::client`; use the owning `packetcraftr::io` module or stable root reexports.

## 0.1.0

The original private, fixed-pipeline release. Historical changes predate this changelog. Critical fixes are maintained on `release/0.1` only until the v0.2 release-candidate stage.
