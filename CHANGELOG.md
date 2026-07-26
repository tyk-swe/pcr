# Changelog

All notable changes to PacketcraftR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0-beta.1] - 2026-07-26

### Added

- Published each library domain as its own crate — `packetcraftr-error`,
  `packetcraftr-capture`, `packetcraftr-session`, `packetcraftr-packet`,
  `packetcraftr-protocol`, `packetcraftr-net`, `packetcraftr-client`,
  `packetcraftr-workflow`, and `packetcraftr-output` — so consumers can compile
  only the parts they use.
- Added offline `packetcraftr protocols [PROTOCOL]` discovery with stable
  built-in capability listings, case-insensitive alias lookup, reflective field
  details, and text or aggregate JSON output.
- Added `--policy-file <PATH>` to every command carrying the shared
  traffic-policy flags — `plan`, `send`, `exchange`, `capture`, `scan`,
  `traceroute`, `dns`, and `fuzz` — reading a JSON or YAML file that states any
  of the six `TrafficPolicy` values. `replay` keeps its own narrower replay
  policy and does not take one. Precedence runs command line, then file, then
  built-in defaults. The file is read only from a path given on the command
  line — there is no ambient discovery — and an unknown key is rejected rather
  than ignored, so a misspelled gate name cannot read as "gate not requested".
- Added a `capture_write` benchmark covering capture encode, decode, and
  transcode throughput, as a baseline for changes to those paths.
- Added PCAPNG annotation fidelity: `Reader::metadata` retains section,
  interface, and packet comments with their scope, name-resolution records, and
  interface-statistics counters, bounded by
  `ReaderOptions::max_metadata_records` with anything past the bound counted
  rather than stored.
- Added a hidden `packetcraftr generate` command that emits shell completions
  for bash, elvish, fish, PowerShell, and zsh, plus one man page per command.
  Release archives now ship both, generated from the packaged binary so they
  describe the exact command surface that variant was built with.
- Added `read --output json`, an aggregate result carrying every copied frame
  with its count, so a bounded capture can be consumed as one document instead
  of a stream. An aggregate document is assembled in memory before it is
  written, so `--output ndjson` remains the streaming choice for a large
  capture. `raw` remains unsupported for `read`.
- Added `--bpf <FILTER>` to `capture` and to `decode --interface`, applying a
  libpcap-syntax filter in the capture backend so unwanted frames never reach
  this process. It is orthogonal to `--filter`, which selects among frames that
  were already captured, and the two combine. Requesting it for a capture file
  is a CLI error that names `--filter` instead.
- Added `decode --filter <EXPRESSION>` for both capture files and live
  interfaces. The filter is compiled before any input is opened, so a mistyped
  protocol or field name is a CLI error rather than a partial run, and the
  number of frames it excluded is reported in the text summary, the aggregate
  result, and the terminal stream record.
- Added `packet::filter`, a bounded display-filter engine over the reflective
  field vocabulary a registry already exposes, so it covers external codecs
  without changes. It supports protocol presence, `==`/`!=` on every scalar
  field kind, ordering on numeric fields, CIDR containment for address fields,
  `&&`/`||`/`!`, and grouping. `Filter::compile` resolves every protocol name,
  field name, operator, and literal against the registry, so a filter that
  compiles cannot fail while frames are streaming.
- Added `decode --interface <NAME_OR_INDEX>`, which dissects frames as they are
  captured from one interface under the same capture window, budgets, and
  shutdown accounting as `capture`. A live source streams, so it supports text
  and NDJSON but not the aggregate JSON result.
- Added recipe-free capture: `packetcraftr capture --interface <NAME_OR_INDEX>`
  observes one interface directly instead of requiring a packet whose only
  purpose was to select a route. Passive observation has no destination to
  authorize, so it is bound by the capture window and the packet and byte
  budgets; the recipe path keeps every destination gate unchanged.
- Added `capture --no-promiscuous` for capturing only traffic the interface
  would accept anyway. Promiscuous mode remains the default.
- Added `net::capture::Options` and `Provider::arm_capture_with`, which carry
  backend behaviour alongside the queue bounds. A provider that predates an
  option refuses it rather than capturing more traffic than requested.
- Added `net::route::Planner::observe_interface`, which describes one interface
  for passive observation through interface lookup alone — no route lookup, no
  neighbor resolution, and no transmission mode.
- Added `packetcraftr decode <PATH>`, which dissects every frame in a capture
  file instead of copying bytes like `read`. Text output prints one
  reflection-driven summary line per frame — protocol path plus the innermost
  addressed endpoints and transport ports — and `--verbose` adds an indented
  dump of every decoded layer field. JSON and NDJSON emit the decoded-frame
  contract.
- Added the `decode` command contract to `packetcraftr.output/v1`: an aggregate
  result carrying decoded frames with emitted and filtered counts, and a stream
  event pairing per-frame records with a terminal completion record. The schema
  id is unchanged; every addition is additive.
- Added `--write <PATH>` to `read`, `capture`, `send`, `exchange`, and `replay`,
  writing exact `pcap`, `pcapng`, or `raw` bytes to a file instead of standard
  output. Requesting it with a terminal-facing format is a CLI error rather than
  a partially redirected result.

### Changed

- Buffered exact byte output and capture-file reads. Capture bytes previously
  went through the line-buffered standard-output handle, which flushes once per
  `0x0a` byte in binary payloads.
- A truncated DNS answer now says what to do about it. The workflow still
  refuses to present partial records, and the reason it reports names querying
  over TCP as the way to read the complete answer.
- A capture copy that cannot carry the source's annotation now says so.
  `TranscodeReport.dropped_metadata` counts the comments, name records, and
  statistics blocks the target format could not represent, plus any the reader's
  own retention bound excluded, and `read` reports the total as a
  `capture.metadata_dropped` warning on standard error. These records were
  previously skipped without a trace.
- Restructured the repository into a Cargo workspace of per-domain crates under
  `crates/`, with a virtual root manifest owning shared dependency versions,
  lints, and the release profile. Cargo now enforces the domain layering that
  was previously convention. The `packetcraftr` crate re-exports every domain
  under its existing name, so `packetcraftr::packet::…` and the rest of the
  public API are unchanged.
- Moved the `native-*` features to `packetcraftr-net`, forwarded by
  `packetcraftr` and `packetcraftr-cli`. Feature selection now requires
  `--package`, as in `cargo build --package packetcraftr-cli --features
  native-route`.
- Made `Layer::declared_layout_fields` available in all builds rather than only
  under `cfg(test)`, so conformance tests outside the defining crate can reach
  it. It keeps its default empty implementation.
- Made `client::Stats::checked_add` a public method on the type instead of a
  workflow-private extension.
- Renamed the canonical interface-enumeration feature to
  `native-interfaces`; native route, Layer 2, and Layer 3 capabilities now
  enable it explicitly.
- Extended the pre-1.0 public output API and `packetcraftr.output/v1` command
  vocabulary with the additive `protocols` aggregate result contracts.
- Documented project purpose, intended audience, and authorization scope in the
  crate root, the contributor guide, and the transmission, replay, scan,
  traceroute, and ARP module docs.

### Removed

- Removed the unreleased `cli` feature. The command-line interface is now the
  `packetcraftr-cli` crate, so it is selected by building that package rather
  than by enabling a feature, and library-only builds simply depend on the
  library crates.
- Removed the redundant `net::exchange::Io` marker trait; generic code can use
  the public `net::transmit::Sender + net::capture::Provider` bounds directly.

## [0.4.0-beta.2] - 2026-07-24

### Added

- Added first-run documentation covering verified feature combinations,
  platform prerequisites, live-traffic safety gates, privileges, examples, and
  troubleshooting.
- Added contributor and security guidance, reproducible bug and
  native-networking issue forms, a pull-request impact and test checklist,
  area/type labeling guidance, and CODEOWNERS routing for safety-sensitive and
  serialized-contract changes.
- Added terminal-aware coloured human output with explicit `--color <WHEN>`
  control (`auto`, `always`, or `never`); structured, hexadecimal, raw, and
  capture-file outputs remain free of terminal styling.
- Added command-focused help examples and clearer output-format, input, and
  safety guidance across the CLI.
- Added exact packet construction and dissection for GRE, SCTP common headers
  with validated opaque chunks, and IGMP, plus IPv4/IPv6-in-IP encapsulation.
- Added SCTP INIT/INIT-ACK and quoted-ICMP response correlation for generic
  exchanges.
- Added a strict Linux-native E2E harness with isolated client, router, and
  server namespaces, independent IPv4/IPv6 UDP and TCP fixtures, deterministic
  teardown, and failure-time network diagnostics.
- Added deterministic native smoke coverage for IPv4/IPv6 route planning and
  Layer 3 transmission, plus successful, timed-out, and unsolicited UDP
  exchanges validated by independent socket fixtures and the output-v1 schema.
- Added an explicit CI baseline and a reusable privileged Linux native-E2E
  workflow with failure evidence.

### Changed

- Release binary archives now include `README.md` and `CHANGELOG.md` alongside
  the executable and license.
- CLI help, version, and parse diagnostics now use one hardened document
  renderer with terminal-control escaping and semantic styling.
- Route planning and live materialization now use only the outer IP envelope;
  encapsulated addresses remain independent and drive inner transport checksums.
- IP protocol numbers 2, 4, 41, 47, and 132 are now typed bindings, so strict
  builds require IGMP, nested IP, GRE, or SCTP children instead of raw payloads.
- Improved scan and traceroute workflow scaling for large probe batches while
  preserving endpoint, response-evidence, and diagnostic ordering.
- Reduced deep packet-builder allocations and repeated binding work by
  collecting materialized layers, layouts, and encoded payload lengths directly
  while codecs retain an immutable view of the source packet.

### Fixed

- Native E2E command timeouts and interruptions now terminate the complete
  privileged process group, treat zombie descendants as exited during survival
  checks, and drain remaining namespace PIDs before teardown.
- Fixed `packetcraftr.output/v1` schema validation for embedded packet fields so
  malformed field values are rejected consistently with standalone packet
  documents.
- Active exchanges now require monotonic capture ingress timing, reject stale or
  unmarked frames during correlation, bound correlation CPU work, and shut down
  capture providers exactly once even when cleanup fails or panics.
- Live routing, destination authorization, checksums, replay, and response
  matching now share strict packet semantics, including ARP targets, IPv4 source
  routes, IPv6 segment routing, transport ports, and unknown route-bearing layers.
- Workflow and replay duration, packet, and byte budgets now cover actual
  provider and callback time, cumulative replay traffic, and fail-atomic
  accounting before later side effects begin.
- Capture-file writers now stop after partial I/O failures, capture readers use
  fallible bounded allocation, and native capture queue statistics update
  transactionally.
- TCP reassembly now applies segment limits to final retained state and prevents
  older accepted segment timestamps from moving flow expiry backwards.
- Native I/O now revalidates interface name/index identity immediately before
  dispatch (subject to OS changes between validation and the send syscall),
  bounds complete macOS route queries, propagates capture-worker panics, and
  reuses namespace-aware Linux netlink workers without nesting runtimes.
- Preserved readable multiline Clap diagnostics instead of displaying escaped
  newline literals, and now propagate Clap's actual exit codes.

### Security

- Documented the verified `RUSTSEC-2024-0436` transitive dependency path and
  rejected upgrade candidates, retained the existing exception expiry, added
  an enforced 2026-09-15 remediation target, and enabled weekly Cargo
  dependency update pull requests.

## [0.4.0-beta.1] - 2026-07-17

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

[Unreleased]: https://github.com/tyk-swe/pcr/compare/v0.5.0-beta.1...HEAD
[0.5.0-beta.1]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.2...v0.5.0-beta.1
[0.4.0-beta.2]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.1...v0.4.0-beta.2
[0.4.0-beta.1]: https://github.com/tyk-swe/pcr/compare/v0.3.0...v0.4.0-beta.1
[0.3.0]: https://github.com/tyk-swe/pcr/compare/4754e3934284cff8f407ae5b4a2a21ed99ac6045...v0.3.0
[0.2.0]: https://github.com/tyk-swe/pcr/tree/4754e3934284cff8f407ae5b4a2a21ed99ac6045
