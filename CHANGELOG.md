# Changelog

All notable changes to PacketcraftR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Published each library domain as its own crate — `packetcraftr-error`,
  `packetcraftr-capture`, `packetcraftr-session`, `packetcraftr-packet`,
  `packetcraftr-protocol`, `packetcraftr-net`, `packetcraftr-client`,
  `packetcraftr-workflow`, and `packetcraftr-output` — so consumers can compile
  only the parts they use.
- Added offline `packetcraftr protocols [PROTOCOL]` discovery with stable
  built-in capability listings, case-insensitive alias lookup, reflective field
  details, and text or aggregate JSON output.
- Added a bounded display-filter language in `packet::filter`, evaluated
  against dissected packets — for example
  `ipv4.source in 10.0.0.0/8 && udp.destination_port == 53`. Paths resolve from
  reserved synthetic
  names (`frame.*`, `tcp.stream`, `udp.stream`), then registered spellings,
  then canonical `<protocol-or-alias>.<field>` names taken straight from each
  protocol's reflective schema, so every field listed by
  `packetcraftr protocols <NAME>` is filterable without further registration.
  The grammar covers boolean operators, ordered comparisons, prefix and set
  membership, `contains`, byte slices, layer-presence tests, and explicit
  occurrence selection (`ipv4#2.source`) for tunnelled stacks. There is no
  regular-expression operator. Compilation is bounded in source length,
  nesting, term count, and set size, and both the parser and the evaluator use
  explicit stacks rather than recursion. A `filter_expression` fuzz target
  covers compilation, and CI smoke-tests it alongside the existing targets.
- Added `--filter <EXPR>` and `--dissect` to `packetcraftr read`. Filtering
  keeps only the frames a display filter accepts and implies dissection;
  without either flag `read` is byte-for-byte unchanged and pays no new cost.
  `--dissect` names the layer chain in text output and carries the full
  dissected stack in NDJSON. A filtered read can also write `--output pcap` or
  `--output pcapng`, so extracting a subset of a capture into a new file no
  longer needs a separate tool; frames stream out as they match, interface
  descriptions and the frame, byte, and per-frame bounds are carried through,
  and a filter that accepts nothing still writes a readable empty capture.
  Writing classic PCAP from a PCAPNG source stays refused whether or not a
  filter is present, since classic PCAP cannot represent per-interface
  metadata. A filter that names an unknown field, or that reads a conversation
  index this command does not maintain, is rejected before any input is read.
- Registered the conventional display-filter spellings for every built-in
  protocol, so `ip.src`, `eth.dst`, `tcp.port`, `udp.dstport`, `vlan.id`,
  `arp.opcode`, and the nine `tcp.flags.*` bits work alongside the canonical
  field names. A bare flag path reads the flag, so `!tcp.flags.ack` means the
  ACK bit is clear.
- Added `registry::Registry::schema`, which publishes each registered
  protocol's reflective schema. Schemas are captured once when the registry is
  built, so field metadata no longer requires constructing a throwaway layer
  per lookup. A decode-only codec cannot produce a default layer and reports
  no schema.
- Added `registry::FilterFieldBinding` and `registry::Builder::bind_filter_field`
  so a protocol module can publish additional display-filter spellings for its
  reflective fields, including single-flag bit selections and paths that read
  either of two fields. Canonical `<protocol>.<field>` paths need no binding.
  Building the registry rejects a binding that names an unregistered protocol
  or an absent field, selects no bits, shifts every selected bit away, or
  shadows a canonical path.
- Added `--filter <EXPR>` to `packetcraftr dissect`, `capture`, and `replay`,
  completing display-filter coverage of every command that produces frames.
  `dissect` emits the dissection only when the frame matches; a frame that
  does not match emits nothing and the command still succeeds. `capture`
  keeps only received frames the filter accepts — a display filter evaluated
  after receipt, not a kernel filter, so it selects what is reported without
  narrowing what the backend captures, and rejected frames still count
  against the operation's frame and byte budgets. `replay` skips
  non-matching frames before authorization, so they are never policy-checked
  or transmitted while still counting against the frame budget, and the
  transmitted frames keep their original wire spacing across the gaps. In
  every command the filter is compiled before any input is read or any live
  work is planned, and a filter that names an unknown field or needs a
  conversation index is refused up front.
- Added the VXLAN overlay encapsulation (RFC 7348) as a fully constructible
  and dissectible built-in protocol with exact round-trip: UDP traffic on
  the registered port 4789 — in either direction — decodes into the VXLAN
  header and its inner Ethernet frame, `vxlan(vni=…)` participates in
  `build`, live workflows, and fuzzing like every other codec, and
  `vxlan.vni` filters work alongside occurrence selection
  (`ipv4#2.destination == …`) for addressing the inner stack. Deviant flag
  bits and non-zero reserved fields are diagnostics on decode and
  permissive-mode territory on build. To make port-registered
  encapsulations reachable, UDP decoding now offers both port numbers as
  child discriminators before its raw fallback; traffic away from
  registered ports decodes exactly as before. The tunnel boundary is
  honoured end to end: dissection restarts the network envelope at the
  inner Ethernet frame, so minimum-frame padding inside the tunnel reads
  as link padding rather than malformed trailing bytes; route planning and
  link materialization take link intent, MAC addresses, and VLAN tags only
  from the outer stack, so a Layer 3 send of a VXLAN packet no longer
  trips over its own tunneled Ethernet frame; and a strict build requires
  the registered port on one UDP endpoint when the datagram carries an
  encapsulation — and, conversely, refuses an opaque raw payload sitting
  on a registered port — because either way the bytes would not dissect
  back into the same layers (permissive builds keep a
  `build.udp_encapsulation_port` warning instead).
- Added the GENEVE overlay encapsulation (RFC 8926) with the same
  end-to-end tunnel-boundary treatment as VXLAN. UDP traffic on port 6081
  decodes the header, and the `protocol_type` EtherType selects the inner
  frame: Transparent Ethernet Bridging (0x6558), IPv4, or IPv6, with
  `protocol_type` resolving automatically from the child on build.
  Variable option TLVs are carried verbatim for exact round-trip; a chain
  that does not parse exactly, a C bit that disagrees with the options
  present, and non-zero reserved bits are decode diagnostics and
  permissive-mode territory on build. Only version 0 is dissected —
  other versions are preserved as malformed bytes rather than guessed at.
- Added the IPsec headers: ESP (RFC 4303, IP protocol 50) and AH
  (RFC 4302, protocol 51), reachable from IPv4, IPv6, and every
  extension header in both address families. ESP decodes its SPI and
  sequence number and deliberately keeps everything after them opaque —
  ciphertext that happens to imitate an inner packet is never dissected.
  AH authenticates rather than encrypts, so the protocol chain continues
  through it: its ICV is sized by the length field, `next_header`
  resolves from the child on build, and both headers round-trip exactly.
- Added PPPoE (RFC 2516) and the PPP protocol field it carries. Session
  frames on EtherType 0x8864 decode the six-byte header and then the PPP
  protocol number, which selects IPv4 or IPv6 and keeps LCP, IPCP, and
  other control frames as typed opaque payloads that round-trip exactly;
  discovery frames on 0x8863 preserve their tag list verbatim. The stage
  code and the payload must agree on a strict build, `session_id` and
  `code` filter under their canonical names, and an Auto EtherType
  resolves to the session stage.
- Added MPLS label stacks (RFC 3032) on EtherTypes 0x8847 and 0x8848 from
  every link parent, including VLAN-tagged frames. Entries chain until
  the S bit; the bottom-of-stack payload has no protocol field, so the
  dissector sniffs its leading version nibble for IPv4 or IPv6 and keeps
  anything else — pseudowire control words included — as opaque bytes
  that still rebuild exactly. A strict build requires the S bit to agree
  with what actually follows the entry, and `mpls.exp` and `mpls.bottom`
  filter the traffic-class and S bits under their conventional names.
- Added `packetcraftr follow <PATH> --stream <tcp|udp>:<INDEX>`, extracting
  one conversation's payload from a capture file entirely offline. The index
  is the same first-seen conversation numbering `stats` reports and stream
  filters match, so the conversation one command names is the conversation
  another extracts. TCP payload is delivered through bounded reassembly in
  stream order per direction — with bytes stranded behind missing segments
  reported rather than silently dropped — and UDP emits one chunk per
  datagram. `--direction` narrows output to the client (the conversation's
  first captured sender) or the server, `text` and `hex` interleave both
  directions with markers in delivery order, `raw` emits one direction's
  exact bytes for piping and rejects `--direction both` as
  indistinguishable, and aggregate JSON carries the chunks with endpoints
  and per-direction totals under a contract published in the v1 schema and
  examples. Extraction stays exactly-once across connection lifecycle
  seams — closing-segment retransmissions, four-tuple reuse with or
  without the same initial sequence number, and resets, whose diagnostic
  payload is never emitted as stream data. IP-fragmented datagrams carry
  no conversation index and are not followed.
- Added `workflow::analysis::follow`, the engine behind the CLI command: a
  `FollowCollector` selecting one conversation from the shared analysis
  pipeline and yielding its payload `Chunk`s in delivery order with a
  per-direction `FollowSummary`.
- Added `packetcraftr expert <PATH>`, reporting cross-frame protocol health
  findings over a capture file entirely offline. Retransmissions — including
  retransmissions whose bytes conflict with the data first seen — come from
  the bounded TCP reassembler, so they are byte-exact rather than heuristic;
  retransmissions of data a mid-stream capture never observed are not
  claimed, and a segment repeating a cleanly closed conversation's delivered
  bytes is still reported after the reassembler has let the flow go.
  Duplicate acknowledgments — reported only while they leave peer data
  outstanding — zero windows and their probes, filled and exceeded receive
  windows, keep-alives, resets,
  and uncaptured earlier segments, including gaps a bare FIN carries, come
  from cross-frame header tracking, with per-flow state restarting when a
  new SYN reuses a four-tuple. Window fullness honours the handshake's
  negotiated window scale and is reported only when both SYNs were captured,
  since the scale is unknowable otherwise. Per-frame dissection diagnostics
  such as checksum mismatches surface as findings under their own codes.
  Data still buffered behind a missing segment when the capture ends is
  reported against the final frame; a conversation that is merely still open
  then — the normal state of any live conversation — is not a finding. Each
  finding carries its severity, code, frame number, and conversation index,
  and the summary tallies findings by severity and code. `--filter` narrows
  the frames analysed while frame and stream numbering stay capture-global,
  and stream-aware filters such as `tcp.stream == 7` are supported. Text,
  aggregate JSON, and streaming NDJSON output are supported, with the JSON
  contracts published in the v1 schema and examples.
- Added `workflow::analysis::expert`, the engine behind the CLI command: an
  `ExpertCollector` observing the shared analysis pipeline's per-frame
  records and TCP reassembly events, producing `Finding` values and an
  `ExpertSummary` with per-severity and per-code tallies.
- Added `packetcraftr stats <PATH>`, computing aggregate statistics over a
  capture file entirely offline: `--table conversations` (per-conversation
  frames, bytes, and duration split by direction, keyed by the same stream
  indices display filters use), `endpoints` (per-address transmit and
  receive tallies), `protocols` (per-protocol frame counts, shares, and
  bytes), `ports` (per-transport-port tallies), and `io` (a time series
  bucketed by `--interval-ms`). `--filter` narrows every table, and because
  stats assigns conversation indices, stream-aware filters such as
  `tcp.stream == 7` work here. Text and aggregate JSON output are supported,
  with the JSON contract published in the v1 schema and examples.
- Added the bounded offline analysis pipeline in `workflow::analysis`: a
  shared read → dissect → index → filter → dispatch loop over capture files,
  with first-seen conversation indexing (`StreamIndex`, `CanonicalFlow`) and
  adapters (`tcp_segment`, `udp_flow`, `ip_fragment`) that map decoded layers
  onto the session crate's reassembly inputs, making bounded TCP stream and
  IP fragment reassembly reachable for the first time. Conversation indices
  are assigned over the whole capture before any display filter runs, so an
  index one run reports is the index another run extracts, while reassembly
  consumes only the frames the filter keeps. `tcp.stream` and `udp.stream`
  filters evaluate against separate per-transport slots, so a UDP
  conversation index can never satisfy a `tcp.stream` comparison on an
  encapsulated frame that belongs to both. Every run is bounded in frames,
  bytes, per-frame size, conversations, and duration, and reassembly expiry
  follows the capture's own clock rather than the wall clock. A segment a
  flow's bounded reassembly window cannot absorb — sparse and filtered
  captures routinely jump further than it — evicts that flow's state,
  surfacing whatever it still buffered, and re-anchors a fresh generation
  rather than failing the run.
- Exposed `session::tcp::Reassembler::limits` and `flow_count`, matching the
  accessors the fragment reassembler already had.
- Added `session::tcp::Reassembler::evict_flow`, `flow_base_sequence`,
  `flow_next_sequence`, and `flow_observed_payload`, so a caller that knows
  a connection is over can retire its state immediately and tell a
  retransmitted handshake from four-tuple reuse. The analysis pipeline uses
  them to evict stale directions when a SYN starts a new connection over a
  reused four-tuple — judged by base continuity and by whether a SYN-ACK's
  acknowledgment falls inside the reverse direction's tracked range — so the
  new generation's segments are never measured against the finished
  connection's sequence base, while simultaneous opens, retransmitted
  handshakes, and Fast Open SYNs keep their state.
- Added `workflow::replay::run_with_selector` and the `replay::Selector` seam,
  which decides per frame whether replay proceeds, after the stream budgets
  and before any authorization, delay, or transmission work. A skipped frame
  still consumes frame budget — selection can never extend how much input one
  operation reads — but is never authorized or transmitted, contributes no
  bytes, and leaves the timing reference untouched, so the frames actually
  transmitted keep their original wire spacing. A selector failure stops the
  operation as the new `replay::Error::Selection` variant.

### Changed

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

[Unreleased]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.2...HEAD
[0.4.0-beta.2]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.1...v0.4.0-beta.2
[0.4.0-beta.1]: https://github.com/tyk-swe/pcr/compare/v0.3.0...v0.4.0-beta.1
[0.3.0]: https://github.com/tyk-swe/pcr/compare/4754e3934284cff8f407ae5b4a2a21ed99ac6045...v0.3.0
[0.2.0]: https://github.com/tyk-swe/pcr/tree/4754e3934284cff8f407ae5b4a2a21ed99ac6045
