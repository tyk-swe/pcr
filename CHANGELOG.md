# Changelog

All notable changes to PacketcraftR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `packetcraftr capture --capture-filter <BPF>` to install native
  libpcap/Npcap BPF before frames enter PacketcraftR's queue or operation
  budgets, independently of the existing post-capture `--filter` display
  language. Native compilation uses the selected interface's IPv4 netmask and
  accepts the stable resolver-free BPF core with numeric operands to prevent
  hidden name resolution.

### Changed

- Adopted cargo-nextest 0.9.140 for repository unit and integration tests and
  mold for Linux linking across local development, CI, fuzzing, native E2E,
  coverage, and release builds. Doctests continue to use Cargo's standard test
  runner.
- Removed unread build-context metadata and unused output enum string helpers,
  replaced the capture/send composite wrapper with tuple composition, and
  collapsed duplicated command-output and DNS text formatting paths. This is a
  breaking Rust API cleanup; emitted command documents are unchanged.
- Removed repository-unused public scaffolding, including the secondary error
  category taxonomy, impossible capture-frame validation, packet normalization
  and layout-reflection hooks, offline fragment reporting and unused analysis
  summaries/index accessors, reassembly limit getters, and duplicate output
  result models. This is a breaking Rust API and output-schema simplification;
  emitted command documents are unchanged.
- Replaced replay's separate wire-route parser with the canonical built-in
  dissector and shared fail-closed packet routing semantics.
- Registered a bounded DNS-over-UDP dissector that publishes read-only header
  and question fields, retains the complete payload for exact round trips, and
  selects typed DNS on UDP port 53 while preserving raw custom-port payloads.
- Removed the unused aggregate protocol-support manifest, workflow matrix, and
  fallback metadata. Consumers should use `support::BUILTIN_PROTOCOLS` and
  `support::BUILTIN_CAPTURE_ROOTS`, the tables used by the runtime registry and
  protocol-discovery command.
- Removed unused `Composite` and `Dispatch` provider-introspection methods;
  construction and their `PacketIo`/capture delegation remain unchanged.
- Unified the scan, traceroute, DNS, and fuzz `ClientExecutor` re-exports around
  one shared carrier while retaining their domain-specific executor traits.

### Fixed

- Tightened output validation to reject malformed IP addresses and DNS records
  containing fields from a different record type. IP-address rejection requires
  JSON Schema `format` assertions, which the bundled validators now enable.
- Rejected live packets whose final Ethernet/VLAN bytes, malformed routing
  layers, custom registries, or non-atomic IP fragments could conceal an
  unauthorized destination; checks run on exact preliminary and rebuilt bytes
  before neighbor discovery, capture, or transmission.
- Made deadline arithmetic fail closed on duration overflow, refreshed active
  TCP generations monotonically, accepted valid nonzero PCAPNG padding, and
  made capture-writer flush failures retryable.
- Registered GRE Transparent Ethernet Bridging and the complete built-in
  EtherType child set, rejected native route sources absent from their selected
  interface, and capped route MTUs to the route/interface minimum.
- Validated fuzz recipes and live-capture PCAPNG settings before input or live
  side effects, and preserved deadline-held unsolicited evidence while
  assigning each response frame to one deterministic request.
- Rejected reverse-flow correlation that only reversed an encapsulated probe's
  inner transport tuple, so injected or captured inner-tuple replies can no
  longer be treated as valid responses for tunneled probes; a direct reply must
  also reverse the transmitted outer envelope.
- Accepted synthesized Ethernet envelopes when validating sent DNS probes and
  rejected encoding dissected DNS layers whose public fields diverge from their
  retained wire payload.
- Bounded cumulative PCAPNG metadata bytes before block-body reads, with a new
  `ReaderOptions::max_metadata_bytes_per_frame` ceiling and resource-limit
  classification for capture size, interface, and metadata limits.
- Hardened fragment and TCP reassembly against malformed wire alignment,
  regressing timestamps, phantom empty generations, infallible scratch
  allocations, and incorrect accounting of complete single-fragment datagrams.
- Fixed offline analysis clock overflow, out-of-order I/O bucket origins,
  multi-century bucket offsets, and stale simultaneous-open state after TCP
  closure or eviction.
- Made packet-buffer allocation failures typed, rejected unsupported expression
  escapes, preserved negative `frame.time_epoch` values, accepted valid IPv6
  SRH TLVs/padding, and tightened bare-RST response correlation.
- Fixed native capture queue draining and bounded shutdown, Npcap activation
  warnings, finite Linux netlink operations and shutdown, and NDP responses
  carried after supported IPv6 extension headers.
- Re-authorized every materialized packet destination, classified IPv4-mapped
  IPv6 addresses by their mapped address, and preserved unmatched or
  freshness-less ambient exchange evidence.
- Prevented one unsolicited frame from satisfying multiple probes, preserved
  executor failures and committed replay evidence across deadline boundaries,
  varied UDP scan retry identities, rejected duplicate fuzz strategies, and
  shared fuzz preparation/evidence aggregate byte accounting.
- Required successful CI for the exact release tag commit, synchronized fuzz
  Clippy policy with the workspace, and moved the Rust 1.97 pin to 1.97.1.
- Fixed `replay --interface <INDEX>` treating a numeric selector as both an
  interface index and a literal interface name, which prevented ordinary
  numeric interface selection from resolving.
- Fixed filtered replay NDJSON records reusing source-capture positions as
  stream-envelope sequences, which could make evidence and completion records
  duplicate or nonmonotonic. Stream sequences are now contiguous while each
  replay result continues to report its independent `source_sequence`.
- Rejected non-contiguous macOS interface netmasks instead of deriving
  misleading route prefixes from them.

## [0.4.0] - 2026-07-29

### Added

- Published each library domain as its own crate — `packetcraftr-error`,
  `packetcraftr-budget`, `packetcraftr-capture`, `packetcraftr-session`,
  `packetcraftr-packet`, `packetcraftr-protocol`, `packetcraftr-net`,
  `packetcraftr-client`, `packetcraftr-analysis`, `packetcraftr-workflow`, and
  `packetcraftr-output` — so consumers compile only what they use.
  `packetcraftr-budget` holds the cooperative `Deadline` accounting that bounds
  every offline and live operation; its `std`-only dependency makes it a
  bottom-layer peer of `packetcraftr-error`, letting both halves bound
  themselves without depending on each other.
- Added offline `packetcraftr protocols [PROTOCOL]` discovery with stable
  built-in capability listings, case-insensitive alias lookup, reflective field
  details, and text or aggregate JSON output.
- Added a bounded display-filter language in `packet::filter`, evaluated
  against dissected packets (for example,
  `ipv4.source in 10.0.0.0/8 && udp.destination_port == 53`). Paths resolve in
  order from reserved synthetic names (`frame.*`, `tcp.stream`, `udp.stream`),
  registered spellings, then canonical `<protocol-or-alias>.<field>` names from
  each protocol's reflective schema, making every field shown by
  `packetcraftr protocols <NAME>` filterable without registration. The grammar
  covers boolean operators, ordered comparisons, prefix and set membership,
  `contains`, byte slices, layer-presence tests, and explicit occurrence
  selection (`ipv4#2.source`) for tunnelled stacks, but no regular expressions.
  Compilation bounds source length, nesting, terms, and set size; parser and
  evaluator use explicit stacks, not recursion. The `filter_expression` fuzz
  target covers compilation and is CI smoke-tested with the existing targets.
- Added `--filter <EXPR>` and `--dissect` to `packetcraftr read`. Filtering
  retains accepted frames and implies dissection; without either flag, `read`
  remains byte-for-byte unchanged with no new cost. `--dissect` names the layer
  chain in text and includes the full dissected stack in NDJSON. Filtered reads
  can stream matching frames to `--output pcap` or `--output pcapng`, extracting
  a capture subset without another tool while carrying interface descriptions
  and frame, byte, and per-frame bounds; no matches still produce a readable
  empty capture. Writing classic PCAP from a PCAPNG source remains refused with
  or without a filter because classic PCAP cannot represent per-interface
  metadata. Unknown fields and conversation indices that `read` does not
  maintain are rejected before input is read.
- Registered the conventional display-filter spellings for every built-in
  protocol: `ip.src`, `eth.dst`, `tcp.port`, `udp.dstport`, `vlan.id`,
  `arp.opcode`, and all nine `tcp.flags.*` bits work alongside canonical names.
  Bare flag paths read the flag, so `!tcp.flags.ack` means the ACK bit is clear.
- Added `registry::Registry::schema`, which publishes each registered
  protocol's reflective schema. Schemas are captured once at registry build
  instead of constructing a throwaway layer per lookup; a decode-only codec
  cannot produce a default layer and reports no schema.
- Added `registry::FilterFieldBinding` and `registry::Builder::bind_filter_field`
  so protocol modules can publish extra display-filter spellings for reflective
  fields, including single-flag bit selections and paths reading either of two
  fields; canonical `<protocol>.<field>` paths need no binding. Registry
  construction rejects bindings naming an unregistered protocol or absent
  field, selecting no bits, shifting every selected bit away, or shadowing a
  canonical path.
- Added `--filter <EXPR>` to `packetcraftr dissect`, `capture`, and `replay`,
  completing coverage of every frame-producing command. `dissect` emits only
  matching frames; no match emits nothing but still succeeds. `capture`
  filters after receipt, not in the kernel, selecting reported frames without
  narrowing backend capture; rejected frames still consume operation frame and
  byte budgets. `replay` skips non-matches before authorization, so they are
  neither policy-checked nor transmitted but still consume frame budget;
  transmitted frames retain their original wire spacing across gaps. Each
  command compiles its filter before reading input or planning live work and
  refuses unknown fields or required conversation indices up front.
- Added the VXLAN overlay encapsulation (RFC 7348) as a fully constructible
  and dissectible exact-round-trip built-in. Registered UDP port 4789 in either
  direction decodes the header and inner Ethernet frame; `vxlan(vni=…)`
  participates in `build`, live workflows, and fuzzing like other codecs, while
  `vxlan.vni` filters and occurrence selection
  (`ipv4#2.destination == …`) address the inner stack. Deviant flag bits and
  non-zero reserved fields are decode diagnostics and permissive-build
  territory. UDP exposes both port numbers as child discriminators before raw
  fallback, making registered encapsulations reachable; traffic away from
  registered ports decodes unchanged. At the tunnel boundary, dissection
  restarts the network envelope at inner Ethernet so minimum-frame padding is
  link padding, not malformed trailing bytes; route planning and link
  materialization use only outer link intent, MAC addresses, and VLAN tags,
  preventing a Layer 3 VXLAN send from tripping over inner Ethernet. For exact
  layer round-trip, a strict build requires a registered port on one endpoint
  for encapsulated UDP and rejects opaque raw payloads on registered ports;
  permissive builds emit `build.udp_encapsulation_port` instead.
- Added the GENEVE overlay encapsulation (RFC 8926) with the same
  end-to-end tunnel treatment as VXLAN. UDP port 6081 decodes its header;
  the `protocol_type` EtherType selects the inner Transparent Ethernet Bridging
  (0x6558), IPv4, or IPv6 frame and resolves automatically from the child on
  build. Variable option TLVs are preserved verbatim for exact round-trip.
  Inexact option chains, a C bit that disagrees with present options, and
  non-zero reserved bits are decode diagnostics and permissive-build territory.
  Only version 0 is dissected; other versions remain malformed bytes rather
  than being guessed.
- Added IEEE 802.2 LLC and SNAP as constructible, dissectible layers
  with exact round-trip. LLC reads its one- or two-byte control format from the
  wire, chains SNAP on the 0xAA SAP pair, and preserves unregistered SAP
  payloads as typed raw bytes. SNAP's zero-OUI space uses plain EtherTypes, so
  `llc/snap/ipv4` builds and dissects like Ethernet II, while vendor OUIs retain
  their own protocol numbering. An Auto link `ether_type` above LLC resolves
  to the encoded 802.3 payload length; minimum-frame bytes beyond it are link
  padding, as with IP.
- Added the L2TPv3 session header over IP (RFC 3931, protocol 115),
  reachable from both address families. Its 32-bit session identifier (zero
  addresses the control connection) dissects and filters as
  `l2tpv3.session_id`; everything after it remains opaque because the
  negotiated cookie has no on-wire length, making tunneled-frame recovery
  guesswork; strict builds likewise reject typed children. L2TP over UDP port
  1701 is deliberately unbound because it mixes v2 and v3 control and data,
  which one interpretation would mis-dissect.
- Added ERSPAN mirrored-frame headers: Type II on GRE protocol type
  0x88BE and Type III on 0x22EB, both ending in mirrored Ethernet with VXLAN's
  tunnel-boundary treatment. The version and enclosing GRE type must agree;
  dissection flags disagreement and strict builds reject it. Type III's
  timestamp, security group tag, and flag word round-trip exactly.
- Added the IPsec headers: ESP (RFC 4303, IP protocol 50) and AH
  (RFC 4302, protocol 51), reachable from IPv4, IPv6, and every extension
  header in both families. ESP decodes SPI and sequence number but leaves all
  ciphertext opaque, never dissecting bytes that imitate an inner packet. AH
  continues the protocol chain because it authenticates rather than encrypts;
  its length field sizes the ICV, `next_header` resolves from the build child,
  and both headers round-trip exactly.
- Added PPPoE (RFC 2516) and the PPP protocol field it carries. Session
  frames on EtherType 0x8864 decode the six-byte header and PPP protocol
  number, selecting IPv4 or IPv6 while keeping LCP, IPCP, and other control
  frames as exact-round-trip typed opaque payloads. Discovery frames on 0x8863
  preserve their tag list verbatim. Strict builds require stage code and
  payload to agree; `session_id` and `code` filter under canonical names, and
  an Auto EtherType resolves to the session stage.
- Added MPLS label stacks (RFC 3032) on EtherTypes 0x8847 and 0x8848 from
  every link parent, including VLAN-tagged frames. Entries chain until the S
  bit. Because the bottom payload has no protocol field, the dissector sniffs
  its leading version nibble for IPv4 or IPv6; everything else, including
  pseudowire control words, remains exact-round-trip opaque bytes. Strict builds
  require S to match what follows; `mpls.exp` and `mpls.bottom` conventionally
  name the traffic-class and S bits.
- Added `packetcraftr follow <PATH> --stream <tcp|udp>:<INDEX>`, extracting
  one conversation's payload from a capture file entirely offline. Its index is
  the first-seen numbering reported by `stats` and matched by stream filters,
  so commands name the same conversation. Bounded TCP reassembly delivers
  stream-ordered payload per direction and reports, rather than silently drops,
  bytes stranded behind missing segments; UDP emits one chunk per datagram.
  `--direction` selects the client (first captured sender) or server; `text` and
  `hex` interleave both marked directions in delivery order; `raw` emits one
  direction's exact bytes for piping and rejects
  `--direction both` as indistinguishable. Aggregate JSON includes chunks,
  endpoints, and per-direction totals under the published v1 schema and
  examples. Extraction remains exactly once across closing-segment
  retransmissions, resets (whose diagnostic payload is never stream data), and
  four-tuple reuse with or without the same initial sequence number.
  IP-fragmented datagrams have no conversation index and cannot be followed.
  The CLI's `workflow::analysis::follow` engine supplies a `FollowCollector`
  that selects one shared-pipeline conversation and yields payload `Chunk`s in
  delivery order with a per-direction `FollowSummary`.
- Added `packetcraftr expert <PATH>`, reporting cross-frame protocol health
  findings over a capture file entirely offline. The bounded TCP reassembler
  reports byte-exact rather than heuristic retransmissions, including bytes
  conflicting with first-seen data; it does not claim unseen data in mid-stream
  captures, but still reports a segment repeating delivered bytes after a
  cleanly closed flow has been released.
  Cross-frame header tracking reports duplicate ACKs only while peer data is
  outstanding, zero windows and their probes, filled and exceeded receive
  windows, keep-alives, resets, and uncaptured earlier segments (including gaps
  carried by a bare FIN); a new SYN reusing a four-tuple restarts per-flow
  state.
  Window fullness uses negotiated scaling and requires both captured SYNs
  because the scale is otherwise unknowable. Per-frame dissection diagnostics,
  such as checksum mismatches, become findings under distinct codes. Data left
  behind a missing segment at capture end is reported on the final frame;
  merely remaining open, normal for a live conversation, is not a finding.
  Each finding includes severity, code, frame number, and conversation index;
  summaries tally severity and code. `--filter` narrows analysed frames while
  frame and stream numbering remain capture-global and supports stream-aware
  expressions such as `tcp.stream == 7`. Text, aggregate JSON, and streaming
  NDJSON are supported, with JSON contracts published in the v1 schema and
  examples. The CLI's `workflow::analysis::expert` engine uses an
  `ExpertCollector` to observe shared pipeline per-frame records and TCP
  reassembly events, producing `Finding` values and an `ExpertSummary` with
  per-severity and per-code tallies.
- Added `packetcraftr stats <PATH>`, computing aggregate statistics over a
  capture file entirely offline: `--table conversations` gives
  per-conversation frames, bytes, and duration split by direction, keyed by
  display filters' stream indices; `endpoints`, per-address transmit/receive
  tallies; `protocols`, per-protocol frame counts, shares, and bytes; `ports`,
  per-transport-port tallies; and `io`, a `--interval-ms`-bucketed time series.
  `--filter` narrows every table, and stats-assigned indices enable stream-aware
  expressions such as `tcp.stream == 7`. Text and aggregate JSON are supported,
  with the JSON contract published in the v1 schema and examples.
- Added the bounded offline analysis pipeline in `workflow::analysis`: a
  shared capture-file read → dissect → index → filter → dispatch loop.
  First-seen indexing (`StreamIndex`, `CanonicalFlow`) and adapters
  (`tcp_segment`, `udp_flow`, `ip_fragment`) map decoded layers to the session
  crate's reassembly inputs, exposing bounded TCP-stream and IP-fragment
  reassembly for the first time. Indices are assigned capture-wide before
  filtering, so runs report and extract the same conversation, while reassembly
  sees only retained frames. `tcp.stream` and `udp.stream` evaluate against
  separate per-transport slots, preventing a UDP index from satisfying
  `tcp.stream` on an encapsulated frame belonging to both. Runs are bounded by
  frames, bytes, per-frame size, conversations, and duration; expiry follows
  capture time, not wall time. A segment beyond a flow's bounded window, common
  in sparse or filtered captures, evicts its state, surfaces buffered data, and
  re-anchors a new generation instead of failing the run.
- Exposed `session::tcp::Reassembler::limits` and `flow_count`, matching the
  fragment reassembler accessors, and added
  `session::tcp::Reassembler::evict_flow`, `flow_base_sequence`,
  `flow_next_sequence`, and `flow_observed_payload`. Callers can immediately
  retire known-finished connections and distinguish retransmitted handshakes
  from four-tuple reuse. The analysis pipeline uses them to evict stale
  directions when a SYN begins a connection on a reused four-tuple, judging
  base continuity and whether a SYN-ACK acknowledgment lies in the reverse
  direction's tracked range. The new generation's segments are therefore never
  measured from a finished connection's sequence base, while simultaneous
  opens, retransmitted handshakes, and Fast Open SYNs retain state.
- Added `workflow::replay::run_with_selector` and the `replay::Selector` seam,
  deciding per frame after stream budgets but before authorization, delay, or
  transmission. Skips still consume frame budget, so selection cannot extend
  an operation's input read, but are never authorized or transmitted,
  contribute no bytes, and leave the timing reference untouched; transmitted
  frames retain original wire spacing. Selector failure stops the operation as
  the new `replay::Error::Selection` variant.

### Changed

- **Breaking:** offline capture analysis moved out of `packetcraftr-workflow`
  into its own `packetcraftr-analysis` crate, re-exported as
  `packetcraftr::analysis`. Replace `packetcraftr::workflow::analysis` with
  `packetcraftr::analysis`; items are otherwise unchanged. This makes the
  offline/live split a dependency edge rather than a convention:
  `packetcraftr-analysis` depends on neither `packetcraftr-client` nor
  `packetcraftr-net`, so any resolver, route, capture, or transmission seam
  would first require a visible dependency.
- **Breaking:** `BoundaryError` moved from `packetcraftr-workflow` to
  `packetcraftr-error`, alongside the classified error vocabulary and in the
  only crate both offline and live halves need for seam reporting.
  `packetcraftr::workflow::BoundaryError` remains a re-export;
  `packetcraftr::error::BoundaryError` is canonical. Its `from_error`,
  `with_source`, `internal_execution`, and `execution_validation` constructors
  are now public.
- **Breaking:** an Ethernet or VLAN `ether_type` at or below 1500 now
  dissects as an IEEE 802.3 payload length framing an LLC header, with bytes
  beyond the declared length treated as link padding; previously such frames
  fell through to raw payload with an unknown-binding warning. Values
  1501-1535 remain undefined and raw; Linux cooked-capture headers are
  unchanged.
- Restructured the repository into a Cargo workspace of per-domain crates under
  `crates/`; a virtual root manifest owns shared dependency versions, lints,
  and the release profile, and Cargo enforces the former conventional layering.
  `packetcraftr` re-exports every domain under its existing name, preserving
  `packetcraftr::packet::…` and the rest of the public API.
- Moved the `native-*` features to `packetcraftr-net`, forwarded by
  `packetcraftr` and `packetcraftr-cli`. Feature selection now needs
  `--package`, for example `cargo build --package packetcraftr-cli --features
  native-route`.
- Made `Layer::declared_layout_fields` available in all builds rather than only
  under `cfg(test)`, allowing conformance tests outside the defining crate to
  reach it; its default implementation remains empty.
- Made `client::Stats::checked_add` a public method on the type instead of a
  workflow-private extension.
- Renamed the canonical interface-enumeration feature to
  `native-interfaces`, now explicitly enabled by native route, Layer 2, and
  Layer 3 capabilities.
- Extended the pre-1.0 public output API and `packetcraftr.output/v1` command
  vocabulary with the additive `protocols` aggregate result contracts.
- Documented project purpose, intended audience, and authorization scope in the
  crate root, contributor guide, and transmission, replay, scan, traceroute,
  and ARP module docs.

### Removed

- Removed the unreleased `cli` feature. The command-line interface is now the
  `packetcraftr-cli` crate, selected by building that package rather than
  enabling a feature; library-only builds depend directly on library crates.
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

- Empty PPPoE session frames now continue into PPP dissection so the missing
  protocol header is diagnosed, and capture statistics retain true timestamp
  minima for out-of-order frames.
- Auto Ethernet and VLAN raw payload builds now choose an undefined non-length
  discriminator instead of the 802.3 zero-length value, so permissive raw link
  payloads decode and rebuild as raw bytes rather than padding.
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

[Unreleased]: https://github.com/tyk-swe/pcr/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.2...v0.4.0
[0.4.0-beta.2]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.1...v0.4.0-beta.2
[0.4.0-beta.1]: https://github.com/tyk-swe/pcr/compare/v0.3.0...v0.4.0-beta.1
[0.3.0]: https://github.com/tyk-swe/pcr/compare/4754e3934284cff8f407ae5b4a2a21ed99ac6045...v0.3.0
[0.2.0]: https://github.com/tyk-swe/pcr/tree/4754e3934284cff8f407ae5b4a2a21ed99ac6045
