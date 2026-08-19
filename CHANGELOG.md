# Changelog

All notable changes to PacketcraftR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** `read` NDJSON is now an explicit event stream ending in one
  mandatory `complete` event with source frame, match, and captured-byte
  counters. `read` and `capture` frame events expose the stable one-based
  `source_frame` used by display filters as `frame.number`, while envelope
  `sequence` remains the zero-based emitted-record ordinal. Capture completion
  now distinguishes captured source frames, matched frames, and captured bytes.
- Explicit packet and frame sources now take precedence over stdin, while
  missing interactive input fails immediately with command-specific guidance.
- **Breaking:** NDJSON envelope `sequence` is now exclusively the contiguous,
  zero-based ordinal of an emitted record for one command invocation. The CLI
  owns stream position through terminal success or error; source-frame, probe,
  attempt, hop, replay, and fuzz-case identifiers remain domain data and no
  longer select terminal error positions. Generic domain-error `sequence()`
  accessors were removed, and public stream-envelope constructors now accept an
  explicit `StreamPosition` instead of an arbitrary integer.
- **Breaking:** Scan, traceroute, and DNS NDJSON now publish semantic events
  during execution instead of serializing an accumulated result afterward.
  Scan and traceroute stream records are per-probe, DNS record and rejection
  events carry their attempt, retained undecoded evidence is emitted when
  accepted, and each stream ends with exactly one terminal complete or error
  record. The library exposes command-specific `run_with_events` entry points;
  aggregate `run` results are collectors over the same event path.
- **Breaking:** Scan output now exposes address-bearing `endpoints` with an
  optional port, replacing the `ports` collection, ICMP port-zero sentinel,
  and evidence-derived address in aggregate and streaming output.
- **Breaking:** Offline fuzz limits now contain only campaign-generation
  bounds. Live evidence bounds moved to `packetcraftr::fuzz::LiveLimits`, the
  CLI has an independent `--max-packet-bytes` option, and live-only fuzz
  options require `--live`.
- Shared wire and captured-frame output records now retain only exact bytes and
  serialize hexadecimal lazily. JSON and hexadecimal output stream to stdout,
  text hexadecimal no longer allocates a second temporary representation, and
  exchange text summaries bypass decoded machine-output construction.
- **Breaking:** Offline TCP and IP-fragment reassembly keys now require a
  compact capture-scope identity created by the exact scope interner.
- **Breaking:** Consolidated the workspace from six crates to four.
  `packetcraftr-packet` became `packetcraftr-core`, with packet mechanics at its
  crate root and the former `packetcraftr-analysis` API under
  `packetcraftr_core::analysis`; `packetcraftr-network` became
  `packetcraftr-netio`; and the former `packetcraftr-live` workflows now live
  directly under `packetcraftr`. The main library re-exports `core`,
  `core::analysis` as `analysis`, and `netio`; the former `packet`, `network`,
  and `live` aliases have no compatibility shims. The `packetcraftr` CLI name,
  command-line interface, and versioned packet and output schema shapes are
  unchanged. Unlike `packetcraftr-live`, `packetcraftr` enables
  `native-interfaces` by default; direct consumers that need the former
  portable footprint must set `default-features = false` when migrating.
- Flattened the public `packetcraftr-core` build, codec, decode, diagnostic,
  document, expression, field, layout, and matcher module paths, and exposed
  `protocol::ChecksumAccumulator` for shared incremental Internet checksums.
- **Breaking:** Rust APIs now use their module as context instead of repeating
  it in type names or exposing alias facades. Canonical examples include
  `build::{Error, Context, Mode, Options, BuiltPacket}`,
  `decode::{Dissector, Error, Options, DecodedPacket}`, `registry::Registry`,
  `document::Packet`, and the scoped `dns::{Error, Request, Result}` family.
  The former domain-prefixed definitions have no compatibility aliases.
- **Breaking:** Route and neighbor contracts now live under their actual
  owners as `route::{Error, Options, Plan, Decision, Provider}` and
  `neighbor::{Error, Options, Resolver}`. Route Rust fields use
  `selected_source` and `decision`, while output-v1 retains the existing
  `selected_address` and `route` keys.
- **Breaking:** Command output modules now expose concise `Result` and `Event`
  models, with shared frame and network representations under public
  `output::frame` and `output::network` owners. Output-v1 documents are
  unchanged.
- Reorganized packet decoding, fragment reassembly, route planning, and live
  exchange correlation around explicit phase and state owners. That internal
  reorganization did not change serialized output contracts or runtime
  behavior.
- Split oversized builders, codecs, reassembly planners, workflow engines, CLI
  orchestration, and integration tests at concrete phase boundaries.
- Added checked, all-or-nothing capture-statistics aggregation through
  `packetcraftr_netio::capture::Statistics::checked_add`.
- **Breaking:** Removed the undocumented `Client::exchange_for_workflow` seam;
  bounded workflows continue to expose supported executors.
- **Breaking:** Layer decoders now use `consumed` as the sole child-payload
  offset; removed the redundant `DecodedLayerValue::payload_offset` field.
- **Breaking:** Live scan, traceroute, and DNS executors now share the canonical
  exchange response-evidence type. Custom DNS executors must set its request
  index, which is normally zero for the single DNS probe in an exchange. DNS
  evidence-limit errors now use the shared captured-frame/byte terminology.
- **Breaking:** Live transmission now returns opaque provider receipts that bind
  semantic builds, materialized routes, exact accepted bytes, byte counts, and
  provider-established monotonic/wall-clock timing. Capture correlation uses
  opaque ingress identity and monotonic freshness, and high-level executor
  successes are invocation-bound rather than caller-constructible evidence.
- **Breaking:** Capture rewriting is now a bounded, same-format operation that
  preserves every validated source record and rejects CLI format conversion or
  filtering instead of silently normalizing PCAPNG structure. The capture API
  exposes section-local records, packet block kinds, arbitrary options, and
  the complete classic-PCAP network word; `transcode` has been removed.
- **Breaking:** Capture-frame timestamps are optional because PCAPNG Simple
  Packet Blocks do not carry time. Timestamp-dependent filters, offline
  analysis, original/scaled replay timing, and capture writers diagnose missing
  time; immediate/fixed-rate replay and structured frame output support it.
- Source, CI, and release builds now use Cargo and Rust toolchain platform
  defaults without a project-level compiler wrapper or linker override.
- **Breaking:** Removed the generic `Packet::mutate_fixed_width_layer` escape
  hatch. All public mutable layer access now invalidates cached encoded
  payload lengths; decoded packets populate those lengths from their layer
  ranges.
- Display-filter requirements now identify TCP and UDP stream-index needs
  independently while retaining the aggregate stream-index signal.
- The workspace now uses Cargo resolver version 3 so dependency selection
  honors the declared workspace Rust version.
- Updated user, contributor, security, and API documentation for the four-crate
  layout and removed duplicated command, feature, and validation inventories.

### Fixed

- Corrected `dissect --output json --filter` to emit one complete aggregate
  document for both matches and no-matches; no-match success now reports
  `result.matched: false` with `result.dissection: null`.
- Human-readable runtime errors now include stable classification codes,
  retained causes, and available remediation guidance.
- Corrected the DNS text summary label from `response_name` to
  `response_code_name`.
- Kept TCP follow delivery edges aligned with directional reassembly
  generations, preventing Fast Open payload retransmissions from being emitted
  twice while still resetting deduplication for four-tuple reuse.
- Required captured reverse-direction outstanding payload before reporting TCP
  duplicate acknowledgments, without advancing duplicate counts for
  unreportable repeats.
- Used the ultimate remaining IPv4 LSRR or SSRR destination for TCP and UDP
  pseudo-header checksums during encoding and decoding.
- Enabled IPv4 broadcast permission on every raw IPv4 socket before
  transmission, including sockets used for subnet-directed broadcasts.
- **Breaking:** Preserved limited and subnet-directed IPv4 broadcast routes
  through native selection and Layer-2 planning, emitting the Ethernet
  broadcast MAC without neighbor resolution and exposing `broadcast` as a
  route selection reason.
- Indexed offline TCP and IP-fragment expiry deadlines so dense captures no
  longer scan every resident reassembly flow for each pushable segment.
- Kept conversation indexing, follow/statistics/expert analysis, TCP
  reassembly, and IP-fragment reassembly separate across PCAPNG interfaces and
  semantic encapsulation paths such as VLAN stacks, tunnel identifiers, MPLS
  labels, and PPPoE sessions.
- Accepted valid injected-provider transmission reports across backward
  wall-clock adjustments by validating timing with monotonic endpoints.
- Preserved TCP response correlation for Layer2 exchanges whose TCP
  sequence-space length depends on encoded payload caches.
- Bounded live duplicate capture tracking to retained exchange evidence.
- Kept neighbor resolution attempt timeouts anchored before Layer2 sends.
- Native capture and Linux netlink workers now retain ownership across finite
  shutdown timeouts and transfer unfinished threads to explicit reapers.
- Rejected byte-slice filter indices whose exclusive upper bound cannot be
  represented instead of silently compiling them as empty ranges.
- Accounted for retained TCP flow-table metadata within the aggregate
  reassembly budget, including transactional replacement and close handling.
- Correctly attributed structured CLI parse errors without mistaking the
  executable, global-option values, or later positionals for the command.

## [0.5.0-beta.1] - 2026-08-09

### Added

- Added `expert --min-severity` and repeatable `--code` finding selectors.
- Added bounded inclusive ranges to `scan --ports`; ranges and individual
  ports deduplicate in first-seen order and remain subject to `--max-ports`.
- Added incremental `follow` NDJSON: delivered chunks stream in order followed
  by one terminal summary record. JSON, text, hex, and raw behavior is unchanged.
- Added resolver-free native BPF through `capture --capture-filter`. It runs
  before PacketcraftR's queue and budgets and is independent of the existing
  post-capture `--filter` language.
- Added bounded, exact-round-trip DNS-over-UDP header and question dissection
  for port 53 while retaining raw handling for custom ports.
- Added a deterministic cargo-nextest 0.9.143 baseline and cross-platform CI
  for no-default, default, all-feature, MSRV, doctest, rustdoc, lint, and
  dependency-policy checks.

### Changed

- **Breaking:** Consolidated the workspace into six packages. Budgets, errors,
  frames, packet mechanics, built-in codecs, and deterministic offline fuzzing
  now live in `packetcraftr-packet`; PCAP I/O and offline diagnostics live in
  `packetcraftr-analysis`; native networking lives in
  `packetcraftr-network`; and policy-gated operations live in
  `packetcraftr-live`. The facade exposes only `packet`, `analysis`, `network`,
  `live`, and `output`; removed crates and former facade aliases have no
  compatibility shims. CLI flags and serialized contracts are unchanged.
- **Breaking:** Flattened command output paths: `output::capture::Read` is now
  `output::read::Result`, while `output::network::{interfaces, plan, routes,
  send, exchange}` are now the top-level `output::{interfaces, plan, routes,
  send, exchange}` modules. Serialized command documents are unchanged.
- **Breaking:** Removed unused public scaffolding across the Rust API, including
  `ProtocolModule`, stored `RoutePlanner`, `TemplateValues`, secondary error
  categories, packet normalization/layout hooks, fragment report and reassembly
  getters, provider introspection, the duplicate command-contract table, and
  aggregate support/workflow manifests. Fuzz and DNS workflow models no longer
  store values derivable by the facade output layer. Output-v1 wire documents
  remain compatible except for the separately documented `follow` stream.
- **Breaking:** Removed accepted no-op traffic-policy options: `plan` lost its
  permissive and packet/byte flags; `capture`, `scan`, `traceroute`, and `dns`
  lost their permissive flag; and `fuzz` lost its hostname-resolution flags.
  Applicable authorization behavior and stable error codes are unchanged.
- `packetcraftr-network/native-route` no longer enables `native-interfaces`, so a
  route-only build avoids the unrelated interface-enumeration dependency.
- Replay now uses the canonical built-in dissector and shared fail-closed route
  semantics instead of a separate wire-route parser.
- Internal ownership now follows command and domain boundaries, Cargo metadata
  defines the workspace graph, and Linux builds use lld. CLI behavior, packet
  bytes, and existing structured documents are unchanged.
- Consolidated user, contributor, security, and review documentation around
  generated CLI help, Cargo metadata, schemas, and CI as authoritative sources.

### Fixed

- Tightened output validation to reject malformed IP addresses and DNS records
  containing fields from another record type; schema validators now enable IP
  `format` assertions.
- Hardened live authorization over final Ethernet/VLAN bytes, custom
  registries, malformed routing layers, fragments, and IPv4-mapped IPv6
  addresses. Every materialized destination is re-authorized before native I/O.
- Required tunneled responses to reverse the transmitted outer envelope and
  prevented one ambient frame from satisfying multiple probes. Unmatched and
  freshness-less evidence is retained deterministically.
- Hardened native routes and capture: route sources must belong to the selected
  interface, MTUs use the route/interface minimum, non-contiguous macOS masks
  are rejected, macOS/Windows route builds work again, and numeric replay
  interface selectors resolve correctly.
- Fixed capture queue draining and bounded shutdown, Npcap activation warnings,
  finite Linux netlink shutdown, and NDP after supported IPv6 extension headers.
- Accepted valid PCAPNG padding, bounded cumulative metadata before allocation,
  and made capture-writer flush failures retryable.
- Hardened fragment/TCP reassembly, capture-clock and statistics arithmetic,
  packet allocation, expression escapes, IPv6 SRH padding, negative capture
  timestamps, and bare-RST matching.
- Validated fuzz recipes and live-capture settings before side effects; fixed
  fuzz accounting, duplicate strategies, UDP retry identities, deadline-held
  evidence, and committed replay evidence across deadline boundaries.
- Validated synthesized Ethernet DNS evidence and rejected re-encoding typed
  DNS fields that disagree with their retained wire payload.
- Made filtered replay NDJSON envelope sequences contiguous while preserving
  each record's independent `source_sequence`.

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
  matching frames in text, hex, and raw formats; aggregate JSON reports the
  filter outcome in its success document. `capture`
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

[Unreleased]: https://github.com/tyk-swe/pcr/compare/v0.5.0-beta.1...HEAD
[0.5.0-beta.1]: https://github.com/tyk-swe/pcr/compare/v0.4.0...v0.5.0-beta.1
[0.4.0]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.2...v0.4.0
[0.4.0-beta.2]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.1...v0.4.0-beta.2
[0.4.0-beta.1]: https://github.com/tyk-swe/pcr/compare/v0.3.0...v0.4.0-beta.1
[0.3.0]: https://github.com/tyk-swe/pcr/compare/4754e3934284cff8f407ae5b4a2a21ed99ac6045...v0.3.0
[0.2.0]: https://github.com/tyk-swe/pcr/tree/4754e3934284cff8f407ae5b4a2a21ed99ac6045
