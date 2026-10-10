# Changelog

All notable changes to PacketcraftR are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This section describes the net changes since 0.5.0-beta.3, not intermediate
changes on `main`. See [migration guidance](docs/migration-unreleased.md) for
replacement APIs and behavior changes, and the [scanner roadmap](docs/roadmap/README.md)
for remaining acceptance gates and revision-bound evidence.

### Breaking

- The evidence ceilings of `scan::Limits`, `traceroute::Limits`, and
  `dns::Limits` now live in `evidence: packetcraftr::evidence::Limits
  { max_frames, max_bytes, max_undecoded }`; serialized field names are
  unchanged.
- Current packet documents use `packetcraftr.packet/v2`; machine output uses
  `packetcraftr.output/v12`. Consumers must explicitly support these families.
  Output v6–v11 schemas and published evidence stay frozen; see
  [consumer compatibility](docs/consumer-compatibility.md).
- Live workflows run through `Client<P, K>` with explicit providers, policy,
  clock, cancellation, and runtime. Requests and sinks replace free workflow
  runners, executor seams, and caller-supplied authorizers. Terminal results
  are `Report`; collectors rebuild `Aggregate`.
- Provider contracts take shared deadlines and retain typed error sources.
  Native contracts/resources remain in netio; route planning, neighbor
  discovery, and live policy belong to the workflow crate. Equivalent public
  aliases and superseded entry points are removed; the migration tables list
  their replacements.
- `ProviderSet` now contains UDP directly as its seventh defaulted type
  parameter and `udp` field. `WithUdp` and the broad `Providers` marker are
  removed. Callers tracking `main` add `udp: ()` to complete literals or use
  partial constructors, and bound workflows by their specific capabilities.
- Packet fields support named objects, DNS questions/records are structured,
  TCP options are typed, and DNS query types serialize as numeric `u16` values.
  Templates accumulate Cartesian axes and validate expansion before iteration.
- Core APIs use module-owned errors, typed frame lengths and link types,
  refcounted codec inputs, and nested validated limits. Invalid configuration
  fails rather than silently lowering a requested ceiling.
- Error sources appear in `causes`, not duplicated inside `message`.
  `Kind::Cli` becomes `Kind::Usage` (`"usage"`); frozen `cli.*` codes retain
  their spelling. Specific error-code changes are listed in the migration guide.
- Scan output distinguishes attempt observations, port inference, host
  discovery, scheduling, and optional traceroute provenance. Send results use
  a per-frame list; multi-interface capture IDs are capture-local rather than
  OS interface indexes. Scripts matching exact fields or enums must migrate.

### Added

- `scan::followup` runs a scan's trace and reverse-DNS follow-ups under the
  scan's own budget, so library callers get what `scan --traceroute` and
  `--reverse-dns` do: `Client::scan_with_followups` for raw scans and
  `Client::scan_connect_with_followups` for TCP connect scans.
- Explicit bounded service identification for selected TCP/UDP endpoints:
  SSH banners, HTTP HEAD, and DNS probes on any permitted port; independently
  versioned probe/match data and sensitive-service exclusions; exact evidence
  and provenance separate from unauthenticated product/version claims.
- Bounded target manifests, exclusions, packet-free scan list mode, and scoped
  IPv6 selection. Port names/presets, mixed TCP/UDP plans, reviewed catalogs,
  curated or operator UDP profiles, and scan-dependent inference preserve
  unknown, conflicting, late, duplicate, and unattributed evidence.
- Opt-in host discovery, reverse DNS, adaptive scheduling, and scan-informed
  traceroute with explicit path-reuse provenance. Portable TCP connect scans
  and rolling raw-packet windows share finite operation budgets.
- Multi-interface live capture, bounded PCAPNG rotation/retention, native buffer
  and timestamp controls, dissection/projection, and completion/file evidence.
- DNS direct TCP, bounded question batches and reverse names, EDNS v0 requests,
  numeric query types, and explicit TCP providers. Replay gains interface/filter
  routing, repetition, bit-rate pacing, and a bounded inter-frame gap.
- Offline HTTP/1, cleartext HTTP/2 and h2c, and DNS-over-TCP analysis with source
  provenance; TCP expert findings, capture summaries, and scoped stream export.
  TLS decryption and HTTP/3 remain unsupported.
- Forwarding verification with explicit identity/check rules, evidence states,
  independent detail/scratch budgets, and a strict reference consumer.
- Bounded fragmentation, capture merging/reordering, header/address rewriting,
  conditional field edits and checksum repair, gzip/Zstd capture I/O, frame
  selection, epoch bounds, and checked PCAP/PCAPNG normalization.
- Packet sets and deterministic TCP/UDP fixture conversations, named layer
  selectors, byte generators, nested reflection/filter paths, field trees,
  projection, and decode-as bindings. DNS/DHCP/TLS fixture construction and
  NTP, STP, LLDP, EAPOL, VRRP, EtherIP, GTP-U, TFTP, and syslog codecs expand
  protocol coverage; multicast helpers preserve typed and unknown wire values.
- Versioned resource presets, effective resource diagnostics, library examples,
  built-in CLI topics, generated completions/man pages, and Linux Arm64 release
  archives alongside the existing supported platforms.
- Independent decoder comparisons, scanner ground-truth fixtures, reviewed
  isolated/host-local native validation, memory benchmarks, and detached
  public-API consumer checks. Compilation or a typed unsupported result does
  not establish native feature parity.

### Changed

- Preparation and final transmission share policy, pacing, deadlines, and
  finite packet/byte budgets. Destination allowlists only narrow existing
  permissions; interface and target resolution follow authorization.
- Blocking native calls share process-wide admission. Cancelled or timed-out
  work keeps its permits until cleanup, and callback publication has bounded
  waits without promising to interrupt arbitrary user callbacks.
- Offline analysis charges retained state, provenance, compression, and
  transient allocation work explicitly. More precise accounting may reject
  inputs previously accepted near a limit; see [resource guidance](docs/analysis-resources.md).
- Human output uses stable readable durations, addresses, outcomes, and causes.
  CLI output types remain independent of clap; command format validation and
  machine records share the command catalog.
- README, migration notes, and roadmap pages now link to authoritative topic
  guides instead of repeating option catalogs and implementation history.

### Fixed

- Preserve authorization before active discovery and validate every route-bearing
  address and final wire image. Reject malformed routing/VLAN state, invalid
  limits, unsupported socket route overrides, and impossible collection budgets
  before transmission; preserve policy and underlying I/O classifications.
- Preserve exact bytes, unknown values, padding, reserved bits, capture scope,
  timestamps, and source evidence through codecs and reconstruction. DNS
  correlation/EDNS, DHCP nesting, TCP options, TLS continuations, and IPv4/IPv6
  fragments retain malformed or incomplete evidence without inventing success.
- HTTP/2 handles capture-delayed frames, SETTINGS/HPACK, stream lifecycle,
  flow-control debt, upgrades, resets, and GOAWAY under finite budgets. Later
  failures qualify earlier complete messages instead of being hidden.
- Service matching rejects malformed HTTP/SSH evidence and stale DNS identities;
  truncated replies retain uncertainty, and unknown or ambiguous results never
  assert exact versions.
  CHAOS-class TXT metadata retains its original class and bounded values.
- Scan, exchange, DNS, replay, and traceroute preserve partial results and
  accounting across timeouts, cancellation, delayed replies, and worker cleanup.
  Submission timing denotes a native interval, not proven wire departure.
- Capture transforms refuse unrepresentable metadata, timestamps, and declared
  frame check sequences. Staged publication binds to the selected directory,
  never overwrites a destination, and checks interruption after synchronization.
  Initialized compression is finalized on processing failures where possible.
- Forwarding verdicts retain readable violations despite unrelated incomplete
  evidence, distinguish absence from preservation, and enforce complete output
  and comparison bounds. Filters/projections use physical-frame facts and
  reject ambiguous byte literals and unavailable timestamps consistently.
- Native route/capture fixes preserve platform capability errors and source
  causes; release validation verifies exact-commit evidence, required assets,
  executable identity, and immutable schema/example snapshots.

### Removed

- Redundant compatibility workspaces, signature-diff and coverage workflows,
  stale repository-policy mirrors, and optional local harnesses outside the
  maintained CI/release path. Current validation lives in [CONTRIBUTING.md](CONTRIBUTING.md).

## [0.5.0-beta.3] - 2026-09-08

See [docs/migration-beta.3.md](docs/migration-beta.3.md) for the migration
guide and [docs/analysis-resources.md](docs/analysis-resources.md) for the
analysis resource semantics introduced in this release.

### Added

- Explicit cooperative cancellation across analysis, pacing, live client
  checks, capture polling, capture rewriting, offline fuzzing and publication
  waits. A CLI interrupt requests cleanup first and forces exit second; a
  cancelled invocation exits 130 and cannot report success.
- Bounded, capture-global IPv4 and IPv6 fragment reassembly with `reject`,
  `first` and `last` overlap policies, separate physical/derived accounting,
  derived transport participation in filters, stream indexing, follow, TLS
  and expert analysis, incomplete idle/EOF outcomes, shared `--ip-*` CLI
  ceilings and a dedicated fuzz target.
- Analysis evidence: capture scopes, clock regressions and forward steps,
  I/O bucket origins and clamping, and follow direction generations.
  `--max-scope-bytes`, `--max-tcp-bytes-per-flow`,
  `--max-tcp-reassembly-bytes`, `--max-tcp-segments-per-flow` and
  `--tcp-idle-expiry-ms` expose previously hardcoded ceilings with unchanged
  defaults. `tls --max-output-sessions` bounds aggregate JSON retention, and
  `expert`/`follow` bound their aggregate documents at `--max-frames` with
  `findings_omitted`/`chunks_omitted` diagnostics.
- Capture export: `read --filter` writes selected packets as same-format
  PCAP/PCAPNG, `read --normalize --output pcapng` exports matching physical
  frames into one bounded section, and offline `read`, `expert`, `follow`,
  `stats` and `tls` stream captures from stdin with `-`. Core exposes
  `analysis::pcap::select` and `analysis::pcap::Limits::advance`.
- DNS: bounded UDP-to-TCP fallback for validated truncated responses
  (`--udp-only` keeps the previous behavior and is required for scoped IPv6
  link-local servers), CAA records, and one shared bounded name decompressor
  at `packetcraftr_core::protocol::application::dns::name` with a `dns_name`
  fuzz target.
- CLI controls: `--max-layers` and `--max-packet-size` on `build` and
  `dissect`, `traceroute --source-port`, `interfaces --interface`, `routes
  --all`, `stats --top N`, the shared repeatable `--tls-port` on `stats` and
  `expert`, the exit-code table in `--help`, native feature listing in long
  `--version`, richer interface text rows, deterministic per-code `expert`
  counts, and a stderr note when `dissect` filters a frame out.
- `protocols` details list display-filter aliases, either-endpoint
  comparisons and packed-bit spellings with `filter_fields` metadata.
- Library additions: `DocumentLimits` and `Packet::parse_with_limits`,
  `output::read::Frame`, `Display` for `output::frame::Timestamp`,
  `output::stream::write_unattributed_error`, and `as_str`/`Display` on
  `netio::capture::OverflowPolicy`, `output::network::LinkMode` and
  `output::network::Capability`.
- Fuzz targets `packet_build` and `tls_session`; `filter_parse` evaluates
  compiled filters against a fuzzed frame. New published examples cover the
  `stats` tables, `read --dissect`, field-level diagnostics, DNS record
  events, scan and traceroute undecoded frames and TLS alert/truncated
  sessions.

### Changed

- **Breaking:** structured output is `packetcraftr.output/v2`: every NDJSON
  envelope carries a root `event` with one terminal `complete` or `error`
  record, replay drops the always-true `transmitted` field, result objects
  accept unknown fields, and NDJSON enforces a 16 MiB record ceiling with
  fail-closed writes bounded by the remaining operation deadline. Binary
  output to a terminal requires `--force-binary-stdout`.
- **Breaking:** crate ownership is explicit. CLI representations and the
  stream encoder live in `packetcraftr_cli::output`; the workflow crate stops
  re-exporting core, analysis, netio and output APIs; `Packet` lives in
  `packetcraftr_core::packet` with public `packet::semantics`;
  `BuiltinProtocol` moves to `protocol`; the progress runtime moves to
  `packetcraftr::progress` and is scoped to a caller-owned `Runtime`
  (`Sink::new_in`); DNS-over-TCP moves to `packetcraftr::dns::tcp`; link
  identity types live in `packetcraftr_core::packet::link`.
- **Breaking:** `packetcraftr::policy` owns operation declarations,
  authorizers and exact-wire checks. `Policy::authorize` admits operations,
  requests are complete `Operation` variants, `DnsOperation` and
  `SocketBudget` separate raw-UDP from TCP budgets, `PolicyAuthorizer` has no
  type parameter, `Client::send`/`exchange` validate the policy first, and
  `policy::Error::InvalidAddressLimit` replaces the target variant.
- **Breaking:** scan, traceroute, DNS and fuzz share one probe skeleton under
  `packetcraftr::probe` (`Request`, `Executor`, `Error`, `Transport`,
  `ProbeEndpoint`, `ProbeStatus`). Scan batches own one probe, probes pair
  transports with typed endpoints, every limits/request type exposes
  `validate(&self) -> Result<(), Error>`, `scan::select_ports`/`PortSpec` own
  port expansion, workflow constants drop repeated module prefixes, fuzz runs
  take `fuzz::RunInput`, DNS limits split into `MessageLimits` plus workflow
  `Limits`, `dns::Request` declares `tcp_fallback` with transport-specific
  evidence, `unpredictable_*` return `Result`, and the twenty-two payload
  types named `Result` are `Report`.
- **Breaking:** analysis APIs: `analysis::Limits` carries the TCP budgets,
  `reassembly::{ip, tcp}::Limits` and `reassembly::tcp::Error` are split,
  `FrameRecord` carries the located timestamp and TCP/UDP layers, collectors
  close with `finish(self, &Summary)`, `StreamTransport`/`StreamRef` live at
  the `analysis` root, capture writers take `stream_limits` at construction,
  `Reader::size_limit` is gone, and `reassembly::ip::Error::Inconsistent`
  classifies engine defects as `internal.ip_reassembly`.
- **Breaking:** core model: registry lookups take `&str` and return `layer::Id`
  by value, `Id` is a `Copy` handle over a static name, `LayerCodec::protocol_id`
  is static and `register_codec(codec, aliases)` replaces `register_builtin_codec`,
  `builtin::registry()` returns a shared `Arc`, `codec::DecodedLayer` and
  `codec::{Mode, Context}` are canonical, diagnostics use static codes with
  `error::Coordinate`, `Classified` requires `std::error::Error` and derives
  `causes` from source chains, `semantics::Error` is an enum, `FieldSchema`
  declares `aliases` (resolved by `Layer::field`/`set_field` too), the crate
  root error is `PacketError`, `ResponseMatcher::matches` returns
  `Option<Match>`, and `FieldLayout::name` is static.
- **Breaking:** failures retain their sources. Netio errors carry an optional
  shared `SystemFault`, drop `PartialEq`, and publish platform text in
  `causes` instead of restating it; route lookup errors keep `#[source]`;
  `InvalidSendEvidence` carries a typed fault; neighbor invariants move to
  `route::Error`; `PacketIo { sender, capture }` replaces the tuple providers
  and `transmit::ModeSender` replaces `Dispatch`; capture ceilings are
  `MAX_*` constants; `validate` returns `()`; `has_loss` becomes
  `evidence_loss_error()`; `dns_tcp` exposes `exchange` and `Category`.
- **Breaking:** output types stop duplicating schema definitions: payload
  modules share `network::{InterfaceId, LinkMode, Endpoint}`, build/dissect
  reports carry a flattened `frame::Wire`, DNS headers become
  `ResponseSummary`, scan/traceroute transport fields are closed enums,
  `Envelope<T>` replaces `Aggregate`/`Stream`, `protocols::Field` converts
  through `TryFrom`, and `dissect::AggregateResult::new` takes the report.
- **Breaking:** `exchange::Options` carries `capture: netio::capture::Limits`
  and an explicit `snap_length`; replay transmitters return the authorized
  `route::Materialized` from `plan_frame`, limits are `max_source_frames` and
  `max_transmitted_bytes`, and `SystemAuthorizer::new` takes the registry.
  `SocketBudget` drops `max_duration` and `DeclaredPackets` borrows packets.
- **Breaking:** classification: packet-domain failures publish specific
  `packet.*`/`cli.*` codes, configured-budget breaches classify as `policy`
  (exit 6) with `internal.codec_contract` for codec violations, capture and
  replay writer failures classify like send and exchange, DNS overruns always
  report traffic-unit codes, privilege refusals use one phrase list on every
  target, and Linux unreachable routes report `io.route_not_found`.
- **Breaking:** human output prints serde spellings (`warning`, `layer2`,
  `pcapng`, `drop-oldest`) instead of `Debug`, with colour keyed by severity;
  `replay` and `fuzz --live` spell the opt-in `--allow-permissive-live`
  (`--allow-malformed-live` remains hidden); `read` rejects `--filter` with
  capture output before compiling the filter.
- Internals and performance: constant-time derived-length invalidation,
  admission charges released at completion, stats retain only requested
  tables, progress workers own resources through cleanup (the reaper is
  gone), one interface-identity lookup per transmission, Npcap device paths
  from GUID fields, poisoned capture mutex recovery, build-script `cfg`
  platform dispatch, transactional capture stdout spooling, O(1)
  `PacketLayout::layer`, and the `boundary` fuzz strategy covering all eight
  fill combinations (seeded byte mutations differ from earlier releases).
  `core::fuzz::Stats` drops the packet aliases and gains `ValueTooLarge`,
  `MAX_TOTAL_BYTES`, `MAX_PACKET_BYTES` and `MAX_VALUE_NESTING`.
- The supported toolchain is Rust 1.98.1 with refreshed dependencies and
  lockfiles. Release archives include both schemas and a verified
  `BUILD-METADATA.json`, and packaging exercises the packaged binary first.

### Removed

- **Breaking:** the `native-interfaces` and unused `decrypt` features;
  `native-route` supplies passive interfaces and routes and pcap-free builds
  select `native-layer3`.
- **Breaking:** the ineffective `--batch-size` option, `scan::Limits::batch_size`
  and `scan::DEFAULT_BATCH_SIZE`; use `--max-probes` and `--rate`.
- **Breaking:** `dns::RecordValue::type_name()` (match variants or use
  `type_code()`) and `tls::Outcome::is_complete()` (match `Outcome::Complete`).
- **Breaking:** `output::stream::EncodeError::{MissingCommand, Writing}`;
  `EncodeError` is `#[non_exhaustive]`.
- **Breaking:** the `Default` derive on `output::contract::Format`.
- **Breaking:** `Diagnostic.range`, `output::envelope::DiagnosticRange` and the
  schema's `$defs.diagnostic.range`, which no producer set.
- **Breaking:** `document::Error::Serialize`, which nothing constructed.
- **Breaking:** `Summary::diagnostics` on scan, traceroute, DNS and live fuzz
  and `fuzz::Report::diagnostics`; diagnostics still arrive as events.
- **Breaking:** `fuzz::Error::MalformedLiveOptInRequired`.
- Nextest is no longer required; development uses Cargo, rustfmt and Clippy.

### Fixed

- Cancellation is honored between live fuzz cases, before DNS resolution and
  executor invocation, during pacing, and during aggregate JSON publication,
  always reporting `io.cancelled` with exit 130; cancellable capture waits
  back off on empty polls.
- Scan, traceroute and live fuzz clip child timeouts to the remaining budget,
  scan materializes one correlated probe per batch, and a failed
  `--interface` lookup no longer discards the selector.
- A live fuzz campaign needing the permissive-live opt-in is refused by the
  authorization seam (`policy.permissive_live_opt_in` or
  `policy.permissive_packet`) instead of an early return.
- Workflow failures over build errors and DNS TCP failures publish their
  retained causes; replay timing errors stop synthesizing causes; DNS
  executor-evidence failures no longer reach `unreachable!` arms.
- DNS-over-TCP uses one bounded frame with deadline-aware partial I/O and
  exact identity validation; DNS relevance filtering bounds CNAME traversal;
  `dns::Name` display stops allocating per byte.
- TLS analysis consumes final payload before clean closure, rejects duplicate
  or truncated extensions, distinguishes HelloRetryRequest key shares, and
  counts distinct conversations correctly after filtering.
- `follow --stream` and `tls --stream` report absent selectors from the first
  pass with exit 2; aggregate `follow`/`tls` skip conversion beyond retention;
  `read --dissect` text shows packet diagnostics; text reports bracket IPv6.
- NDJSON writes and flushes are bounded to one second and fail as incomplete
  streams without retrying stdout during cleanup.
- Replay schedules against one monotonic anchor and applies source-ownership
  policy after route selection (`--allow-source-spoofing`).
- Reduced IPv6 segment routes accept `Segments Left == Last Entry + 1`;
  PPPoE reassembly scopes include the Ethernet endpoint pair; explicit
  interface selection checks source ownership first; hostname
  deserialization canonicalizes input; checksum failures name the calling
  protocol.
- `routes` skips interfaces without a usable MTU; macOS routing-socket
  deadlines fail closed; compiled BPF programs are released by their owner.
- Offline fuzz publishes its real `stats.elapsed`, and the fuzz examples use
  distinct placeholder durations; `protocols` stops advertising
  `exact_round_trip` for `raw_ip`.
- Release archives include the README Quick Start fixtures; recipe stdin
  accepts YAML with leading comments or reordered keys.

### Security

- Dependency advisory and license policy (`cargo deny`) runs on a weekly
  schedule, on dependency changes, and again as a release preflight. No
  advisory exceptions exist; the duplicate-version skips in `deny.toml` each
  document the dependency that requires them.

## [0.5.0-beta.2] - 2026-08-27

### Added

- Added `packetcraftr tls` session assembly across TCP segmentation, with
  SNI/ALPN, negotiated parameters, JA3/JA3S/JA4, alert and completion status,
  bounded selection/buffering, text, JSON, and streaming NDJSON output.
- Added decode-only TLS records on common TCP ports, `--tls-port` overrides,
  protocol binding discovery, public TLS registry/parser/session/output APIs,
  and a runnable documentation-address capture.
- Added explicit source-spoofing policy: packet sources not owned by the
  selected interface require `--allow-source-spoofing` before discovery,
  capture, or transmission.

### Changed

- **Breaking:** TCP port dispatch can now decode TLS instead of raw payload;
  `BuiltinProtocol` and the output command vocabulary gained TLS variants.
- **Breaking:** protocol detail output exposes parent bindings, and its Rust
  constructor takes them.
- **Breaking:** passive capture requires an interface; progressive commands
  emit typed, contiguous NDJSON events ending in one completion or error.
- **Breaking:** scan output uses address-bearing endpoints; replay coordinates,
  fuzz limits, and live-only options were normalized.
- **Breaking:** the workspace became four crates: `packetcraftr-core`,
  `packetcraftr-netio`, `packetcraftr`, and `packetcraftr-cli`. Public modules
  were flattened and obsolete aliases removed.
- **Breaking:** capture rewriting preserves source format and validated records;
  `transcode` was removed and missing timestamps are diagnosed where required.
- **Breaking:** live workflows share one authorization seam, and native route
  joins the default features.
- Explicit inputs take precedence over stdin, machine output streams from exact
  bytes, live checksum rejection uses stable diagnostic codes, capture budgets
  are enforced by library policy, and public name helpers now drive text output.

### Removed

- **Breaking:** removed unused IP-fragment reassembly and its limits.
- **Breaking:** removed the always-enabled
  `decode::Options::verify_checksums` field and the fixed TLS per-direction
  buffer option.
- **Breaking:** removed unreachable packet, registry, capture-writer, document,
  decode, codec, template, client-plan, and replay convenience APIs. Use the
  remaining module-scoped entry points, including `replay::run_with_selector`.

### Fixed

- `dissect --output json --filter` always emits a complete aggregate result,
  including successful no-matches.
- Hardened structured error classification, TCP scope/reassembly, live response
  correlation and deadlines, callback/worker ownership, byte-range validation,
  resource accounting, and malformed-input handling.
- IPv4 broadcast routes remain broadcasts through selection and transmission;
  outer source routes and final destinations drive the correct checksums.
- The workspace now denies unchecked indexing and arithmetic in library code.

### Security

- Updated rtnetlink to 0.23, removing the unmaintained `paste` dependency and
  its advisory exception.

## [0.5.0-beta.1] - 2026-08-09

### Added

- Added expert finding selectors, bounded scan port ranges, incremental follow
  NDJSON, resolver-free native BPF capture filters, and exact DNS-over-UDP
  header/question dissection.
- Established deterministic nextest and cross-platform feature, MSRV, doctest,
  rustdoc, lint, and dependency-policy CI.

### Changed

- **Breaking:** consolidated the workspace into six packages split across
  packet mechanics, analysis, native networking, policy workflows, facade, and
  CLI; removed former crate aliases while preserving CLI and wire contracts.
- **Breaking:** flattened command output modules and removed unused public
  scaffolding, redundant aggregate manifests, and no-op policy flags.
- Route-only builds avoid interface-enumeration dependencies; replay uses the
  canonical dissector and fail-closed route semantics.

### Fixed

- Tightened schema validation, final-wire authorization, tunneled response
  matching, native route/interface identity, MTU selection, capture shutdown,
  PCAPNG bounds, reassembly, fuzz/live validation, DNS evidence, and replay
  sequencing.
- Live destinations are re-authorized after materialization, stale or reused
  evidence cannot satisfy probes, and queue/deadline accounting fails closed.

## [0.4.0] - 2026-07-29

### Added

- Published the original per-domain crate workspace, including the independent
  error/budget, packet/protocol, capture/session, analysis, native, workflow,
  output, facade, and CLI layers.
- Added `protocols` discovery and a bounded display-filter language with
  aliases, field paths, occurrence selection, slices, set/prefix membership,
  and stream indices. Filters cover read, dissect, capture, replay, and offline
  analysis.
- Added exact-round-trip VXLAN, GENEVE, LLC/SNAP, L2TPv3, ERSPAN, ESP/AH,
  PPPoE/PPP, and MPLS protocol support with strict discriminator and tunnel
  boundary handling.
- Added offline `follow`, `expert`, and `stats` commands on a shared bounded
  read/dissect/index/filter pipeline with capture-global conversation indices.
- Added replay selection before authorization/transmission while retaining
  stream budgets and source timing.

### Changed

- **Breaking:** offline analysis moved to `packetcraftr-analysis` and
  `packetcraftr::analysis`, with no dependency on live I/O.
- **Breaking:** `BoundaryError` became canonical in the error domain, and
  Ethernet/VLAN discriminator values at or below 1500 now decode as 802.3/LLC
  payload lengths.
- Native features moved to the networking crate, interface enumeration became
  `native-interfaces`, and the output-v1 vocabulary gained protocol discovery.
- Repository layout and documentation were aligned with Cargo metadata and
  generated CLI help as authoritative sources.

### Removed

- Removed the unreleased `cli` feature; build the `packetcraftr-cli` package.
- Removed the redundant exchange `Io` marker; use the sender and capture
  provider traits directly.

## [0.4.0-beta.2] - 2026-07-24

### Added

- Added first-run, contributor, security, issue, review, and CODEOWNERS
  guidance; terminal-aware human color; command-focused CLI examples; and
  Linux native E2E/CI coverage.
- Added exact GRE, SCTP, IGMP, and nested IPv4/IPv6 construction/dissection,
  plus SCTP and quoted-ICMP exchange correlation.

### Changed

- Release archives include the README and changelog, CLI diagnostics share one
  hardened renderer, and route/materialization logic follows only the outer IP
  envelope.
- Protocol numbers for IGMP, nested IP, GRE, and SCTP became typed bindings.
  Packet building, scan/traceroute batching, and binding lookup allocate less.

### Fixed

- Hardened strict packet semantics across routing, authorization, checksums,
  replay, correlation, workflow budgets, capture I/O, TCP reassembly, native
  interface identity, macOS routes, Linux netlink, and CLI exit handling.
- Fixed PPPoE continuation, timestamp minima, Ethernet/VLAN raw fallback,
  packet-schema validation, capture-worker cleanup, and failure-atomic writing.

### Security

- Documented and time-bounded the temporary `RUSTSEC-2024-0436` exception and
  enabled weekly dependency updates.

## [0.4.0-beta.1] - 2026-07-17

### Added

- Added tag-driven multi-platform full and pcap-free release archives with
  SHA-256 checksums.
- Added named `ReaderOptions`, `PcapOptions`, and `PcapNgOptions`.

### Changed

- Reduced build/decode and reassembly allocations, reused route decisions, and
  simplified capture construction and workflow extension traits.
- Clarified traceroute identity, timeout, rate, policy, and output behavior.

### Removed

- **Breaking:** removed `Reader::read_frame` / `Writer::write`; use
  `next_frame` / `write_frame`.
- **Breaking:** removed legacy clock, reassembly, fragment-key, resolved-target,
  capture-constructor, output link-type, DNS transport, workflow error/stats,
  and route identifier aliases. Their module-scoped replacements are canonical.

### Fixed

- Corrected schema API documentation; preserved traceroute identity and fresh
  ICMP correlation; enforced capture section bounds, replay link-type checks,
  and consistent binding priority.

## [0.3.0] - 2026-07-14

### Changed

- **Breaking:** reorganized the Rust API under canonical capture, client, error,
  net, output, packet, protocol, session, and workflow domains.
- Consolidated the workspace into one Rust 2024 package while preserving Rust
  1.96, feature profiles, CLI commands, packet documents, and output contracts.

### Fixed

- Hardened packet/dissection, tunneled responses, workflow evidence, capture
  deadlines, neighbor caching, reassembly, PCAP/PCAPNG handling, CLI parsing,
  native routes, feature gates, and interface validation.

## [0.2.0] - 2026-07-11

### Added

- Established the original PacketcraftR packet, capture, native networking,
  session, workflow, library, and CLI baseline.

[Unreleased]: https://github.com/tyk-swe/pcr/compare/v0.5.0-beta.3...HEAD
[0.5.0-beta.3]: https://github.com/tyk-swe/pcr/compare/v0.5.0-beta.2...v0.5.0-beta.3
[0.5.0-beta.2]: https://github.com/tyk-swe/pcr/compare/v0.5.0-beta.1...v0.5.0-beta.2
[0.5.0-beta.1]: https://github.com/tyk-swe/pcr/compare/v0.4.0...v0.5.0-beta.1
[0.4.0]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.2...v0.4.0
[0.4.0-beta.2]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.1...v0.4.0-beta.2
[0.4.0-beta.1]: https://github.com/tyk-swe/pcr/compare/v0.3.0...v0.4.0-beta.1
[0.3.0]: https://github.com/tyk-swe/pcr/compare/4754e3934284cff8f407ae5b4a2a21ed99ac6045...v0.3.0
[0.2.0]: https://github.com/tyk-swe/pcr/tree/4754e3934284cff8f407ae5b4a2a21ed99ac6045
