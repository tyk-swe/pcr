# Changelog

All notable changes to PacketcraftR are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `packetcraftr_core::budget::remaining_before` is the one helper every crate
  uses to turn a deadline into a remaining wait; the previous netio-private copy
  is gone. Core exposes `protocol::application::dns::{read_u16, read_u32}` and
  the CLI library exposes `output::hex` for the compact hex rendering shared by
  rendering and machine output, with borrowed formatting for `--output hex`.
  `scan::DEFAULT_ATTEMPTS` names the scan attempts default.
- Published `output-expert-complete.json` and `output-replay-complete.json`
  examples; every NDJSON-capable command now publishes its terminal record.
- Clients can share an explicitly supplied progress runtime and inspect its
  admission snapshot. Netio exposes read-only process-wide native resource
  capacity, rejection and retained-cleanup diagnostics.
- Opt-in `--resource-diagnostics` adds effective settings and worker samples to
  existing JSON/NDJSON envelopes. `--output-timeout-ms` configures the finite
  NDJSON writer wait; its default remains one second.
- Independent TShark and isolated Linux native validation on main pushes,
  weekly runs, and manual CI dispatch, plus warnings-as-errors documentation
  profiles on every PR. Releases retain exact-commit
  evidence and explicitly identify unexercised Windows/macOS runtime lanes.
- Opt-in EDNS v0 requests advertise a bounded UDP payload size and optionally
  set the DO bit. DO requests DNSSEC data; it does not enable signature validation.
- DNS `--type` accepts bounded decimal and `TYPE<n>` codes alongside named
  aliases, preserving exact question codes and unknown response RDATA.
- Offline DNS inspection decodes answer, authority, and additional records,
  including EDNS and exact unknown RDATA. Core exposes bounded DNS record
  decoding shared by live queries, with typed failures for malformed or
  truncated messages and explicit message, record, name, and TXT limits.

### Changed

- `packetcraftr --help` lists exit code 130 for interrupted operations next to
  the classified codes.
- `traceroute --port`, `--source-port`, and `--first-hop` reject zero during
  argument parsing. `tls --max-tls-buffer-bytes 0` is rejected like any other
  value below the per-direction floor instead of disabling buffering.
  `replay --rate` help states that replay sends at exactly that rate, unlike
  the live commands' ceiling.
- Rust: `analysis::expert::Finding::code` and `Summary::codes` use the static
  code strings directly; `ReflectiveFieldError`, DNS name `Error`,
  `QueryTypeParseError`, and progress `EmitError` are `#[non_exhaustive]`.
- PR CI runs five jobs, with documentation and validation failure fixtures
  folded into Linux. Release-archive builds and smoke checks run in the release
  workflow; decoder and isolated native validation run outside PRs.
- Rust DNS `Request` gains an optional `edns` field, and `encode_query` takes
  that option as its fifth argument. `None` preserves the original query bytes.
- Structured command output advances to `packetcraftr.output/v3`. DNS
  `query_type` values are integers in `0..=65535` in summaries and events;
  packet documents remain `packetcraftr.packet/v1`.
- Rust DNS `QueryType` is a numeric value with `new`/`code` methods and uppercase
  named constants. Its serde representation is an integer; `Display` retains
  human-readable aliases. See [the migration notes](docs/migration-unreleased.md).
- DNS TCP fallback requires explicit provider composition. Native socket
  ownership moves to netio; the workflow retains DNS framing, shared deadlines,
  and evidence. Library exchange executors opt in with `.with_dns_tcp(provider)`;
  the CLI explicitly selects the standard-library TCP provider.
- Release archives share one verifier for required assets, binary identity,
  exact offline packet bytes, and complete NDJSON output on Unix and Windows.
- Netio interface-snapshot and packet-routing validation retain their original
  typed error sources. Route errors `InvalidSourceRouting` and
  `InvalidSegmentRouting` gain an optional `source` field; classification codes
  remain unchanged. See [the migration notes](docs/migration-unreleased.md).
- DNS record and name types move to `packetcraftr_core`; malformed declared
  records now produce offline diagnostics instead of a header-only DNS layer.

### Removed

- Rust: the equivalent public paths `packetcraftr_core::{Packet, PacketError}`
  (use `packet::`), `build::{Context, Mode, DEFAULT_MAX_LAYERS,
  DEFAULT_MAX_PACKET_SIZE}` (use `codec::` and `layout::`),
  `protocol::application::{Dns, Tls}` (use `dns::Dns` and `tls::codec::Tls`),
  the `protocol::application::tls` facade re-exports (use `fingerprint::`,
  `model::`, and `parse::`), `analysis::pcap::DEFAULT_SIZE_LIMIT` (use
  `frame::DEFAULT_SIZE_LIMIT`), and `packetcraftr::dns::tcp::SocketFault` (use
  `packetcraftr_netio::SystemFault`).
- The independent downstream compatibility workspace (`compatibility/`); its
  codec, offline collector, provider composition and output-consumer checks
  are covered by the workspace integration tests.
- The public API signature-diff CI job, `scripts/check-public-api.py`,
  `docs/public-api.md`, and the `API-DIFF.txt`/`*.current.txt` release
  assets. `VALIDATION-EVIDENCE.json` carries decoder and native evidence only.
- The manual coverage workflow, the checked-in branch-ruleset mirror,
  `scripts/measure-memory.sh`, and the static measurement snapshot, scaling
  chart and allocation comparison under `docs/`.
- **Breaking:** the `packetcraftr::fuzz::PolicyAuthorizer` and
  `packetcraftr::replay::{ReplayFrame, WireBudget}` re-exports; import them
  from `packetcraftr::policy`.

### Fixed

- Release evidence requires versioned, complete named decoder/native results,
  pinned decoder identity, input/tool digests, exact corpus frame counts,
  matching TLS JA3 evidence, and successful native scenario/launcher exits.
  Missing parent namespace IDs and contradictory or duplicate results are
  rejected. Producers and release validation share the evidence contract.
- `routes` failures keep the provider's classification, context, and cause
  chain instead of collapsing to a generic I/O message. DNS query construction
  errors and neighbor operation-and-cleanup errors expose their cause through
  `std::error::Error::source`, so `causes()` and rendered help include it.
- Unix and Windows release archives include the resource-diagnostics output
  examples required by archive verification.
- TCP pending growth no longer recopies its retained range on adjacent or
  reverse extension. Bounded payload pages and interval metadata are charged
  independently; transient output/history allocations are admitted before commit.
  Tight memory budgets may reject earlier because page slack and peaks are charged.
- Packet-document semantic budgets are independent of object-key order in JSON
  and YAML, including byte arrays, address widths and nested lists. Temporary
  staging remains bounded separately from semantic node/list/payload limits.
- TCP retransmission history uses an explicitly sized ring instead of assuming
  `VecDeque::try_reserve_exact` returns an exact capacity.
- Live DNS truncation errors include their required byte widths, fixing
  workspace compilation after the shared DNS decoder error gained that field.

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
