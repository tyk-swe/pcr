# Changelog

All notable changes to PacketcraftR are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Add typed security scan snapshots and `compare_snapshots`, retaining the byte
  comparison API and its validation. Separate security input adaptation,
  published output fields, and rendering, and organize capture investigations,
  packet preparation, and scan execution by responsibility without changing
  CLI or data contracts.

- Add local IOC hunting, DNS anomaly and TCP beacon detection, TLS certificate
  and HTTP configuration audits, native scan comparison, and standalone HTML
  assessments. Publish bounded security findings in output/v1 and a versioned
  local IOC document; support severity exit thresholds and explicit incomplete
  evidence. Live audits need ordinary TCP sockets and authenticate certificates
  before sending HTTPS requests.

- Publish output/v1 with typed raw measurement coverage, provisional stream
  qualification before inference, preserved positive evidence under permissive
  capture loss, and separate RTT unavailable counts. All current examples use the v1 baseline.

- Group all 31 CLI commands under packet, files, analyze, network, and reference,
  removing every flat path. Add layered short/full help,
  compact text results and global verbose details, canonical command references,
  and completion/man-page coverage for grouped paths. Machine output
  identifiers remain unchanged.

Net changes since 0.5.0-beta.3. See [migration guidance](docs/reset-v1.md)
for replacement APIs.

### Breaking

- Reset output, packet, and rewrite documents to one current v1 contract each;
  remove historical schemas, aliases, and version-only fixtures. Historical v1
  documents are not compatible with this baseline. Update scripts and migrate
  or regenerate documents together; see the [reset guide](docs/reset-v1.md).
- Keep only grouped CLI paths for all 31 operations. Preserve options, compact
  machine command identifiers, and protocol/value aliases. Share one release
  asset manifest between packaging and archive verification.
- Reset internal validation and acceptance report versions to 1 without
  weakening evidence requirements. The package stays at `0.5.0-beta.3`.

- Reserve four of the 16 native-root places for eligible control work by bounding
  connecting/established TCP data at 12. Trace stages share their parent runtime
  by default; explicit trace runtimes remain independent. Built-in collectors
  publish cooperatively without worker admission. See the architecture migration
  notes for snapshot and `Runtime::new(0)` implications.


- Rename codec extension types to `Codec`, `EncodeContext`, `DecodeContext`,
  `Encoded`, and `Decoded`, and address defaults to `codec::Addresses`.
  Use `field::Kind`, `field::Value`, `probe::Endpoint`, and `probe::Status`.
- `analysis::Session::new` takes its stream selector from `Options.stream`.
  `Client::with_deadline` consumes the client and narrows its existing ceiling;
  scan preparation and remaining-budget helpers are replaced by private operation
  state. Composed scan, trace, DNS, and OS stages share their bounds and accounting.
- CLI invocations own output, cancellation, deadlines, and resource diagnostics;
  worker closures inherit those bounds. Command behavior and serialized schemas
  remain unchanged by this refactor.

- `scan::Limits`, `traceroute::Limits`, and `dns::Limits` nest evidence bounds
  under `evidence: packetcraftr::evidence::Limits { max_frames, max_bytes, max_undecoded }`,
  preserving JSON and binary Serde representations.
- Packet documents use `packetcraftr.packet/v1`; machine output uses
  `packetcraftr.output/v1` (see
  [consumer compatibility](docs/consumer-compatibility.md)).
- Live workflows run through `Client<P, K>` with explicit providers, policy,
  clock, cancellation, and runtime, taking `(request, sink)` and returning
  `Report` (`Collector::finish` rebuilds `Aggregate`). `ProviderSet` includes
  `udp` as its seventh defaulted field; `WithUdp` and the broad `Providers`
  marker are removed.
- Provider contracts take `&budget::Deadline` and retain typed error sources.
  Route planning, neighbor discovery, and live policy belong to `packetcraftr`.
- Packet fields support named objects, DNS questions/records are structured,
  TCP options are typed, DNS query types serialize as numeric `u16`, and
  templates accumulate Cartesian axes.
- Core APIs use module-owned errors, typed frame lengths and link types,
  refcounted codec inputs, and nested validated limits. Error sources appear in
  `causes` rather than duplicated inside `message`, and `Kind::Cli` is renamed
  `Kind::Usage` (`"usage"`).
- Scan output separates attempt observations, port inference, host discovery,
  scheduling, and optional traceroute provenance; `send` reports a per-frame
  list; `capture` uses capture-local interface IDs.

### Added

- Add capture-free policy-gated `send_layer3` with `TransmitProviders`, bounded
  owned hostname resolution, explicit cooperative sink delivery, and separate
  native execution/socket snapshots. Preserve isolated arbitrary callbacks.


- Offline statistics overview with capture totals and five-row traffic leaderboards,
  explicit `--sort frames|bytes`, and CSV exports for flat statistics tables.
  Use the current output/v1 contract and fixtures.
  See [statistics](docs/statistics.md) for ordering, limits, and CSV headers/units.

- Raw SCTP `INIT` and `COOKIE-ECHO` scans (`scan::SctpScan`, `--transport sctp`,
  `--sctp-scan`, `sctp:` port prefixes), standalone IP-protocol (`0..=255`)
  inventory (`scan::select_ip_protocols`, `--transport ip`, `--ip-protocols`,
  `--exclude-ip-protocols`), extra host-discovery probe families (`tcp-ack`,
  `icmp-timestamp`, `icmp-netmask`, `sctp`, `ip`), output/v1, dataset 1.8.0
  `sctp_ip_protocol_scenarios`, and the `sctp_ip_protocol` native validation
  runner ([native validation](docs/native-validation.md)).
- Raw TCP diagnostic scans (`scan::TcpScan`: `Syn`, `Ack`, `Window`, `Fin`,
  `Null`, `Xmas`, `Maimon`, and observation-only `Custom`, via `--tcp-scan` and
  `--tcp-flags`) with mode-specific inference (`unfiltered`, `tcp_<mode>.*`),
  retained `tcp_window` in output/v1, dataset 1.7.0 diagnostic scenarios, and
  the `tcp_diagnostics` native validation runner ([TCP diagnostics](docs/tcp-diagnostics.md)).
- Standalone `identify-os` / `Client::identify_os` with dual-stack probes,
  verified open/closed prerequisites, exact wire evidence, qualified OS-family
  candidates, and output/v1 ([OS identification](docs/os-identification.md)).
- Explicit service identification (`identify` / `Client::identify`) over
  selected TCP/UDP endpoints with SSH, HTTP HEAD, DNS, SMTP, and FTP probes,
  optional `--tls` wrapping (TLS 1.2/1.3, declared SNI, DER certificate
  observations, `usage.tls`), sensitive-service exclusions, and sourced hostnames
  and wildcard-version CPEs
  ([service identification](docs/service-identification.md)).
- Bounded target manifests/exclusions, `network scan --list`, scoped IPv6 selection,
  port catalog/presets, curated and operator UDP profiles, mixed TCP/UDP plans,
  opt-in host discovery, reverse DNS, adaptive scheduling, and scan-informed
  traceroute with sourced hop reuse (`Client::scan_with_followups`,
  `Client::scan_connect_with_followups`, `Client::trace_hosts`), backed by
  scanner corpus datasets 1.1.0–1.8.0.
- Multi-interface live capture with bounded PCAPNG rotation/retention, native
  buffer and timestamp controls, and opt-in dissection/projection.
- DNS direct TCP (`--tcp`), bounded question batches, `--reverse` PTR queries,
  and EDNS v0 requests. Replay interface/filter routing, repetition, bit-rate
  pacing (`--bps`), and `--max-gap-ms`.
- Offline HTTP/1, cleartext HTTP/2 and h2c (`http2`), and DNS-over-TCP analysis
  with source provenance; TCP expert findings, capture summaries, and dependency-aware
  stream/datagram `export`.
- Forwarding verification (`verify-forwarding`) with identity/preservation/expectation
  rules, evidence states, detail/scratch budgets, and a reference consumer.
- Capture `fragment`, `merge` (chronological look-ahead or `append`), `rewrite`
  (headers, CIDR/MAC maps, fixed-width fields, dry-run), gzip/Zstd capture I/O,
  frame selection, epoch bounds, and checked PCAP/PCAPNG normalization.
- Packet sets (`--axis`, `--set`), deterministic TCP/UDP sessions, byte
  generators, nested reflection/filter paths, `--tree` and `--field` projection,
  decode-as bindings, DNS/DHCP/TLS fixture construction, and NTP, STP, LLDP,
  EAPOL, VRRP, EtherIP, GTP-U, TFTP, and syslog codecs.
- Versioned resource presets (`ci-v1`, `workstation-v1`), `--resource-diagnostics`,
  built-in `topics`, generated completions/man pages (`documentation`), and
  Linux Arm64 release archives.

### Changed

- Preparation and final transmission share policy, pacing, deadlines, and
  packet/byte budgets; `--allow-destination` narrows permitted addresses.
- Blocking native calls share process-wide admission; timed-out or cancelled
  workers retain permits until cleanup.
- Offline analysis charges retained state, provenance, compression, and TCP
  out-of-order page slack explicitly ([resource guidance](docs/analysis-resources.md)).
- Consolidate contributor guidance in `CONTRIBUTING.md` and streamline CLI help,
  built-in topics, user guides, and migration notes.

### Fixed

- Make native worker submission and TCP socket promotion single-use ownership
  transfers, preventing duplicate work or socket charges under one admission.
- Skip capture-source rotation discovery for fixed raw scans, avoiding repeated
  traversals of every unsent probe that could exhaust the scan duration budget.
- Apply raw-scan acquisition qualifications to follow-up endpoint reports so
  NDJSON and collected inferences agree for fixed and adaptive scans.
- Retry transient cleanup-slot overlap after callback worker admission, keeping
  immediate runtime reuse reliable without releasing unfinished cleanup charges.
- Bound executor thread retirement under original caller control, including
  abandoned socket destructors and provider-owned thread-local cleanup.
- Retire idle historical namespace services without abandoning queued work;
  transfer connect execution to socket ownership transactionally; retain actual
  unfinished lookup/capture charges after caller cancellation.
- Preserve inherited raw-scan and analysis-finalization control, share one
  capture-group cleanup allowance, and treat local TCP deadline expiry as an
  unavailable observation in adaptive control.
- Replace growing HTTP/TCP-DNS/fragment provenance unions with charged mutable
  assembly and remove repeated adaptive endpoint-prefix work discovery.
- Index raw response candidates and expirations while preserving ambiguity and
  conservative matching fallbacks. Refill adaptive raw slots incrementally under
  one acquisition lifetime and cumulative budget, with bounded source rotation.
- Retain bounded preparation previews while revalidating current routes,
  interfaces, MTUs and final bytes. Account for retained stage summaries, scoped
  names and overlapping capture-source allocations before admission.
- Preserve inherited elapsed control in native waits and prepare repeated sends
  after pacing, so route and MTU checks follow that cooperative boundary.
- Use the current curated decoder inventory in release-archive verification.

- Keep rejected UDP application checks visible in compact scan output, including
  their profile and rejection reason.
- Preserve option descriptions in generated manuals for both grouped and legacy
  command paths, including options omitted from short CLI help.

- NDP Route Information options accept every prefix-field length permitted by
  RFC 4191, retaining valid longer encodings as typed routes without changing
  their wire bytes.

- Loopback IP scans exclude captures of their own empty transmitted probes,
  and SCTP INIT ACK observations validate every chunk's framing and padding.

- Keep compact IP reply ambiguity history for the entire operation, including
  serial execution, adaptive waves, and discovery-to-scan transitions.

- Retain ambiguous IP retry replies as unattributed evidence, distinguish
  IPv6 link padding from Jumbo Payload options, and count excluded TCP
  discovery endpoints after SYN/ACK expansion.

- Correlate ICMPv6 errors quoting empty IPv6 probes when RFC 4884 padding
  and extension objects follow the declared datagram.

- Include shared IP reply identities in scan and discovery duration admission,
  and consume discovery-only transport exclusions before validating scan ports.

- Pipelined IP-protocol probes serialize overlapping reply identities, including
  repeated attempts and IPv6 extension probes, so responsive protocols retain
  positive evidence.
- Strict IPv6 extension builds still require their declared child headers;
  IP-in-IP replies retain positive evidence when an inner packet contains an
  ICMP error.
- IP-protocol replies resolve IPv6 extension chains while retaining extension
  protocol probes. Portless scans consume exclusions applied to their active
  TCP, UDP, or SCTP discovery transports.
- Composed IP discovery consumes shared protocol exclusions before selecting
  port-scan endpoints. SCTP and IP-protocol native acceptance builds and executes
  all Linux profiles in an isolated link fixture and rejects missing or duplicate
  evidence inventories; its commands use the capture queue and byte limits.
- Bounded benchmark execution keeps child reaping in the measurement thread
  when output overflow kills a process.
- Service identification handles reply-code-only SMTP terminals, final
  permitted SMTP/FTP continuation lines, uncoded FTP multiline banners, fatal
  TLS alerts after completed reads, CHAOS TXT class retention, and YAML
  deserialization budgets (RUSTSEC-2026-0333).
- Scan follow-ups share the client deadline, propagate reverse-DNS cancellation
  and pacing errors, narrow per-question DNS capture settings, and preserve
  configured neighbor bounds.
- Preserve authorization before active discovery, final-wire validation, exact
  unknown/reserved/padding bytes, HTTP/2 delayed frames and GOAWAY qualification,
  staged output directory binding, and forwarding violation precedence.

### Removed

- Redundant compatibility workspaces, signature-diff and coverage workflows,
  `AGENTS.md`, `docs/roadmap/`, and unmaintained local harnesses outside
  CI/release validation.

## [0.5.0-beta.3] - 2026-09-08

See [docs/migration-beta.3.md](https://github.com/tyk-swe/pcr/blob/1e3faf61fe510d6e6be6ba7a7bcb933f4def3632/docs/migration-beta.3.md) for the migration
guide and [docs/analysis-resources.md](https://github.com/tyk-swe/pcr/blob/1e3faf61fe510d6e6be6ba7a7bcb933f4def3632/docs/analysis-resources.md) for the
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
