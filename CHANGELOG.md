# Changelog

All notable changes to PacketcraftR are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `build` and `dissect` expose `--max-layers` and `--max-packet-size`, and
  `traceroute` exposes a validated `--source-port` for UDP and TCP probes.
- DNS queries and decoded records support CAA (type 257), and streamed scan
  completion records report final open, closed, filtered, unreachable,
  unknown, and timeout endpoint counts.
- `interfaces --interface NAME_OR_INDEX`, `routes --all`, and `stats --top N`
  add focused selection controls; interface text rows now include MTU,
  capability, link type, MAC address, flags, and description.
- Long `--version` output lists the enabled native feature set without adding
  a runtime dependency.
- `stats` and `expert` accept the shared, repeatable `--tls-port` option, so
  their protocol accounting and display filters can recognize per-frame TLS
  layers on non-default TCP ports.
- Text `expert` output reports deterministic per-code finding counts before
  its final severity summary.
- Text, hex, and raw `dissect` output reports a filtered-out frame on stderr
  while retaining empty stdout and a successful exit status.
- Fuzz targets `packet_build` (expression and document parsing into every
  encoder, both modes, with a decode round trip) and `tls_session` (captures
  through TCP reassembly into the TLS session collector); `filter_parse` now
  evaluates compiled filters against a fuzzed frame instead of an empty one.
- The root `--help` and the README document the exit-code contract (2 cli,
  3 packet, 4 capability, 5 io, 6 policy, 70 internal); a test keeps the help
  table equal to the code that maps error kinds to exit codes.
- A test that fails when a property in `schemas/packetcraftr.output.v1.schema.json`
  is serialized by no `examples/documents/output-*.json`, so consumers generating
  strict types from the examples see every field; the few live-only properties
  carry a reason in the test. New examples cover `stats --table io`, `--table
  ports`, `--table protocols` and `--table endpoints`, `read --dissect`, a
  dissection with a field-level diagnostic, a DNS `any` response with EDNS,
  SOA, NS, MX and unknown-type records plus an undecoded reply, DNS CNAME, PTR
  and SRV record events, scan and traceroute undecoded-frame events, a scan
  probe response, and TLS sessions ended by a fatal alert or a truncated
  capture; the exchange, traceroute and DNS `complete` examples now carry a
  decoded response, an undecoded frame, and EDNS metadata respectively.
- `packetcraftr_core::protocol::application::dns::name`: one bounded DNS name
  decompressor, with a typed failure enum and a caller-supplied
  compression-pointer ceiling. The built-in DNS-over-UDP dissector and the DNS
  workflow's message codec each carried their own copy of the pointer walk, the
  63-byte label cap, the 255-byte expanded-name cap and the pointer ceiling —
  two chances to get a decompression bomb wrong, and their failure vocabularies
  had already drifted apart. Both now call the shared decoder and keep their own
  presentation escaping and their own error mapping, so every published byte is
  unchanged; `packetcraftr::dns::WireError` gains `From<name::Error>` for the
  translation. A `dns_name` fuzz target covers the shared decoder.
- A test that fails if any file outside `crates/packetcraftr-netio/src/platform/`
  re-enables `unsafe_code`. The workspace's central safety claim previously
  lived only in AGENTS.md and in a comment at the `packetcraftr-netio` crate
  root, so a new opt-out anywhere else would have compiled silently.
- `#[test] fn the_command_tree_is_valid`, which runs clap's `debug_assert()`
  over the whole command tree. `fuzz` adjusts sixteen arguments by id, eleven
  of them defined in other modules, and the tree is rebuilt on every
  invocation — so renaming any of those fields turned *every* `packetcraftr`
  invocation into a clap panic, and nothing exercised the tree at unit-test
  speed.
- `expert` and `follow` bound what their aggregate JSON document retains, at
  `--max-frames`, instead of pushing every finding or payload chunk
  unconditionally. One frame can raise several findings, so the frame budget
  alone did not bound the document. A document that leaves anything out now
  carries an `expert.findings_omitted` or `follow.chunks_omitted` warning
  diagnostic saying how many, so a truncated document never reads as complete.
  Text and NDJSON write each item as it completes and are unaffected.
- `netio::capture::OverflowPolicy::as_str`/`Display`, and `as_str`/`Display` on
  `output::network::LinkMode` and `output::network::Capability`, each returning
  the one spelling the serialized document and the CLI flag already use.
- `analysis::pcap::Limits::advance` is public. `read` now charges its frames
  through the same two ceilings the rewrite copy and the analysis loop charge
  through, instead of a hand-written copy of the same arithmetic and the same
  two error variants.
- `output::read::Frame`, the record `output::read::Event::Frame` carries, so a
  per-frame renderer takes the record it can receive rather than the whole
  event. Every emitted byte is unchanged.
- A conformance test that serializes a real Rust value of every aggregate
  payload — one per command whose `formats()` offers JSON, plus a branch case
  for each optional half — and validates the emitted envelope against
  `schemas/packetcraftr.output.v1.schema.json`. 121 of the schema's 122
  `additionalProperties` declarations are `false`, so one added `pub` field on
  any payload breaks every consumer; until now only hand-written example
  documents were validated, and no test ever serialized an aggregate type.
- `output::frame::Timestamp` implements `Display`, carrying the inverse of the
  pre-epoch floor-seconds encoding that `Timestamp::try_from` applies, with the
  round-trip test the rule never had. The rule previously lived only in the
  CLI's renderer, two crates from the encoding it inverts.
- `output::stream::write_unattributed_error`, which publishes the one
  command-less NDJSON error record a failure before command selection can emit.
- A test pinning every enum whose serialized names the output schema freezes —
  including the ten re-exported straight out of a domain module, where renaming
  a variant is a wire break with nothing in between — against the vocabulary
  the schema declares, in value and in order.
- A test asserting that every error code in the published `output-*-error.json`
  documents carries its failure class as its own prefix, and that no code is
  published under two classes.
- `--max-tcp-bytes-per-flow`, `--max-tcp-reassembly-bytes`,
  `--max-tcp-segments-per-flow`, and `--tcp-idle-expiry-ms` on `stats`,
  `expert`, `follow`, and `tls`. The four TCP reassembly ceilings behind them —
  including the 256 MiB aggregate, the largest single memory ceiling in an
  analysis run — were previously hardcoded and unreachable from any caller.
  Every default equals the value the pipeline used before, so an unconfigured
  run is unchanged.
- Bounded, capture-global IPv4 and IPv6 fragment reassembly with explicit
  `reject`, `first`, and `last` overlap policies; separate physical/derived
  accounting; derived transport participation in filters, stream indexing,
  follow, TLS, and expert analysis; incomplete idle/EOF outcomes; shared CLI
  ceilings; and a dedicated fuzz target.
- Bounded DNS UDP-to-TCP fallback: one validated truncated UDP response may
  continue over length-prefixed TCP to the same reauthorized numeric server
  within the original attempt deadline. `packetcraftr dns --udp-only` retains
  the prior UDP-only diagnostic behavior and is required for scoped IPv6
  link-local servers.
- Nine implementation fuzz targets, property coverage for document, capture,
  filter, layout, reassembly, and TLS behavior, plus non-gating Criterion and
  peak-RSS measurement harnesses.
- `DocumentLimits` and `Packet::parse_with_limits`, enforcing matching bounded
  JSON/YAML semantics before retained values are allocated.
- Weekly dependency-policy checks and a portable smoke check for the
  repository-backed Quick Start commands.

### Changed

- The `build` CLI reports `--max-layers` and `--max-packet-size` breaches as
  `packet.build_resource_limit` (exit 3); the core library retains its policy
  classification for callers that enforce the same finite resource budget.
- **BREAKING:** ephemeral-port helpers and `ExchangeExecutor` now have the
  single canonical paths under `packetcraftr::probe`; their former
  `packetcraftr` root re-exports are removed.
- **BREAKING:** `traceroute::Request` adds `source_port`, `scan::Summary` adds
  `counts`, and the `packetcraftr_core::document::DEFAULT_MAX_DOCUMENT_NESTING`
  alias is removed; use `MAX_DOCUMENT_NESTING` instead. Downstream struct
  literals must initialize the new fields.
- **Breaking:** `replay` and `fuzz --live` spell the permissive-live opt-in
  `--allow-permissive-live`, the same flag `send` and `exchange` already use for
  the same policy field; `--allow-malformed-live` remains as a hidden alias.
- `--max-unsolicited` on `exchange` names its value `COUNT`, and the help for
  the offline `--max-bytes` reader bound and the live `--max-bytes` traffic
  budget now say which subsystem each one limits.
- Test suites and comments follow the repository conventions: `packetcraftr-core` integration tests share fixtures under `tests/common/` and are split into files under ~600 lines named `*_contracts.rs`; the offline fuzz engine tests moved to `tests/fuzz_engine_contracts.rs`; `packetcraftr-netio/tests/error_contracts.rs` documents its per-enum tables; source comments state invariants instead of history, and `AGENTS.md` records the module layout and naming vocabulary.

- **BREAKING:** `packetcraftr::Stats::checked_add_assign` reports overflow as `Err(StatsOverflow)` instead of `None`. The `output::envelope::{Aggregate, AggregateError}` aliases are gone (use `Envelope`), the NDJSON encoder and unattributed error record now live in `packetcraftr::output::stream`, and the offline fuzz statistics conversion moved next to `output::fuzz`. Private workflow modules named `contract.rs` under `policy`, `send`, and `target` are now `model.rs`.

- Consolidated the workflow crate's internals: the exchange now lives in eight cohesive modules instead of fourteen, the transmission pipeline (`plan_and_authorize`, `materialize_and_authorize`) sits on `Client` next to the gates it applies, and the replay system boundary is `replay::{authorizer, transmitter}`. No public paths changed.

- **BREAKING:** live workflows share one executor boundary: `packetcraftr::probe::{Request, Executor}` replaces the separate `scan::Executor<Probe>`, `traceroute::Executor<Probe>`, `dns::Executor`, and `fuzz::Executor` traits (the names remain as re-exports of the shared trait, keyed by `scan::Batch`, `traceroute::Batch`, `dns::Exchange`, and `fuzz::ExecutionCase`); DNS-over-TCP continuation moved to `dns::TcpExecutor`, and a fuzz `ExecutionCase` now carries its own timeout instead of a second `execute` argument.

- **BREAKING:** scan and traceroute share one probe skeleton under `packetcraftr::probe`: `probe::Error { workflow, kind }` with `ErrorKind` and `Workflow` replaces `scan::Error` and `traceroute::Error` (the published codes and remediations are unchanged), `probe::{Transport, ProbeEndpoint, ProbeStatus}` replace the duplicated scan/traceroute enums (`traceroute::Strategy` and `traceroute::ProbeTarget` remain as aliases; `ProbeTarget::strategy()` is now `transport()`), and evidence retention, diagnostics, and batch validation live in one shared state type.

- `packetcraftr-netio` platform internals share one worker-join helper (`platform::worker_reaper::join_with_deadline`), the capture queue plans oldest-first eviction separately from admission, the neighbor resolver keeps evidence in one `EvidenceBuffer`, `neighbor::Options::capture_limits()` exposes the discovery capture bounds, and the macOS and Windows route backends share `route_normalize::constrain_by_preferred_source`. The Npcap loader binds its symbols through one `load_symbols!` macro and the interface-identity module only opts out of `unsafe_code` on Linux and macOS.
- **BREAKING:** `packetcraftr_netio::PacketIo { sender, capture }` replaces the `(sender, capture)` tuple implementations of `transmit::Sender` and `capture::Provider`, and `transmit::Dispatch` is now `transmit::ModeSender`.
- `packetcraftr-netio` now resolves native capabilities through build-script `cfg` flags (`native_route`, `pcap_backend`, `npcap_backend`, `native_layer3`, ...) and a single `platform::dispatch` module instead of five per-capability dispatch files. Platform backends are named after the operating-system facility they use (`netlink`, `af_route`, `iphelper`), route normalization lives in `platform::route_normalize`, and rules shared by the libpcap and Npcap backends live in `platform::pcap_common`. Npcap on targets other than x86_64 MSVC is now reported by the generic unsupported-capability message. No public API or error code changed.
- **BREAKING:** `Registry` lookups take protocol names as `&str` and return `layer::Id` by value; `BuiltinProtocol::from_id` takes an `Id` by value; `codec::DecodedLayerValue` is now `codec::DecodedLayer`. Reassembly `contract` modules are named `model`, `Padding::excluded_from` is the single padding-exclusion rule, and offline analysis no longer materializes filter inputs when no filter is set.
- Codecs and analyzers identify layers through `BuiltinProtocol::identifies` and name IP protocol numbers through `packetcraftr_core::protocol::network::ip_protocol` instead of comparing protocol names as strings and repeating numeric literals.
- **BREAKING:** `Diagnostic::code` and `Diagnostic::field` (core and output mirrors) are now `&'static str`; diagnostic codes come from a fixed published set, and `Diagnostic::{info, warning, error, at_field}` take static names.
- **BREAKING:** `packetcraftr_core::layer::Id` is a `Copy` handle over a static protocol name: `Id::new` takes `&'static str`, `From<String>` and `Deserialize` are gone, and run-time names resolve through `Registry::protocol_named`. `layer::Malformed::intended_protocol` is `Option<String>` and `packet::semantics::Error::MalformedMayHideDestination` carries the name as text.
- The workflow crate no longer panics on internal invariants: live response timestamps come straight from the validated capture frame, execution permits use a monotonic counter, and the replay, exchange, fuzz, and materialization paths report impossible states as errors instead of aborting.
- **BREAKING:** `packetcraftr_netio::Error::Encapsulation`, which nothing raised, is removed. Native interface snapshot validation reports `route::SystemError::InvalidResponse` instead of a bare string; the published interface-discovery message is unchanged.
- **BREAKING:** `packetcraftr_core::error::Classified` now requires `std::error::Error` and derives `causes` from the retained source chain by default; only dual-failure and snapshot types override it. `fuzz::TargetParseError` is an enum naming the rejected part of a `LAYER.FIELD` target, and `document::Error::Field` reports a required-field failure without wrapping it in `codec::Error`. `analysis::Error`, `fuzz::Error`, and `progress::EmitError` convert from `budget::DeadlineExceeded`. The registry, builder, fuzz preparation, and follow engines no longer contain reachable panics.
- **BREAKING:** link-layer identity types now live in core as `packetcraftr_core::packet::link::{MacAddress, VlanKind, VlanTag}`; `packetcraftr_netio::link` re-exports them, and `packet::semantics::vlan_tags` returns `Vec<VlanTag>` directly (the `VlanMetadata` wrapper and `vlan_metadata` are gone).
- **BREAKING:** the built-in protocol table is a single source of truth: `packetcraftr_core::protocol::support` was removed in favour of `BuiltinProtocol::ALL`, `BuiltinProtocol::is_constructible`, and `BuiltinProtocol::exact_round_trip`; capture link-type roots are published as `protocol::capture::BUILTIN_CAPTURE_ROOTS`.
- **Breaking:** `packetcraftr_core::Packet` now lives in the public `packetcraftr_core::packet` module, and the formerly hidden IP semantics (`IpPath`, `TransportKey`, `outer_ip_path`, `live_destinations`, VLAN metadata) are published as `packetcraftr_core::packet::semantics`. The semantics no longer panic on unexpected address families; every failure is reported through `semantics::Error`.

- **BREAKING:** the DNS-over-TCP exchange moved from
  `packetcraftr_netio::dns_tcp` to `packetcraftr::dns::tcp`. It is portable
  `std::net` code with no native dependency and one consumer, the DNS
  workflow, so it no longer sits in the native-I/O crate or behind the
  `native-route` feature: an offline-only build now performs TCP fallback
  instead of returning `Error::Unsupported`.
- **BREAKING:** the progressive-output runtime moved from
  `packetcraftr_core::progress` to `packetcraftr::progress`. Nothing in the
  core crate consumed it — it is workflow-crate infrastructure, and hiding it
  behind `#[doc(hidden)]` only obscured that. The offline fuzz campaign now
  publishes through `packetcraftr::fuzz::run_offline_with_events`;
  `packetcraftr_core::fuzz::run_observed` (formerly `run_with_events`) takes a
  deadline-aware observer and no runtime. `DeadlineExceeded` implements
  `Display`/`Error`, and `progress::EmitError` is a `thiserror` enum whose
  variants convert `From` their payloads.

- **Breaking (CLI text):** human output no longer prints library enums through
  `Debug`. A diagnostic line reads `warning tcp.retransmission: ...` rather
  than `Warning tcp.retransmission: ...`, matching the `"warning"` the same
  field has always carried in JSON; `expert` findings, `plan`/`send`/`replay`
  link modes (`layer2`, not `Layer2`), `routes` capabilities (`layer2_and3`),
  `read`'s capture-rewrite message (`pcapng`), and the capture overflow-policy
  diagnostic (`drop-oldest`, the spelling `--overflow-policy` accepts) follow
  the same rule. Terminal colour is no longer chosen by string-matching the
  rendered line either: severity colour keys off those three serde spellings,
  and success colour is a property of the summary-line call site rather than a
  ten-word list of verbs that a `stats` row or a `follow` payload line could
  match by accident. The two summary lines that open with `matched` — `capture
  --filter`'s and `stats`' — gain the success colour every other summary line
  already had; those are the only colour additions.
- `capture` and `replay` classify a capture-file writer failure the same way
  `send` and `exchange` already do: a broken stdout consumer is `io.stdout`
  with its remediation instead of the codeless `io.runtime` `capture` used to
  report, and a writer budget or metadata failure keeps the capture error's own
  class (`policy.capture_stream_limit`, exit 6, rather than exit 5) — the class
  `replay` already reported for the identical condition.
- `read` rejects `--filter` with `--output pcap`/`pcapng` before it compiles the
  filter, so `--output pcapng read x.pcapng --filter '(ethernet'` reports the
  incompatibility rather than a syntax error for a filter the command would
  have refused anyway.
- **Breaking (library):** the sixteen output payload modules stop declaring
  types the frozen schema already treats as one. `output::replay::Interface` is
  gone in favour of `output::network::InterfaceId` and `output::replay::LinkMode`
  in favour of `output::network::LinkMode` (renamed from `network::Mode`) —
  both pairs already resolved to `$defs.interfaceId` and `$defs.linkMode`.
  `output::follow::Endpoint` and `output::tls::Endpoint` are re-exports of one
  `output::network::Endpoint`, matching the byte-identical
  `$defs.followEndpoint` and `$defs.tlsEndpoint`. The two `$defs` stay in place
  so no `$ref` a consumer holds moves, and every emitted byte is unchanged.
- **Breaking (library):** `output::build::Report` and `output::dissect::Report`
  carry a flattened `frame: output::frame::Wire` instead of each re-declaring
  `bytes_hex`/`length` plus a `bytes()` accessor. `Wire` formats hexadecimal at
  serialization, so a built or dissected packet no longer retains a second
  owned copy at twice the packet's size for the life of the result. The two
  emitted keys and their order are unchanged.
- **Breaking (library):** the ten DNS response-header fields declared three
  times — on `output::dns::Report`, again on `Event::Complete`, and again on a
  private struct — become one `output::dns::ResponseSummary` carried as
  `#[serde(flatten)] response: Option<ResponseSummary>`. Serde emits the inner
  fields when a response was accepted and nothing when none was, reproducing
  `output-dns-success.json` and `output-dns-complete.json` byte for byte.
- **Breaking (library):** `output::scan::Probe.protocol`,
  `output::scan::Endpoint.transport`, and the three `output::traceroute`
  `strategy` fields are the closed enums their schema entries always declared
  (`scan::Protocol`, `scan::Transport`, `traceroute::Strategy`) instead of
  `String`. The scan text renderer no longer decides its endpoint label by
  string-matching `"icmp"`. Every serialized name is unchanged.
- **Breaking (library):** `output::envelope::Aggregate<T>` and the private
  `Stream<T>`, which declared the same six fields and each their own
  `success`/`error`/`with_stats`, collapse into one `Envelope<T>` with an
  `Option<u64>` sequence; `Aggregate<T>` and `AggregateError` remain as
  aliases. `StreamEncoder::new` takes a `Command` rather than an
  `Option<Command>`, and the encoder's state moves under the mutex it already
  held, so a record is written, the sequence advanced, and the state settled as
  one step. Every emitted key is unchanged.
- **Breaking (library):** `output::protocols::Field` converts through
  `TryFrom<&FieldSchema>` and `FieldKind::from_core` returns an `Option`,
  replacing an `unreachable!` that a safe public `From` could reach the moment
  core's `#[non_exhaustive] FieldKind` gained a variant. `protocols --detail`
  now reports `internal.field_kind` instead of aborting; no current field kind
  can produce it.
- **Breaking (library):** `output::dissect::AggregateResult::from_filter(matched,
  dissection)` becomes `new(Option<Report>)`, so the `matched` flag can no
  longer disagree with the dissection beside it.
- **Breaking (library):** `exchange::Options` carries one
  `capture: netio::capture::Limits` in place of `max_capture_queue_frames`,
  `max_captured_bytes`, and `capture_overflow_policy`, and its `snap_length` is
  now the explicit snapshot length instead of `decode.max_packet_size` doubling
  as one. The same four numbers are no longer copied onto the internal
  `Prepared` and `Transaction` values, where the drain read one copy and
  retention accounting the other, so a workflow that mutates a cloned
  `Options` after validation can no longer arm a provider with limits the rest
  of the exchange does not use. Every default is unchanged.
- **Breaking (library):** `policy::Error::InvalidAddressLimit` replaces
  `target::Error::InvalidAddressLimit`, and `Policy::validate` returns
  `Result<(), policy::Error>`. Checking whether `max_resolved_addresses` is in
  range is a pure policy question, and three CLI call sites — `replay` among
  them, which never resolves a target at all — reached it before any target
  existed. The code, kind, message, and exit code are unchanged.
- **Breaking (library):** `Client::send` and `Client::exchange` validate the
  client's own `Policy` before anything else, exactly as
  `PolicyAuthorizer::authorize_operation` already did for scan, DNS,
  traceroute, and fuzz, so both authorization front doors refuse a malformed
  policy identically. `Client::policy()` exposes the policy a client applies.
- **Breaking (library):** `replay::Transmitter::validate_interface` becomes
  `plan_frame`, returning the materialized `route::Materialized` the engine
  hands straight back to `transmit(&route, frame)`. "The bytes on the wire are
  routed by the plan that was authorized" is now structural instead of the
  transmitter re-finding its own plan by comparing whole `Frame` values against
  remembered ones; `SystemTransmitter` keeps only its interface cache, and both
  "frame/route was not validated before replay transmission" errors are gone
  with the state that produced them.
- **Breaking (library):** `replay::Limits::max_frames` and `max_bytes` are
  `max_source_frames` and `max_transmitted_bytes` — the first bounds frames
  *read*, including the ones a `--filter` skips, the second only bytes that
  reach the wire — and `Error::FrameLimit`/`ByteLimit` follow as
  `SourceFrameLimit`/`TransmittedByteLimit`. `Limits::from_policy` replaces the
  CLI's hand-copying of the policy budget into those fields, and `Limits` no
  longer derives `Serialize`/`Deserialize`, which nothing used and which pinned
  the old field names. Messages, codes, and accepted values are unchanged.
- **Breaking (library):** `authorization::SocketBudget` drops `max_duration`,
  which no authorizer enforced and which DNS already enforces on its own
  attempt deadline, and gains `SocketBudget::none()` for an operation that
  opens no socket. `authorization::DeclaredPackets` borrows `&[&Packet]`
  instead of a slice of owned packets, so authorizing a campaign stops deep
  cloning every built packet — ten thousand `Vec<Box<dyn Layer>>` clones in a
  10,000-case run — for a loop that only reads declared destinations.
- **Breaking (library):** `netio::route::Error::RouteLookup` and
  `InterfaceLookup` retain the provider failure as a `#[source]` instead of
  flattening it into a `message` string, so the chain reaches
  `Classified::causes`, which is now walked from that chain rather than
  hand-written. `packetcraftr_core::error::source_chain` is the shared walk.
  Both errors keep their exact published messages.
- **Breaking (library):** every failure a platform refusal produces now retains
  that refusal as a `#[source]` instead of formatting it into a `message`
  string. `netio::Error::{Unsupported, InterfaceDiscovery, MissingDependency,
  Device, Privilege, Send, Capture}` and
  `netio::route::SystemError::OperatingSystem` carry an
  `Option<netio::SystemFault>` — an `Arc<dyn Error + Send + Sync>`, shared
  rather than boxed so `netio::Error` stays `Clone` for the capture session
  that hands its terminal failure out repeatedly, while still retaining the
  non-`Clone` `io::Error`, `pcap::Error`, and Npcap loader failures.
  `netio::dns_tcp::Error::{Connect, Write, Read}` carry the same optional
  source, and `ConfigureTimeout` a required one in place of the `message` that
  could only have restated it. `packetcraftr::target::Error::Resolver` retains
  the socket lookup failure, and the `Clock` variant of `replay`, `scan`,
  `traceroute`, `dns`, and `fuzz` retains the injected clock's own error. The
  libpcap, Npcap, raw-socket, netlink, macOS routing-socket, Win32, and
  worker-cleanup adapters all pass their typed failure through instead of
  `format!`ing it.
- **Breaking (library):** because a retained system failure is not comparable,
  `netio::Error`, `netio::neighbor::Error`, `netio::route::SystemError`,
  `netio::dns_tcp::Error`, and `packetcraftr::target::Error` no longer derive
  `PartialEq`/`Eq`. Nothing outside tests compared them, and `matches!` never
  needed the derive. `netio::route::Error::Neighbor` and the two live-I/O
  failures in `packetcraftr::Error::OperationAndCaptureShutdown` are boxed, so
  a neighbor failure's captured discovery evidence and a paired
  operation/cleanup failure no longer set the size of every route or workflow
  `Result`.
- **Breaking (CLI/output):** a failure that now retains its source stops
  restating it in `message`, and the platform text is published in `causes`
  instead. `capture` on an interface it cannot open reports `capture failed:
  could not open lo through libpcap` with `"causes": ["libpcap error: ..."]`
  rather than one line carrying both, and `send` without raw-socket privileges
  reports `live packet I/O requires additional privileges: opening a raw IP
  socket` with `"causes": ["Operation not permitted (os error 1)"]`. The
  `Clock` failures, `hostname resolution for <name> failed`,
  `DNS-over-TCP could not configure the <phase> timeout after N phase byte(s)`,
  and `packet transmission failed: replay route selection failed` — the
  Layer 3 `replay` route lookup, which publishes the adapter's own
  `no route to <destination> was found` in `causes` — lose the trailing
  `: <system text>` for the same reason. The published
  `examples/documents/output-capture-error.json` and `output-send-error.json`
  are those two failures, so the contract's `causes` array is demonstrated
  rather than only declared.
- **Breaking (library):** `Classified::causes` is derived with
  `packetcraftr_core::error::source_chain` at all 19 implementations that
  retain sources, up from the one that adopted it when the helper landed; the
  remaining hand-written lists are the two dual operation/cleanup failures,
  which carry two unrelated errors and so have no single chain, and the two
  value types (`BoundaryError`, `fuzz::CaseFailure`) that carry a captured
  snapshot. `source_chain` now skips a link whose `Display` is identical to the
  link above it — what `#[error(transparent)]` and `BoundaryError::from_error`
  both produce — so a wrapper never publishes the same sentence twice.
- `packetcraftr dns` states the same authorization shape for every query, with
  an empty socket budget when `--udp-only` is in effect. A query-count or
  query-byte overrun therefore always reports `policy.traffic_unit_limit` or
  `policy.traffic_byte_limit`; previously the identical overrun reported
  `policy.packet_limit` or `policy.byte_limit` when TCP fallback was off and
  the traffic-unit codes when it was on, so one condition had two codes
  depending on a runtime flag. The exit code (6) is unchanged.
- The exchange publishes one message for the unsolicited/undecoded retention
  ceiling. Both retention paths emitted the same `exchange.unsolicited_limit`
  code with different wording, and diagnostics are deduplicated by code, so
  whichever path reached the limit first decided what the operator saw for the
  same condition.
- Response correlation treats the exchange deadline instant itself as inside
  the operation, which is the convention the send, drain, and capture-eligibility
  paths already used. A frame arriving in the same nanosecond as the deadline is
  no longer simultaneously eligible for correlation and declared uncorrelatable.

- **Breaking (library):** `analysis::Limits` carries the four TCP reassembly
  budgets beside the IP ones — `max_tcp_bytes_per_flow`,
  `max_tcp_reassembly_bytes`, `max_tcp_segments_per_flow`, and
  `tcp_idle_expiry` — and `validate` refuses each at zero, refuses a zero or
  out-of-range `tcp_idle_expiry`, and refuses a per-flow window at or above the
  TCP serial half-space before any input is read, where that last check
  previously surfaced only as a runtime `InvalidWindowLimit` from the first
  pushed segment.
- **Breaking (library):** the fused `reassembly::Limits` is split into
  `reassembly::ip::Limits` and `reassembly::tcp::Limits`, each with only the
  ceilings its engine enforces and without the now-redundant `max_ip_`/`tcp_`
  prefixes, so neither pipeline construction site fills the other engine's half
  with `..default()`. `reassembly::tcp::MAX_BYTES_PER_FLOW` names the per-flow
  window ceiling the engine enforces.
- **Breaking (library):** `reassembly::tcp::Error` splits into
  `Resource(ResourceError)` and `Malformed(MalformedError)`, matching
  `reassembly::ip::Error`. The analysis classifier is now an exhaustive match
  with no catch-all, so a future TCP resource failure cannot be reported as
  `packet.reassembly` with advice to inspect the flow instead of raising a
  budget; TCP resource failures name the `--max-tcp-*` budgets in their
  remediation. Every existing variant keeps its message, code, and kind.
- **Breaking (library):** `analysis::FrameRecord` carries the `timestamp` the
  pipeline validated and the `tcp_layer`, `tcp_header`, `tcp_payload_len`, and
  `udp_layer` values the pipeline already located, so consumers stop re-walking
  the layer stack; an `expert` run did six or more such walks per frame.
  `analysis::stats::Collector::observe` is infallible as a result.
- **Breaking (library):** the four analysis collectors close their pass with
  one `finish(self, summary: &analysis::Summary)`. `expert::Collector::finish`
  no longer takes a positional `end_number: u64`, where passing
  `frames_matched` instead of `frames_read` compiled and silently
  misattributed every trailing finding.
- **Breaking (library):** `StreamTransport` and `StreamRef` moved to the
  `analysis` root, and `stats::TransportKind` and `follow::Selector` — the same
  enum and the same struct declared a second time — are gone. `follow` is
  selected with a `StreamRef`, `StreamTransport::as_str` is its filter
  spelling, and its `Display` delegates there.
- **Breaking (library):** `analysis::IpDatagramOutcome::Incomplete` wraps
  `reassembly::ip::IncompleteDatagram` instead of restating its seven fields.
  No published document changes shape.
- **Breaking (library):** `reassembly::ip::Error` gained `Inconsistent`,
  classified `internal.ip_reassembly`. The engine's family-mismatch and
  post-completion guards route to it, so a defect in reassembly stops reaching
  the operator as `packet.reassembly` — "your capture is malformed" — and an
  IPv6 family mismatch stops being reported as an invalid IPv4 header.
- **Breaking (library):** the classic-PCAP and PCAPNG writers take their
  aggregate `stream_limits` in `PcapOptions`/`PcapNgOptions`. `Writer::set_stream_limits`
  is gone: a stream's budget is fixed at construction and cannot be retuned
  part-way through committed output. `Writer::frames_written` and
  `Writer::captured_bytes_written` report what a writer has committed, which
  is how a refused record is observed to have committed nothing.
- **Breaking (library):** `pcap::Reader::size_limit` is gone; it was an
  accessor for a value the caller supplies in `ReaderOptions` and had no
  consumer.
- **Breaking (library):** `netio::capture`'s `DEFAULT_CAPTURE_QUEUE_FRAMES` and
  `DEFAULT_CAPTURE_QUEUE_BYTES` are now `MAX_CAPTURE_QUEUE_FRAMES` and
  `MAX_CAPTURE_QUEUE_BYTES`, joined by a new `MAX_SNAP_LENGTH`, because
  `Limits::validate` enforces all three as hard ceilings rather than as
  defaults. `validate` no longer borrows `packetcraftr-core`'s
  `frame::DEFAULT_SIZE_LIMIT` as this crate's maximum, and the scan,
  traceroute, DNS, fuzz, and exchange request modules cite the renamed
  ceilings. Every accepted value is unchanged: a `DEFAULT_*` constant now names
  a starting value and nothing else.
- **Breaking (library):** `validate` on a `packetcraftr-netio` limits or
  options type checks and returns nothing. `capture::Limits::validate`,
  `capture::Statistics::validate`, `neighbor::Options::validate`, and
  `exchange::Options::validate` are all `(&self) -> Result<(), Error>`.
- **Breaking (library):** `capture::Statistics::has_loss` is gone;
  `evidence_loss_error()` is the single typed answer, removing the two
  `.expect("lossy capture statistics must produce a typed error")` calls the
  predicate/accessor pair forced in two crates.
- **Breaking (library):** `dns_tcp::Provider` and `dns_tcp::SystemProvider`
  became the free function `dns_tcp::exchange`, and a new `dns_tcp::Category`
  with `Error::category()` replaces the four `is_*` predicates. `Classified` is
  an exhaustive match over that category with no fallback, so a new variant is
  a compile error instead of being silently reported as
  `internal.dns_tcp_request`, and the DNS workflow classifies executor failures
  from the same category. Every existing variant keeps its code and kind.
  `dns_tcp::Response` dropped `started_at` and the `bytes_read` field that
  equalled `frame.len()` by construction.
- **Breaking (library):** `VlanKind`, `VlanTag`, and `MAX_VLAN_TAGS` moved from
  `netio::neighbor` to `netio::link`, with `From<semantics::VlanMetadata>`;
  `netio::link::Capability::supports(mode)` is public. Serialized VLAN output
  is unchanged, because `packetcraftr::output::network` keeps its own mirror
  types.
- **Breaking (library/output):** `MissingSourceMac`, `MissingNeighborTarget`,
  and `MissingNeighborSource` moved from `neighbor::Error` to `route::Error`,
  merging with the field-less `route::Error::MissingNeighborSource` the planner
  already had, so a route defect is no longer reported through the neighbor
  error type. `route::materialize` returns `route::Error`, wrapping genuine
  neighbor failures in a new `Neighbor` variant, and
  `packetcraftr::Error::Neighbor` — which no producer could reach any more — is
  gone. The three moved variants now publish `internal.route_contract` instead
  of `internal.neighbor_invariant`; both are `Kind::Internal`, so exit codes do
  not move, and no example document or schema pins either code.
- **Breaking (library):** `netio::Error::InvalidSendEvidence` carries a closed
  `SendEvidenceFault` instead of a `String`, so its three unrelated invariant
  failures are distinguished by type rather than by matching message text. The
  frame-construction failure now reads
  `provider-accepted bytes cannot form a capture record: <cause>`.
- `netio::route::Materialized::for_prepared_layer2_frame` replaces the ten
  route fields neighbor discovery used to invent — including a lookup
  destination, a packet source, and a neighbor target that nothing reads — for
  a Layer 2 frame whose bytes are already complete.
- **Breaking (library/output):** analysis, filter, and reassembly options and
  records gained required IP-fragment limits, overlap policy, physical/derived
  views, counters, and lifecycle variants; public struct literals and
  structured follow, stats, TLS, and expert consumers must handle the new
  fields and events.
- **Breaking (library/output):** `dns::Request` now declares `tcp_fallback`;
  DNS attempt events identify their transport and optional source port, while
  aggregate/completion output reports `fallback_attempted` and the optional
  `accepted_transport` instead of a hard-coded UDP transport.
- **Breaking (library):** authorization gained `DnsOperation` and
  `SocketBudget`, separating exact raw-UDP wire bounds from finite TCP
  connection, framed-message, application-byte, and duration bounds.
- Updated all Rust dependencies and lockfiles, including Criterion 0.8,
  Noyalib 0.0.28, jsonschema 0.52, RustCrypto hashes 0.11, libloading 0.9, and
  pcap 2.5.
- **Breaking (library):** fuzz runs now take `fuzz::RunInput` instead of four
  positional arguments.
- **Breaking (library):** `replay::SystemAuthorizer::new` now receives the
  caller's `Arc<Registry>` while final-wire policy decoding remains trusted.
- **Breaking (library):** authorization requests are complete `Operation` enum
  variants built from `WireBudget`, `DeclaredPackets`, `ReplayFrame`, and
  `PermissiveLive`; incomplete/default requests are no longer representable.
- **Breaking (library):** replay transmitters return the passively selected
  `route::Plan` from interface validation, and replay authorizers explicitly
  approve that final wire route before pacing or transmission.
- **Breaking (library):** `Packet::parse_with_resource_limits` became
  `parse_with_limits`, and packet documents no longer implement
  `serde::Deserialize` directly.
- **Breaking (library):** the twenty-two public payload types named `Result`
  are now named `Report`, reserving `Result` for `std::result::Result`. This
  covers `packetcraftr_core::fuzz::Report`, the `scan`, `traceroute`, `dns`,
  `exchange`, and `fuzz` workflow reports, and every `output` payload.
  Serialized documents are unchanged: the payload type name never reached the
  wire, which still carries the payload under the envelope's `result` key.
- Capture-file stdout encoding now spools transactionally instead of retaining
  a capture-sized encoded buffer.
- Native feature implications and the pcap-free CI profile are explicit.
  Progressive callback deadlines and native-worker cleanup now remain bounded
  without releasing state still owned by timed-out workers.
- Release archives include the packet and output schemas and exercise packaged
  protocol listing plus exact build/dissect behavior before publication.
- **Breaking (library):** `protocol::builtin::registry` returns a shared
  `Arc<Registry>` built once instead of a fallible freshly-built `Registry`;
  `registry_with` and `registry_with_tls_ports` stay fallible.
- **Breaking (library):** `LayerCodec::protocol_id` returns `&'static Id`,
  `LayerCodec::aliases` is gone, and `registry::Builder::register_builtin_codec`
  is now `register_codec(codec, aliases)` with the caller owning the alias list.
- **Breaking (library):** `ResponseMatcher::matches` returns `Option<Match>`
  instead of a `MatchResult` with a `matched` flag and an unread `reason`.
- **Breaking (library):** the crate-root `Error` re-exported from `model` is
  now `PacketError`, and its unconstructed `Field` variant is gone.
- **Breaking (library):** `layer::FieldSchema` declares the alias spellings a
  field accepts, so literal construction needs the new `aliases` field.
- `codec::EncodedLayer` gained `with_fields` and `with_diagnostics`, so a
  header-only codec builds through `EncodedLayer::header` instead of spelling
  the always-empty `suffix`.
- Reflective field aliases (`dst`, `src`, `sport`, `dport`, `vid`, `op`, and
  the rest) now resolve through `Layer::field`/`set_field` as well as document
  and expression construction, so template axes and fuzz targets accept the
  same spellings a packet document does. Supplying both spellings of one field
  is still refused. Aliases stay out of `pcr protocols` field lists and out of
  the canonical filter namespace.
- **Breaking (output):** packet-domain failures now publish a specific
  `error.code` and `remediation` instead of the generic `packet.error` and
  `cli.error`. `build`, `decode`, `frame`, `expression`, and `document` errors
  each classify their own variants: `packet.unbound_layers`,
  `packet.missing_codec`, `packet.invalid_layer`, `packet.codec`,
  `packet.empty`, `packet.padding_boundary`, `packet.length_overflow`,
  `packet.frame_metadata`, `cli.expression_syntax`, `cli.expression_limit`,
  `cli.expression_protocol`, `cli.expression_field`, `cli.document_syntax`,
  `cli.document_schema`, `cli.document_limit`, `cli.document_protocol`, and
  `cli.document_field`. `examples/documents/output-build-error.json` carries
  the new code; the output schema is unchanged, since `error.code` is any
  non-empty string.
- **Breaking (output):** a build or decode failure that breaches a finite
  configured budget is now classified `policy` (exit 6) rather than `packet`
  (exit 3), under `policy.build_resource_limit` and
  `policy.decode_resource_limit`. This matches how the analysis and capture
  paths already classify the same conditions. A codec that violates its own
  contract is `internal.codec_contract` (exit 70) rather than `packet`.
- **Breaking (library):** `error::Context`'s four-`Option` struct is now the
  `error::Coordinate` enum, and `Classified::context` returns
  `Option<Coordinate>`. Every construction site already set exactly one field,
  and the externally tagged encoding is byte-identical: `{"attempt": 3}`.
  Published documents and the schema's `errorContext` are unchanged.
- **Breaking (library):** `semantics::Error` is an enum of the nineteen route
  ambiguities it previously formatted into a string newtype. Every message is
  unchanged, so the live-transmission authorization gate refuses exactly the
  inputs it refused before, and a new ambiguity now needs a variant instead of
  a prose string.
- **Breaking (library):** `BuiltinProtocol` moved from the doc-hidden
  `semantics` seam to the documented `protocol` module; `semantics` keeps only
  the route-interpretation items and is now documented as a seam for both
  `packetcraftr` and `packetcraftr-netio`.
- **Breaking (library):** `codec` owns `Mode` and `Context`, and `layout` owns
  `DEFAULT_MAX_LAYERS` and `DEFAULT_MAX_PACKET_SIZE`, so the codec extension
  contract no longer depends on the builder. All four stay re-exported from
  `build`, so existing paths still resolve.
- **Breaking (library):** `layout::FieldLayout::name` is `&'static str`
  instead of an owned `String` — fifteen allocations per IPv4 header per
  direction — and `ByteRange`, `FieldLayout`, `LayerLayout`, `PacketLayout`,
  and `Diagnostic` no longer derive `Deserialize`, which nothing used.
  Serialized JSON is unchanged.
- **Breaking (library):** `Template::expansion_len` returns `usize`; its body
  is infallible and its only caller wrote a `map_err` for an impossible error.
- `PacketLayout::layer` resolves an index by position and re-checks the stored
  index instead of scanning every layer, ending an O(n^2) lookup inside the
  analysis adapter's per-frame loops. `PacketLayout::new` debug-asserts the
  invariant in all three producers.
- `diagnostic::Severity` gained `as_str`, `Display` delegating to it, and
  `PartialOrd`/`Ord`, so `pcr expert --min-severity` compares the library enum
  directly instead of through a converted copy.
- `Packet::{push, insert, replace, get, get_mut}` and its `FromIterator` no
  longer restate the `'static` bound that `Layer: Any` already implies, and
  `layer::ReflectiveFieldError` now derives `Debug`, `Clone`, `Copy`, `Eq`,
  and `std::error::Error` like every other public error type.
- **Breaking (output):** a libpcap or Npcap refusal is classified against one
  privilege-phrase list on every target, so `capability.privilege` no longer
  depends on which backend phrased the refusal: `not permitted` and
  `administrator` were privilege failures on Windows and generic capture or
  send failures on Linux and macOS for the same condition. Every phrase the
  previous per-backend lists recognized is still recognized, so no refusal
  moves out of `capability.privilege`.
- Native Layer 2 and Layer 3 transmission verify the selected interface's
  identity with a single name lookup instead of a full native interface
  enumeration per frame. On Linux that removes a worker thread, a Tokio
  runtime, a route-netlink socket, and a complete link plus address dump from
  every transmitted packet. The verified property, the accept/reject decision,
  and the `io.device` diagnostic are unchanged; capture, which reads the
  enumerated addresses, still enumerates once per session.
- The Windows Npcap device path is built from the adapter GUID's own fields
  instead of `windows-rs`'s `Debug` formatting, which carries no stability
  guarantee and was on the path of every Windows capture and Layer 2 send. The
  rendered name is unchanged.
- The native capture session recovers from a poisoned queue mutex everywhere
  instead of reporting `io.capture` from two of six accessors; the shared state
  is plain data whose every mutation commits in one step. `capture::Session`
  and the published documents are unchanged.
- **Breaking (library):** progressive publication is scoped to a
  `progress::Runtime` a caller owns. `Sink::new` became
  `Sink::new_in(&Runtime, emit)`, `progress::MAX_WORKER_CAPACITY` replaces the
  private process-wide worker limit, and the `static OnceLock` runtime is gone
  along with the only `std::thread` use reachable from a plain
  `packetcraftr-core` call. This removes a process-global latch: cleanup
  failure used to set an `available` flag to false permanently, after which
  every later progressive operation in the process failed with no way to reset.
  `core::fuzz::run_with_events` and `scan`, `traceroute`, `dns`, and
  `fuzz::run_with_events` take a `&Runtime`, and `Client` owns one for
  `exchange_with_events`. A runtime starts no thread until its first sink is
  admitted, so composing a client that never publishes events costs nothing.
- **Breaking (library):** `fuzz::Limits::validate` is
  `(&self) -> Result<(), Error>`, matching its siblings, and enforces the new
  `fuzz::MAX_TOTAL_BYTES` and `fuzz::MAX_PACKET_BYTES` instead of citing
  `DEFAULT_MAX_TOTAL_BYTES` and `layout::DEFAULT_MAX_PACKET_SIZE` as maxima.
  Every accepted value is unchanged. `fuzz::MAX_VALUE_NESTING` names the value
  nesting bound that was a bare `64`, and the recursion depth is no longer a
  parameter every caller passed as `0`.
- **Breaking (library):** `core::fuzz::Stats` drops `packets_attempted` and
  `packets_completed`, which were unconditional aliases of `cases_generated`
  and `cases_built` in a module with no transmission seam. The output boundary
  maps the case counters onto the published packet columns, so
  `stats.packets_attempted` and `stats.packets_completed` are unchanged in
  every document.
- **Breaking (library):** `fuzz::Error::ValueTooLarge { limit }` reports a
  reflected value that does not fit the campaign's retained-byte budget.
  That path previously reported `ByteLimit { actual: limit + 1, limit }`,
  inventing an `actual` one byte over the limit for a value that may be
  megabytes. Both variants classify as `policy.fuzz_resource_limit`.
- The `boundary` fuzz strategy picks a byte-value fill from a selector bit the
  length index does not read, so all eight (length, fill) combinations occur
  instead of four. Boundary mutations of `bytes` fields therefore differ from
  earlier releases for the same seed; every other strategy, and case seeding
  itself, is unchanged.
- **Breaking (library):** `scan::Probe` and `traceroute::Probe` pair each
  transport with exactly the addressing it needs — `scan::ProbeEndpoint::{Tcp,
  Udp, Icmp}` and `traceroute::ProbeTarget::{Udp, Tcp, Icmp}` — instead of a
  transport beside an `Option<u16>` port. `Probe { transport: Tcp, port: None }`
  was constructible by any caller and made the public `Probe::packet` panic
  through an `expect` one call inside a private function, where
  `clippy::missing_panics_doc` could not see it. `ProbeEndpoint::transport()`,
  `ProbeTarget::strategy()`, and `port()` keep every published field flat, so
  no document changes. `traceroute::plan` now returns `Error::InvalidPort`
  where a UDP probe would leave the validated port range, instead of panicking
  after silently wrapping the offset to 16 bits.
- **Breaking (library):** `scan::Executor` and `traceroute::Executor` are one
  generic `Executor<P>` over the probe type; they were byte-identical modulo
  that type. Implementors write `impl scan::Executor<scan::Probe>`.
- **Breaking (library):** `Limits`, `Request`, and options types in `scan`,
  `traceroute`, `dns`, and `fuzz` follow one `validate` shape:
  `validate(&self) -> Result<(), Error>` checks and returns nothing, and is
  `pub` on every request and limits type. What used to be returned under that
  name has its own name: `scan::Request::selected_ports` and
  `dns::Request::canonical_name`, each of which validates first.
- **Breaking (library):** `dns::Limits` splits into `dns::MessageLimits` (the
  bounds the message codec enforces) and the workflow `dns::Limits` that embeds
  it as `message` beside the evidence and duration budgets. `decode_response`,
  `decode_tcp_frame`, and `classify_response` take `MessageLimits`, so decoding
  one message no longer requires a capture-queue frame count, and the codec's
  defaults no longer reach for a capture constant.
- **Breaking (library):** workflow constants drop the module name they repeat:
  `scan::{MAX_RATE, MAX_PROBES, MAX_ATTEMPTS, MAX_DURATION, DEFAULT_BATCH_SIZE,
  DEFAULT_MAX_PORTS, DEFAULT_MAX_UNDECODED_FRAMES}`,
  `traceroute::{MAX_RATE, MAX_PROBES, MAX_PROBES_PER_HOP, MAX_DURATION,
  DEFAULT_FIRST_HOP, DEFAULT_MAX_HOPS, DEFAULT_PROBES_PER_HOP,
  DEFAULT_UDP_PORT, DEFAULT_TCP_PORT, DEFAULT_MAX_UNDECODED_FRAMES}`, and the
  `dns::` equivalents, matching `fuzz::MAX_RATE`. Values are unchanged.
- **Breaking (library):** `scan::select_ports` and `scan::PortSpec` own port
  expansion, de-duplication, and the `max_ports` ceiling. The CLI parsed the
  `--ports` token syntax and then re-implemented all three, hand-copying the
  library's `exceeds max_ports=` message while constructing a
  `scan::Error` itself.
- **Breaking (library):** `dns::unpredictable_transaction_id` and
  `dns::unpredictable_source_port` own DNS query-identity randomization, which
  is spoofing resistance and was previously untested in a CLI file.
- **Breaking (library):** `PolicyAuthorizer` holds `Option<&dyn Resolver>` and
  has no type parameter; `authorization::NoResolver` is removed. A
  packet-oriented authorizer asked to resolve a hostname now reports
  `internal.target_resolution` — the caller wired a name into an authorizer
  with no resolver — instead of `policy.hostname_resolution`, blaming a policy
  that was never consulted, or `io.hostname_resolution`, advising the reader to
  inspect a resolver that does not exist. A numeric target still resolves and
  is still gated by the destination policy.
- **Breaking (library):** `dns::Exchange` drops `max_responses`, which its only
  construction site set to `limits.max_evidence_frames`; the executor now reads
  the one bound. `dns::UndecodedEvidence` drops `transport`, which had one
  possible value because DNS-over-TCP never yields captured frames. The
  published `dnsUndecoded.transport` stays the constant `"udp"`.

### Removed

- **Breaking (library):** `output::stream::EncodeError::MissingCommand` and
  `::Writing`. The first existed only because `StreamEncoder::new` accepted an
  `Option<Command>` for one error-only pre-parse path, now served by
  `write_unattributed_error`; the second could never be observed, because the
  state it reported was set and cleared under the same lock the check ran
  behind. `EncodeError` is now `#[non_exhaustive]`.
- **Breaking (library):** the `Default` derive on `output::contract::Format`,
  which nothing used. A format is chosen on the command line, so the type has
  no meaningful default.
- **Breaking (output/library):** `diagnostic::Diagnostic.range`,
  `output::envelope::DiagnosticRange`, and the output schema's
  `$defs.diagnostic.range`. The field was documented as optional but no
  producer ever set it, so no published document changes.
- **Breaking (library):** `document::Error::Serialize`, which nothing
  constructed.
- **Breaking (library):** `Summary::diagnostics` on `scan`, `traceroute`,
  `dns`, and live `fuzz`, and `fuzz::Report::diagnostics`. Every construction
  site set them to `Vec::new()` — DNS used its summary as a scratch buffer and
  cleared it before returning — so `Collector::finish`'s `extend` was a no-op
  in three workflows and no published document ever carried a value. Every
  diagnostic still reaches consumers as `Event::Diagnostic`, and a fuzz case
  still carries the diagnostics raised while it ran. No published document
  changes.
- **Breaking (library):** `fuzz::Error::MalformedLiveOptInRequired`, which
  became unreachable when the malformed-live opt-in moved to the authorizer.

### Fixed

- `routes` and `routes --all` skip interfaces without a usable MTU, so macOS
  devices that cannot supply a route decision do not abort the listing.
- Scan execution now materializes and validates one correlated probe per batch,
  preventing reused sequence and IP identifiers. Larger batch limits currently
  execute as single-probe batches, with duration budgets adjusted accordingly.
- DNS relevance filtering indexes canonical owners and bounds CNAME traversal
  work, including reverse-ordered chains and cycles.
- TLS analysis consumes final payload before clean TCP closure. Hello parsing
  rejects duplicate extensions, incomplete vectors, and trailing extension bytes,
  and distinguishes HelloRetryRequest key shares from normal ServerHello shares.
- PPPoE reassembly scopes include the direction-independent Ethernet endpoint pair.
- Explicit interface selection checks source ownership on the selected interface
  before considering other interfaces that own the same address.
- Reduced IPv6 segment routes accept `Segments Left == Last Entry + 1` and
  require and preserve the explicit outer IPv6 destination. `SegmentRoute::active_index`
  is now optional because the active segment can be absent from the list.
- Replay schedules frames against one monotonic anchor; overdue frames send
  immediately without shifting subsequent targets. Deadline preflight charges only
  the remaining anchored wait, so processing time does not cause premature rejection.
- Hostname deserialization validates and canonicalizes input through its parser.
- Quick-start checks use a private temporary directory. Deadline tests use
  scripted time for exact phase assertions and bounded loopback server I/O.

- A workflow failure over a packet-build error published no causes at all.
  `packetcraftr::Error::Build` fell into the arm that returns an empty list, so
  `send`, `exchange`, `fuzz`, and `replay` dropped the codec or field
  diagnostic the build error had retained; `dns::Error::TcpExecution` dropped
  the DNS-over-TCP chain the same way. Both now publish what they carry.
- `replay::Error::{InvalidTiming, Timing}` no longer publish a synthesized
  cause that repeated the tail of their own message. A cause is a retained
  source, not a second copy of the failure.
- `examples/documents/output-fuzz-success.json` and `output-fuzz-complete.json`
  no longer publish `"elapsed": {"secs": 0, "nanos": 0}`, a duration a campaign
  that now measures its own elapsed time can no longer produce. Each carries
  its own round placeholder instead — 500 µs and 1 ms — so the two documents do
  not read as one measurement copied twice, matching the convention every other
  published duration already follows.
- The two `dns_tcp` deadline tests no longer race the wall clock. They compared
  a fixed 10 ms scripted read delay against a 1 ms attempt deadline, so a
  scheduling stall anywhere before the delayed read reported the timeout in an
  earlier phase and failed the assertion; the scripted stream now sleeps past
  whatever budget the caller set for that specific read, so the deadline is
  crossed inside the intended phase however long the rest took.
- A failed `--interface` lookup no longer discards the selector. The live
  executor cleared the pending selector before the fallible resolution, so a
  second attempt after a transient enumeration failure would have built an
  exchange with no interface constraint at all and transmitted on whatever the
  route provider picked. The selector is now cleared only after the lookup
  succeeds, and a regression test with a once-failing provider asserts the
  second attempt still refuses.
- A live `fuzz` campaign that needs the malformed-live opt-in is now refused by
  the authorization seam rather than by an early return before it. The early
  return skipped `policy.allow_permissive_packets` entirely, so the
  authorizer's branch for that shape was dead in production and the standing
  policy allowance was never applied to a fuzz campaign. A denied campaign now
  reports `policy.permissive_live_opt_in` when `--allow-malformed-live` is
  missing and `policy.permissive_packet` when the policy does not stand behind
  permissive bytes, instead of `policy.fuzz_malformed_opt_in` for both. Both
  codes are `policy` failures with the same exit code, nothing is transmitted
  before either check, and the transmit path keeps its own independent
  permissive-live gate.
- `dns::Name`'s `Display` writes each printable byte directly instead of
  allocating a `String` per byte, on the path taken for every rendered owner
  name and every rejected record.
- DNS executor-evidence failures that the shared validator can produce but the
  DNS path was assumed never to reach are formatted like every other one,
  instead of reaching four `unreachable!` arms.
- An offline `fuzz` campaign publishes the duration it actually took as
  `stats.elapsed`. Generation measured that duration to charge the campaign
  deadline and then discarded it, so every offline campaign — including the
  published `examples/documents/output-fuzz-complete.json` — reported
  `{"secs": 0, "nanos": 0}`. The output schema is unchanged, and everything a
  campaign derives from its seed remains byte-identical between runs.
- DNS-over-TCP uses one bounded two-byte frame, deadline-aware partial I/O,
  pre-allocation message limits, exact response identity/question validation,
  deterministic retry precedence, and no synthetic captured-frame evidence.
- Replay applies final-wire source ownership policy after passive route and
  interface selection, requiring `--allow-source-spoofing` for captured IP or
  Ethernet sources the selected route does not own.
- The Quick Start capture commands use the published TLS fixture.
- `pcr protocols` no longer advertises `exact_round_trip: true` for `raw_ip`,
  whose codec is a decode-only IP-version dispatcher and always refuses to
  encode. The field is now sourced per protocol from the built-in catalog
  rather than published as a constant, and `matcher` is derived from the same
  catalog instead of a second copy of the mapping. Only that one boolean value
  changes in `examples/documents/output-protocols-success.json`; the output
  schema is unchanged.
- Pseudo-header and transport-checksum failures name the calling protocol
  (`tcp`, `udp`, `icmpv6`) instead of `transport`, which is not a registered
  protocol and has no codec.
- **Breaking (output):** a destination the Linux kernel reports as unreachable
  (`ENETUNREACH`, `EHOSTUNREACH`, `ENOENT`, or `ESRCH` from `RTM_GETROUTE`) is
  now `io.route_not_found` with the message `no route to <destination> was
  found`, exactly as it already was on macOS and Windows. The same user input
  previously produced two different machine codes depending on the host.
- A compiled libpcap BPF program is released by its owning type rather than by
  a manual `pcap_freecode` the single caller had to remember on both the
  success and failure paths.
- macOS routing-socket requests no longer panic if the monotonic clock cannot
  represent the bounded two-second deadline; they fail closed with the
  operating-system diagnostic its Linux and capture siblings already return.

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

[Unreleased]: https://github.com/tyk-swe/pcr/compare/v0.5.0-beta.2...HEAD
[0.5.0-beta.2]: https://github.com/tyk-swe/pcr/compare/v0.5.0-beta.1...v0.5.0-beta.2
[0.5.0-beta.1]: https://github.com/tyk-swe/pcr/compare/v0.4.0...v0.5.0-beta.1
[0.4.0]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.2...v0.4.0
[0.4.0-beta.2]: https://github.com/tyk-swe/pcr/compare/v0.4.0-beta.1...v0.4.0-beta.2
[0.4.0-beta.1]: https://github.com/tyk-swe/pcr/compare/v0.3.0...v0.4.0-beta.1
[0.3.0]: https://github.com/tyk-swe/pcr/compare/4754e3934284cff8f407ae5b4a2a21ed99ac6045...v0.3.0
[0.2.0]: https://github.com/tyk-swe/pcr/tree/4754e3934284cff8f407ae5b4a2a21ed99ac6045
