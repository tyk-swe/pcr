# Migrating from 0.5.0-beta.3

## CLI workflow groups

Prefer `packetcraftr <group> <command>`: `packet` for packet operations, `files`
for capture files, `analyze` for offline analysis, `network` for live operations,
and `reference` for built-in documentation. Every previous flat command remains
supported without runtime warnings. `analyze dns` is the former `dns-read`;
`network dns` is the live DNS command.

`-h` shows common options and short examples. `--help` includes every option,
default, supported format, and prerequisite. Empty root/group invocations show
help and exit 2. `packetcraftr help <group> <command>` also works.

Human text output is compact by default; add `-v`/`--verbose` for retained
evidence, provenance, and technical details. Warnings, failed checks, ambiguity,
incomplete outcomes, and omission counts remain visible. Explicit detail
selectors, including `--tree`, `--dissect`, and `--field`, remain effective.
Reference output and requested packet bytes stay comprehensive.

Workflow grouping preserves command identifiers, existing flags, defaults, exit
codes, policy enforcement, and packet/v2. Verbosity has no effect on machine/byte
formats. Current producers use output/v18, including the statistics additions below.


Net upgrade from 0.5.0-beta.3 to current `main`. See the [changelog](../CHANGELOG.md)
for additions, the [path tables](#renamed-and-removed-paths) for mechanical Rust
replacements, and [the provider cleanup](#callers-tracking-main) if you already
track `main`.

## Architecture ownership and control repairs

These repairs preserve packet/v2 and publish output/v18. Historical schema families are
unchanged. Resource diagnostics retain their existing units; the effective TCP
process ceiling is now 12, rather than 16, to reserve four native-root places
for eligible control work. Root exhaustion still refuses work. In Rust,
`tcp_connect_snapshot().capacity` now means the TCP data allocation; use
`native_snapshot()` for aggregate root ownership and the new
`execution_snapshot()` / `socket_snapshot()` for lifecycle phases.

- `Trace.runtime: None` shares the containing operation's runtime while caches
  remain fresh. Set `Some(runtime)` only when an independent root is intentional.
- `target::Resolver::resolve_controlled` is an additive cooperative hook. The
  default checks before and after legacy `resolve`; a blocked custom resolver
  remains blocked. Wrap owned legacy implementations with
  `target::BlockingResolver::new(resolver)` to bound caller waiting and unfinished
  lookup admission. The system resolver uses that bounded native ownership while
  preserving system hosts-file/NSS/search-domain lookup and first-seen order.
  Hostname policy still runs before lookup; resolved-address policy follows it.
- Capture `Session` gains `request_stop` and `shutdown_until`. Override both for
  cooperative two-phase group cleanup. Their defaults preserve legacy shutdown
  behavior and make no new preemption guarantee. Groups stop all sources first,
  then pass one independent cleanup deadline to every join. Native unfinished
  work retains its resource charge through eventual cleanup.
- `analysis::Collector::finish_controlled` is additive. Its default wraps legacy
  finalization and checks each trailing event. Implement it for large custom
  finalizers that can check the supplied effective deadline internally.
- `Sink::delivery()` defaults to `Delivery::Isolated`; arbitrary closure
  acknowledgements still control execution synchronously through the bounded
  worker boundary. Built-in collectors select `Cooperative`, consume no worker
  admission, and run on the caller thread. `Runtime::new(0)` accepts those
  collectors; it continues to refuse isolated workers. Opting a custom sink into
  cooperative delivery promises prompt callbacks, not forced interruption.
  Additive `Sink::publish_controlled(event, &Deadline)` defaults to `publish`;
  adapters can preserve effective operation control through nested waits.
  Isolated facade workers now retain admission through actual thread exit,
  callback captures, TLS destruction, and opaque panic cleanup. Cancellation
  returns without releasing unfinished work. Each independent runtime has a
  separate bounded cleanup allocation matching its worker capacity (maximum
  eight callback plus eight cleanup workers). `resources::ThreadCleanup` and
  `ThreadJoinSlot` are additive netio APIs for pre-spawn cleanup reservation and
  actual-join ownership; failed transfers stay retained and report that state.
  `resources::executor_thread_snapshot` separately reports busy/idle/retiring
  native executor slots, including completed handles awaiting dispatch pruning;
  existing resource-grant snapshot meanings are unchanged.
  Runtime snapshots count resource grants, not resident cleanup workers. See
  [resource ownership](analysis-resources.md#effective-settings-and-resource-ownership).
- Trusted CLI NDJSON sinks select cooperative delivery only when their writer is
  already isolated. Generic callback acknowledgements, text isolation, record
  order, and per-line write/flush visibility are unchanged. Effective operation
  control reaches writer waits alongside invocation cancellation, including
  invocations with no duration. Application NDJSON
  emits and charges exact compact `result` bytes in one serialization; envelope,
  diagnostics, and newline retain their previous accounting treatment. Text and
  aggregate application accounting keep the existing measure.
  Cancellation after a write starts cannot recall bytes, including an already
  started `complete` record. Such a caller returns an error and retains unfinished
  writer charges; consumers must also require a successful CLI exit status.
- Numeric Layer 3 sends can use `ProviderSet::transmit(route, interface, transmit)`
  and `Client::send_layer3`, through `TransmitProviders` / `TransmitSet`, without
  supplying a capture implementation. Existing `PacketProviders` and `send`
  remain available for workflows that may perform neighbor discovery. Explicit
  Layer 2 is rejected by `send_layer3`; final-wire, route, MTU, and cumulative
  budget validation remain shared.
  Repeated sends wait for pacing before preparing the next packet, so a route or
  MTU change during the wait is validated before transmission. A next-packet
  rejection can therefore follow its pacing wait.

An attempted TCP `DeadlineExpired` is a local unavailable observation, rather
than transport silence, for adaptive control as well as port inference. Actual
transport `TimedOut` retains its existing meaning. Raw capture observations now carry the qualification contract described below.

## Execution ownership and Rust names

Direct `Client` calls still take a request and a sink. Use
`client.with_deadline(deadline)` to consume a configured client and narrow its
absolute ceiling. Repeated calls cannot widen an earlier ceiling. The removed
`with_parent_deadline`, `with_scan_neighbors`, `with_neighbor_request_authorization`,
and `with_remaining_budget` helpers have no aliases. Use
`scan_with_followups` or `scan_connect_with_followups` to compose stages under one
remaining deadline and budget. Preparation mode and pacing are private operation
state; reusable providers, caches, policy, and worker capacity stay on the client.

Update extension implementations and imports directly:

| Previous name | Replacement |
| --- | --- |
| `codec::LayerCodec` | `codec::Codec` |
| `codec::LayerEncodeContext` | `codec::EncodeContext` |
| `codec::LayerDecodeContext` | `codec::DecodeContext` |
| `codec::EncodedLayer` | `codec::Encoded` |
| `codec::DecodedLayer` | `codec::Decoded` |
| `codec::Context` | `codec::Addresses` |
| `field::FieldKind` | `field::Kind` |
| `output::protocols::FieldKind` | `output::protocols::Kind` |
| `field::FieldValue` | `field::Value` |
| `probe::ProbeEndpoint` | `probe::Endpoint` |
| `probe::ProbeStatus` | `probe::Status` |

`analysis::Session::new(registry, options, collector)` now uses `options.stream`;
remove the separate selector argument. Stream numbering remains capture-wide,
with selection and filters applied after indexing. CLI output formats, error
codes, packet semantics, and historical schemas are unchanged.

## Contract versions

| Contract | beta.3 | Current main |
| --- | --- | --- |
| Packet JSON/YAML | `packetcraftr.packet/v1` | `packetcraftr.packet/v2` |
| Command JSON/NDJSON | `packetcraftr.output/v2` | `packetcraftr.output/v18` |

Older packet documents are rejected. Output v6–v17 schemas stay frozen for
historical evidence; see the [consumer policy](consumer-compatibility.md).

## Offline statistics (v17)

Adopt `output::contract::SCHEMA_V18` for current producers. Core and output
statistics `Table` gain `Overview`; output `TableData::Overview` contains total
counts and protocol/endpoint/conversation rows. Core `stats::Report` adds
`protocol_count`, `endpoint_count`, and `conversation_count` fields; update
struct literals. `output::contract::Format` gains `Csv`; update exhaustive matches.

CLI adds `--table overview`, `--sort frames|bytes`, and `--output csv` for flat
statistics tables. Existing commands, defaults, aliases, and default ordering are
unchanged. Overview defaults to five rows per leaderboard; `--top 0` keeps totals.
See [statistics](statistics.md) for sorting, CSV headers/units, and limitations.

## Scanner, identification, and live workflows

- **SCTP and IP-protocol inventory (v16):** Adopt `output::contract::SCHEMA_V16`.
  `scan::Request` and `scan::Probe` gain `sctp_scan: scan::SctpScan` (default `Init`);
  `scan::ProbeEvidence` gains `ip_protocol: Option<u8>`, `icmp_request: Option<&'static str>`,
  and `sctp_scan: Option<SctpScan>`; `scan::Endpoint` gains `ip_protocol: Option<u8>`;
  `probe::Transport` gains `Sctp` and `Ip`; `probe::Endpoint` gains `Sctp`, `Ip`,
  `TcpAck`, `IcmpTimestamp`, and `IcmpNetmask`; `scan::Reply` and `scan::Rule` gain
  SCTP, IP-protocol, and ICMP timestamp/netmask/protocol-unreachable variants.
  CLI adds `--transport sctp|ip`, `--sctp-scan`, `--ip-protocols`,
  `--exclude-ip-protocols`, `--discovery-ip-protocols`, `sctp:` port prefixes, and
  `--discovery-probes tcp-ack,icmp-timestamp,icmp-netmask,sctp,ip`.
- **TCP diagnostic scans (v15):** Adopt `output::contract::SCHEMA_V15`.
  `scan::Request` and `scan::Probe` gain `tcp_scan: scan::TcpScan` (default `Syn`);
  `scan::ProbeEvidence` gains `tcp_scan: Option<TcpScan>` and `tcp_window: Option<u16>`;
  `scan::State` gains `Unfiltered`; `scan::Rule` gains `TcpDiagnostic(DiagnosticRule)`.
  CLI adds `--tcp-scan` and `--tcp-flags`. See [TCP diagnostics](tcp-diagnostics.md).
- **OS identification (v14):** `Client::identify_os` / `identify-os` take a
  numeric target, distinct open/closed TCP ports, and `os_fingerprints::Corpus`
  (`os::Collector` rebuilds the aggregate). See [OS identification](os-identification.md).
- **Service identification and TLS (v12–v13):** Explicit `identify` /
  `Client::identify` (never automatic during scans). Set
  `identify::Request::tls: Option<TlsSettings>` for TLS wrapping (`--tls`,
  `--server-name`). `Usage`, `Evidence`, and `Outcome` gain TLS members;
  service-probe `Request`, `Protocol`, and `Field` gain SMTP/FTP variants;
  `MatchRule` and `Candidate` gain optional `hostname_field`, `device_type`, and `cpe`.
  See [service identification](service-identification.md).
- **Target, port, discovery, adaptive, and traceroute plans (v7–v11):**
  - `Request::targets: target::Selection` replaces `target`; handle `Target::ScopedAddress`
    and `Authorized::selected()`.
  - `Request::endpoints: Vec<probe::Endpoint>` and `planned_endpoints()`
    replace transport/port fields (`select_endpoints` expands catalog terms).
    `Request::udp_payload: Bytes` and `udp_profiles` configure UDP probes; reports
    gain `rtt: Rtt`.
  - `Request::discovery: discovery::Options` adds opt-in `before|only|skip` host
    discovery; probes/evidence gain `stage` and reports gain `hosts`.
  - `Request::adaptive: Option<scan::Adaptive>` (`--adaptive`) adds `scheduling`
    and `scan::discovery::Scan::Incomplete`.
  - `traceroute::hosts` / `Client::trace_hosts` (`scan --traceroute`) and
    `scan::followup` (`Client::scan_with_followups`, `scan_connect_with_followups`)
    run scan, trace, and reverse DNS under one budget.
  - `client.scan_connect(request, sink)` runs socket scans under `Operation::Socket`
    and `SocketLimits` (`tcp::start_connect` returns `PendingConnect` under the
    12-place TCP data allocation within the shared 16-place native root). See [scanner evidence](scanner-evidence.md).
- **Send and replay:** `client.send(send::Request, sink)` supports `--axis`,
  `--repeat`, and `--rate` (`frames` and `passes_completed` replace single `frame`/`route`).
  `client.replay(Request::new(Source::stream(reader), routing, options), sink)`
  replaces `Options::interface` with `Routing` (`--map-interface`, `--map-filter`,
  `--repeat`, `--inter-pass-delay-ms`, `--bps`, `--max-gap-ms`, `allow_permissive_live`).
- **Live capture:** `frame.interface_id` is a zero-based capture-selection ID;
  completion uses `output::capture::Summary` (`output::read::Frame::try_from`
  replaces `Event::try_from_frame`). JSON requires `--write`; rotation uses PCAPNG.
- **Destination allowlists:** `Policy::allowed_destinations: Vec<DestinationConstraint>`
  (`--allow-destination`) narrows permitted target, declared, route, and final-wire
  addresses (`policy.destination_not_allowed` / `cli.live_target`).

## Packets, protocols, filters, and offline analysis

- **Packet/v2, DNS, TCP options, TLS, and templates:**
  - Packet/v2 adds named objects (`{name=value}`) and nested paths (`questions[0].name`).
  - `Dns::questions: Vec<Question>` replaces `qnames`/`qtypes`/`qclasses`;
    `QueryType` serializes as numeric `u16` (`QueryType::new(code)`, `.code()`,
    uppercase constants, `Display`). Import `Name`, `Record`, `RecordValue`,
    `Edns`, `EdnsOption` from `packetcraftr_core::protocol::application::dns`;
    `Dns::try_from(bytes)` / `from_wire_with_limits` replace `from_wire`.
  - Live `dns::Request` replaces `tcp_fallback` with `transport: TransportMode`
    (`Udp`, `UdpThenTcp`, `Tcp`), adds `edns: Option<EdnsRequest>` (5th
    `dns::wire::encode_query` argument), supports question batches and
    `--reverse`, and uses `dns::tcp::query(request, Arc::clone(&provider))`.
  - `Tcp::options` is `Vec<TcpOption>` rather than `Bytes`.
  - `Tls::try_from(Hello)` builds ClientHello/ServerHello fixtures; replace
    `Extension::len` with `data.len()`.
  - `Fragment` gains `reserved: u8` and `reserved_bits: u8` (`0..=3`), decoded
    with `decode.ipv6_fragment_reserved` / `decode.srh_flags`.
  - `Template::axis` forms a Cartesian product (`expansion_len()`, `expand(maximum)`);
    `expression::Limits` adds `max_generated_bytes`.
  - Built-in protocols add STP, LLDP, EAPOL, VRRP, EtherIP, GTP-U, TFTP, and
    syslog; UDP 5353/5355 bind DNS.
- **Display filters and epoch bounds:** Function `(` must directly follow the
  name; ambiguous unquoted byte words (`deadbeef`, `c0:0`) fail `cli.filter`.
  Offline commands accept inclusive `--start-epoch`/`--stop-epoch`
  (`frame::TimeBounds::new(start, end)` in `Options`).
- **Offline analysis, HTTP/2, forwarding, and captures:**
  - Update `analysis::Options` literals for `plan`, `deadline`, `stream`,
    `time_bounds`, and `track_sources`. Expert codes add `tcp.connection_refused`,
    `tcp.fast_retransmission`, `tcp.out_of_order`, and `tcp.not_closed_at_end`.
  - `http2` analyzes cleartext prior knowledge and h2c (`--http2-port`); `http`
    remains HTTP/1-only. See [analysis resources](analysis-resources.md#http2-limits).
  - `verify-forwarding` compares physical observations with opaque `Observation`
    values and `verify` / `verify_with_limits`; see [verification](verification-contract.md).
  - Capture normalization/rewrite/merge refuse declared FCS metadata
    (`Reader::refuse_declared_fcs`). `merge` adds `order` and `max_reorder_frames`
    to `MergeLimits`; hand-built `transform::rules::Rule` gains `map: None`.

## Error codes and messages

Errors retain typed sources in `causes` (`Classified::causes()`, `error::source_chain`,
`error::Source::new(error)`); `message` describes only the current failure.
`Kind::Cli` becomes `Kind::Usage` (`"usage"`, exit 2); `cli.*` codes keep their
spelling. `filter::Error` and `policy::Error` drop `PartialEq`/`Eq` (`policy::Error`
also drops `Clone`).

| Failure | Current classification / action |
| --- | --- |
| Analysis processing deadline | `policy.duration_limit`, not `policy.analysis_resource_limit` |
| Analysis dissection or live build failure | Original decode/build classification, not generic `packet.decode` / `packet.build` |
| Time filter on an untimestamped frame | `packet.timestamp_unavailable`, exit 3 |
| Malformed/unresolved `fuzz --field` | `cli.selector`, exit 2 |
| Invalid `build --link-type` | Argument-parsing `cli.error`, exit 2 |
| Invalid normalization output | `cli.capture_normalize_format` (PCAP and PCAPNG supported) |
| Zero/above-ceiling HTTP/DNS or export limits | `cli.analysis_limit`, exit 2 (`Analysis(Error::InvalidLimit { .. })`) |
| Invalid HTTP/DNS port or HTTP body limit | Argument-parsing `cli.error`, exit 2 |
| Text/hex/raw/JSON stdout write | `io.stdout`, exit 5, with the I/O error in `causes` |
| UDP/ICMP requested with TCP-connect scan | `cli.scan_method`, exit 2 |

## Core, limits, providers, and client model

- **Core conventions:** Registry APIs take `LinkType` and `impl Into<Discriminator>`;
  frame constructors take `frame::Lengths { captured, original }`; `codec::Codec::decode`
  takes `Bytes` and `codec::DecodeContext` gains `parent`/`hop_limit`. Use inherent
  `Layer::{downcast_ref, downcast_mut, is}` and `decoded.frame.bytes()`.
  `BuiltPacket` exposes `contains_malformed()` / `contains_network_trailer()`, while
  workflow `policy::requires_live_opt_in(&built)` owns live policy.
- **Limits and budgets:** Replace `capture_file::Limits::advance` with
  `Budget::new(limits)?` and `.charge(len)?`. `Runtime::new(capacity)` returns `Result` (1..=8).

| Before | After |
| --- | --- |
| Flat TCP/IP fields in `analysis::Limits` | `tcp: reassembly::tcp::Limits`, `ip: reassembly::ip::Limits` |
| `decode::Options { max_layers, max_packet_size }` | `Options { limits: packet::Limits { .. } }` |
| `build::Options { mode, max_layers, max_packet_size }` | `Options { mode, limits: packet::Limits { .. } }` |
| `Interner::with_limits(count, bytes)` | `Interner::with_limits(scope::Limits { max_scopes, max_bytes })?` |
| Workflow `max_evidence_frames`, `max_evidence_bytes`, `max_undecoded` | `evidence: evidence::Limits { max_frames, max_bytes, max_undecoded }` |

- **Providers, routes, and `Client`:**
  - Blocking provider calls take `&budget::Deadline` (`deadline::PASSIVE_LOOKUP_TIMEOUT`
    for passive lookups). Transmit uses `send(Outbound::{Layer2, Layer3})`.
    Capabilities return `Unsupported { capability, message, source }`.
  - Workflow `route` owns `plan`/`Plan`/`Options`/`Materialized`; `Client`
    resolves interface selectors and neighbors over its own providers after
    authorization (`with_neighbor_options(options)?`).
  - `Client<P, K = SystemClock>::new(registry, policy, providers)` replaces free
    runners, executors, and authorizers. Bind custom `ProviderSet` bundles by
    `CaptureProviders`, `PacketProviders`, `TargetProviders`, `TcpProviders`,
    and `UdpProviders`. Every workflow takes `(request, sink)` and returns
    `Report`; `Collector::finish(report)` rebuilds `Aggregate`.

## Output field types

`packetcraftr_cli::main()` returns `ExitCode`. Output `Format` and stats `Table`
no longer implement `clap::ValueEnum`; `Command::require_format` returns `Format`.
Use `From`/`TryFrom` (yielding `envelope::Published<T>` when diagnostics/stats
accompany the payload) instead of `from_*`/`try_from_*`/`complete_from_*`.
Protocol `Detail` flattens `summary` (`detail.summary.<field>`).

## Renamed and removed paths

Each table maps a 0.5.0-beta.3 name to its current name, by crate. Names are
relative to the crate root unless a crate prefix is given, and behavior notes
for a row are in the sections above.

### packetcraftr-core

| 0.5.0-beta.3 | Current main |
| --- | --- |
| `packetcraftr_core::{Packet, PacketError}` | `packet::{Packet, Error}` |
| `packet::link::{MacAddress, VlanKind, VlanTag}` | `packet::{MacAddress, VlanKind, VlanTag}` |
| `build::{Context, Mode}` | `codec::{Context, Mode}` |
| `build::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE}`, `layout::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE}` | `packet::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE}` |
| `analysis::pcap` (capture-file formats) | `capture_file`, with the same items |
| `analysis::pcap::DEFAULT_SIZE_LIMIT`, `frame::DEFAULT_SIZE_LIMIT` | `frame::DEFAULT_MAX_SIZE` |
| `analysis::pcap::DEFAULT_INTERFACE_LIMIT` | `capture_file::DEFAULT_MAX_INTERFACES_PER_SECTION` |
| `analysis::pcap::DEFAULT_TOTAL_INTERFACE_LIMIT` | `capture_file::DEFAULT_MAX_TOTAL_INTERFACES` |
| `analysis::pcap::DEFAULT_METADATA_BLOCK_LIMIT` | `capture_file::DEFAULT_MAX_METADATA_BLOCKS_PER_FRAME` |
| `analysis::pcap::DEFAULT_METADATA_BYTE_LIMIT` | `capture_file::DEFAULT_MAX_METADATA_BYTES_PER_FRAME` |
| `analysis::pcap::DEFAULT_STREAM_FRAMES`, `DEFAULT_STREAM_BYTES` | `capture_file::DEFAULT_MAX_STREAM_FRAMES`, `DEFAULT_MAX_STREAM_BYTES` |
| `analysis::pcap::ReaderOptions`, `Reader::with_options` | `capture_file::ReaderLimits`, `Reader::with_limits` |
| `protocol::capture::{CaptureRoot, BUILTIN_CAPTURE_ROOTS}` | `frame::LinkType::BUILTIN_ROOTS`, a `(LinkType, BuiltinProtocol)` slice; use `LinkType::root_protocol`, `LinkType::for_root_protocol` (raw IP is `LinkType::RAW`), and `LinkType::is_raw_ip` instead of matching link-type constants by hand |
| `packet::semantics` | `protocol::semantics` (no longer exports its field-name constants) |
| `protocol::raw::parse_hex` | `layer::parse_hex`; the `Raw`, `Padding`, and `Malformed` layers stay at `layer` |
| `protocol::gre::Gre` | `protocol::tunnel::Gre` |
| `protocol::icmp::{Icmpv4, Icmpv6}` | `protocol::network::{Icmpv4, Icmpv6}` |
| `protocol::ipv6::{Fragment, HopByHop, DestinationOptions, SegmentRoutingHeader}` | `protocol::network::{Fragment, HopByHop, DestinationOptions, SegmentRoutingHeader}` |
| `protocol::application::{Dns, Tls}` | `protocol::application::dns::Dns`, `protocol::application::tls::Tls` |
| `protocol::application::tls::{codec, fingerprint, model, names, parse}` submodule paths | the same items re-exported flat from `protocol::application::tls` (`tls::codec::Tls` is `tls::Tls`, `tls::parse::parse_record` is `tls::parse_record`, `tls::names::version_name` is `tls::version_name`, `tls::model::extension` is `tls::extension`) |
| `protocol::application::dns::name::decompress(message, offset, max_pointers)` and `Decompressed` | `dns::decode_name(&message, offset, Limits { max_name_pointers, .. })`, returning `(Name, resume)`; `Name::labels()` gives the label octets |
| `protocol::application::dns::name::{MAX_LABEL_LEN, MAX_NAME_LEN}` | `protocol::application::dns::{MAX_LABEL_LEN, MAX_NAME_LEN}` |
| `dns::name::Error` | variants directly on `dns::Error` |
| `Dns::qnames`, `qtypes`, `qclasses`; `Dns::from_wire` | `Dns::questions`; `Dns::try_from` |
| `Tcp::options: bytes::Bytes` | `Tcp::options`, a list of `protocol::transport::TcpOption` |
| `frame::GlobalInterfaceId` | `u32` |
| `layer::{raw_layout, malformed_layout, padding_layout}` (`#[doc(hidden)]`) | `layer::Raw::layout(len)` |
| `protocol::QuotedIcmpError`, `QuotedProbeTransport`, `quoted_icmp_error_kind` | `protocol::IcmpErrorKind`, `QuotedTransport`, `quoted_icmp_error` (same variants) |
| `Layer::as_any`, `Layer::as_any_mut` | removed; use `layer.downcast_ref::<T>()` |
| `error::Kind::Cli` | `error::Kind::Usage` |
| `packet::PacketError` | `packet::Error` |
| `layer::FieldError` | `field::Error` |
| `layer::ReflectiveFieldError` | `layer::Refusal` (a reason, not an error) |
| `analysis::pcap::SelectionError` (`Predicate` variant) | `capture_file::Error::Predicate` |
| `fuzz::TargetParseError::{MissingSeparator, InvalidLayer, InvalidField}` | `fuzz::Error::{TargetSeparator, TargetLayer, TargetField}` |
| `analysis::reassembly::{ip, tcp}::{ResourceError, MalformedError}` | `analysis::reassembly::{ip, tcp}::{Resource, Malformed}` |
| `analysis::follow::Direction` | `analysis::follow::PeerDirection`, distinct from `frame::Direction` |
| `expression::Options`, `filter::Options` | `expression::Limits`, `filter::Limits` (each with `validate()`); `expression::Limits` also has `max_generated_bytes` |
| `budget::Cancellation::POLL_INTERVAL` | `packetcraftr_netio::deadline::POLL_INTERVAL` |
| `document::PACKET_DOCUMENT_SCHEMA_V1` | `document::PACKET_DOCUMENT_SCHEMA_V2` |
| `fuzz::Summary.diagnostics`, `fuzz::Report.diagnostics` | removed, so `Summary` is `{ seed, first_case, stats }` and `Report` is `{ seed, first_case, cases, stats }`; the field was always empty, and per-case diagnostics are `Case::diagnostics` |
| `fuzz::CaseFailure::new(message, classification, causes)` | `fuzz::CaseFailure::with_source(message, classification, source_error)`; `causes()` is then the source chain |

### packetcraftr-netio

| 0.5.0-beta.3 | Current main |
| --- | --- |
| `PacketIo { sender, capture }` | removed; transmit and capture are separate `packetcraftr::ProviderSet` fields |
| `transmit::Sender` | `transmit::Provider` (same `send` method) |
| `transmit::Frame` | `transmit::Outbound` (same variants and methods) |
| `transmit::{Layer2Sender, Layer3Sender}` | `transmit::Provider`; match `Outbound::Layer2`/`Outbound::Layer3` inside `send` |
| `ModeSender::new(SystemLayer2, SystemLayer3)`, `SystemLayer2.send_layer2(frame)` | `transmit::SystemProvider`, `SystemProvider.send(Outbound::Layer2(frame))` |
| `transmit::{Layer2Frame, Layer3Frame}::try_new(bytes, &materialized)` | `try_new(bytes, materialized.transmit_route())` |
| `route::{plan, Plan, Options, materialize, Materialized}` and the planning `route::Error` | `packetcraftr::route::{plan, Plan, Options, Materialized, Error}`; the `Client` materializes admitted plans |
| `route::SystemError` | `route::Error` |
| `route::Options.interface: Option<InterfaceId>` | `packetcraftr::route::Options.interface: Option<route::Interface>` |
| `route::Provider::classify_error(&error)` | `error.classification()`; `type Error` must implement `Classified` |
| `route::Provider::lookup_with_preferences(destination, hint, source)`, `lookup_interface(&interface)` | the same with a trailing `&deadline` |
| `interface::Provider::interfaces()` | `interfaces(&deadline)`, returning `interface::Error` |
| `Error::InterfaceDiscovery { message, source }` | `interface::Error::Discovery { message, source }` |
| `Error::Unsupported { message, source }` | `Error::Unsupported(Unsupported { capability, message, source })` |
| `capture::Provider::arm_capture(&request)` | `arm_capture(&request, &deadline)` |
| `capture::Session::wait_ready(timeout)`, `next_captured_frame(timeout)` | `wait_ready(&deadline)`, `next_captured_frame(&deadline)` |
| `capture::Cancellable::new(session, cancellation)` | the session itself; pass `Deadline::new(timeout).with_cancellation(cancellation)` to each wait |
| `capture::Statistics`, `capture::Session::statistics()` | `capture::Stats`, `capture::Session::stats()` |
| `capture::MAX_TIMEOUT` | `deadline::MAX_WAIT`, the one-hour ceiling every provider wait and bounded live operation accepts |
| `SendEvidenceFault` | `transmit::SendEvidenceFault` |
| `SystemFault` (`Some(Arc::new(error))`) | `packetcraftr_core::error::Source` (`Some(Source::new(error))`) |
| `neighbor::{Error, Request, Resolution, Options}` | `packetcraftr::neighbor::{Error, Request, Resolution, Options}` |
| `neighbor::{Resolver, ActiveResolver, SystemResolver}` | removed; the `Client` resolves over its own providers |
| `link::MAX_VLAN_TAGS` | `packetcraftr::neighbor::MAX_VLAN_TAGS` |
| `link::{MacAddress, VlanKind, VlanTag}` | `packetcraftr_core::packet::{MacAddress, VlanKind, VlanTag}` |

### packetcraftr

| 0.5.0-beta.3 | Current main |
| --- | --- |
| `Client<R, N, I>`, `Client::new(registry, routes, neighbors, io, policy)` | `Client<P, K>`, `Client::new(registry, policy, providers)` |
| `Client::send(packet, options)` returning `send::Report { sent, stats }` | `client.send(send::Request::packet(packet, options), sink)`; a single `SentPacket` is `aggregate.sent[0].packet` |
| `Client::exchange(&template, options)`, `Client::exchange_with_events(&template, options, emit)` | `client.exchange(exchange::Request { template, .. }, sink)` |
| `exchange::Options` | `exchange::Request` and `exchange::Collection` |
| `scan::{run, run_with_events}`, `traceroute::{run, run_with_events}`, `dns::{run, run_with_events}` | `Client::{scan, traceroute, dns}` |
| `fuzz::{run, run_with_events, run_offline_with_events}` | `Client::fuzz`; `packetcraftr_core::fuzz::run_observed` for the offline campaign |
| `replay::run_with_selector`, `replay::Selector`, `SystemAuthorizer`, `SystemTransmitter`, `Transmitter` | `Client::replay`; `Request::with_filter`; the client's policy and providers |
| `replay::Options.interface` | `replay::routing::Routing` |
| `probe::{Executor, ExchangeExecutor, Request, Batch, Execution}`, `{scan, traceroute}::{Executor, Execution, Batch}`, `dns::{Executor, Exchange, Execution, TcpExchange, TcpExecution, TcpExecutor}`, `fuzz::{Executor, Execution, ExecutionCase}` | removed; the client runs each step, and tests inject fake providers instead |
| `policy::{Authorizer, PolicyAuthorizer, unsupported_operation}`, `fuzz::PolicyAuthorizer`, `replay::Authorizer` | removed; the client's `Policy` admits every workflow |
| `clock::CancellableClock`, `Clock::cancellation` | removed; `Client::with_cancellation` |
| `SentPacket` | `evidence::SentPacket` |
| `progress::{Runtime, RuntimeSnapshot, MAX_WORKER_CAPACITY}` | `runtime::{Runtime, RuntimeSnapshot, MAX_WORKER_CAPACITY}` |
| `progress::Sink<T>`, `progress::EmitError` | `runtime::Worker<T, A = ()>`, `runtime::Error` (implements `Classified`) |
| `scan::ProbeEndpoint`, `traceroute::ProbeTarget` | `probe::Endpoint` |
| `scan::ProbeStatus`, `traceroute::ProbeStatus` | `probe::Status` |
| `scan::Transport`, `traceroute::Strategy` | `probe::Transport` |
| `probe::Error { workflow, kind }`, `probe::ErrorKind`, `probe::Workflow` | `scan::Error` and `traceroute::Error`, whose variants are the former kinds |
| `probe::{EPHEMERAL_SOURCE_PORT_BASE, ephemeral_source_port}` | no longer public; the dynamic range starts at 49152 (IANA), so choose source ports in your own code |
| `scan::ResponseClassification`, `traceroute::ResponseClassification` | `scan::CorrelatedResponse`, `traceroute::CorrelatedResponse` |
| `traceroute::Completion`, `report.completion` | `traceroute::Termination`, `report.termination` (the published `completion` field is unchanged) |
| `scan::Request.target` | `scan::Request.targets: target::Selection` |
| `{scan, traceroute, exchange, replay, dns, fuzz}::Summary` | `{scan, traceroute, exchange, replay, dns, fuzz}::Report` |
| `dns::AttemptTransport`, `AttemptEvidence.exchange` | `dns::TransportEvidence`, `AttemptEvidence.transport_evidence` |
| `dns::EvidenceError` | `dns::IncoherentReport` |
| `dns::WireError` | `dns::wire::Error` |
| `dns::{canonical_query_name, decode_response, decode_tcp_frame, encode_query}` | `dns::wire::{canonical_query_name, decode_response, decode_tcp_frame, encode_query}` |
| `dns::{Name, Record, RecordValue, Edns, EdnsOption}` | `packetcraftr_core::protocol::application::dns::{Name, Record, RecordValue, Edns, EdnsOption}` |
| `dns::ResponseMetadata::response_code_name`, `dns::ValidatedResponse::response_code_name` | `dns::response_code_name(code)` |
| `dns::{MAX_MESSAGE_BYTES, MAX_RECORDS, MAX_NAME_POINTERS}` | `packetcraftr_core::protocol::application::dns::{MAX_MESSAGE_BYTES, MAX_RECORDS, MAX_NAME_POINTERS}` (values unchanged: 65535, 4096, 128); `dns::MessageLimits::default().max_message_bytes` gives the default message-size limit |
| `dns::tcp::exchange(request)` | `dns::tcp::query(request, Arc::clone(&provider))` |
| `dns::tcp::SocketFault` | `packetcraftr_core::error::Source` |
| `dns::Request.tcp_fallback`, `dns::DEFAULT_TCP_FALLBACK` | `dns::Request.transport: dns::TransportMode`; the constant is removed |
| `dns::QueryType::{A, Aaaa, Any, ...}` variants, `QueryType::as_str()` | `QueryType::{A, AAAA, ANY, ...}` constants, `Display` |
| `scan::MAX_DURATION`, `traceroute::MAX_DURATION`, `dns::MAX_DURATION`, `fuzz::MAX_DURATION`, `replay::MAX_REPLAY_DURATION`, `exchange::MAX_EXCHANGE_TIMEOUT` | `packetcraftr_netio::deadline::MAX_WAIT` (core's offline `fuzz::MAX_DURATION` is unchanged) |
| `policy::{WireBudget, SocketBudget, BudgetOverflow}` | `policy::{WireLimits, SocketLimits, LimitOverflow}` (classified `policy.budget_overflow`) |
| `dns::Error::BudgetOverflow` | `dns::Error::LimitOverflow` |
| `policy::Operation::Budgeted(limits)` | `policy::Operation::Wire(limits)` |
| `budget()` on `Operation`, `DnsOperation`, and `DeclaredPackets` | `limits()` |
| `replay::{Authorizer, Operation, ReplayFrame, WireBudget}` | `policy::{Operation, WireLimits}`; `Authorizer` and `ReplayFrame` are removed |
| `policy::Operation::Replay(frame)`, `policy::ReplayFrame` | removed; replay frame admission is internal, so the client's policy admits each replay frame itself |
| `policy::Operation::shape()` | removed; callers that logged or compared its labels (`"budgeted"`, `"dns"`, `"declared-packet"`, and `"replay"` in beta.3) match on `Operation::{Wire, Dns, Declared}` directly, and on `Socket`, which is new |
| `replay::FrameEvidence.source_interface_id` | `evidence.frame.interface` |
| `Policy::authorize` returning `packetcraftr::Error` | returns `policy::Error` |
| `packetcraftr::Error::{UnsupportedOperation, Wire(decode_error), PermissiveLiveOptInRequired}` | `policy::Error::{UndecodableWire { source }, PermissiveLiveOptIn}`, reached through `packetcraftr::Error::Policy`; `UnsupportedOperation` is removed |
| `Err(packetcraftr::Error::Policy(policy::Error::PacketLimit { .. }))` | `Err(policy::Error::PacketLimit { .. })` |
| `packetcraftr::Error::{ExchangeOutput, ExchangeOutputAndCaptureShutdown, OperationAndCaptureShutdown, InvalidExchangeEvents, HeterogeneousExchangeRoute, InvalidExchangeOption}` | `exchange::Error::{Output, OutputAndCaptureShutdown, OperationAndCaptureShutdown, IncoherentEvents, HeterogeneousRoute, InvalidRequest}` |
| `fuzz::{RunInput, LiveOptions, LiveLimits}` | `fuzz::Request { campaign, packet, .. }`; `timeout`, `cases_per_second`, `destination`, `max_evidence_frames`, and `max_evidence_bytes` are its fields, and `allow_malformed_live` is `allow_permissive_live` |
| `LiveOptions::validate`, `LiveLimits::validate` | `fuzz::Request::validate` (also validates the campaign) |
| `fuzz::Case { prepared, outcome, sent, responses, unmatched, undecoded }` | `fuzz::Trial { case, evidence: Option<fuzz::Evidence { sent, outcome, responses, unmatched, undecoded }> }` |
| `fuzz::CaseOutcome::{Built, Rejected}` and `{Response, Timeout}` | `trial.case.outcome` (core `CaseOutcome`) for a case never sent, and `evidence.outcome` (`fuzz::Outcome`) |
| `fuzz::Summary { seed, first_case, stats }`, `fuzz::Report { seed, first_case, cases, stats }` | `fuzz::Report { seed, first_case, campaign, stats }`, `fuzz::Aggregate { seed, first_case, trials, campaign, stats }` |
| `fuzz::Stats.{cases_generated, cases_built}` and `.{packets_attempted, packets_completed, bytes, elapsed, capture}` | `report.campaign.{cases_generated, cases_built}` (core `fuzz::Stats`) and `report.stats` (`packetcraftr::Stats`) |
| `From<BoundaryError>` for `dns::Error` and `fuzz::Error` | construct `Error::Authorization(boundary_error)` explicitly |
| `scan::Limits`, `traceroute::Limits`, `dns::Limits` fields `max_evidence_frames`, `max_evidence_bytes`, `max_undecoded` | `limits.evidence` (`evidence::Limits { max_frames, max_bytes, max_undecoded }`); the Serde struct representation, including binary field order, is unchanged |

### packetcraftr-cli

| 0.5.0-beta.3 | Current main |
| --- | --- |
| `output::contract::SCHEMA_V2` | `output::contract::SCHEMA_V18` |
| `Command::require_format(format) -> Result<(), Error>` | `require_format(format) -> Result<Format, Error>` |
| `impl clap::ValueEnum` for `output::contract::Format` and `output::stats::Table` | removed; declare your own value enum and convert with `From` |
| `try_from_*`, `from_*`, and `complete_from_*` constructors on output types | `From`/`TryFrom`, yielding `output::envelope::Published<T>` where diagnostics or stats travel with the result (see [Output field types](#output-field-types)) |

## Callers tracking main

Items introduced and removed entirely after beta.3 have no released migration.
Pin a reviewed revision rather than depending on intermediate names. This cleanup
changes provider composition; the current producer family is output/v18:

- `ProviderSet<R,N,C,T,P,H>` defaults UDP to `()`; full literals add `udp: ()`.
- Replace `WithUdp<ProviderSet<R,N,C,T,P,H>,U>` with
  `ProviderSet<R,N,C,T,P,H,U>`; `with_udp` now returns this flat bundle.
- Replace the broad `Providers` bound with the capabilities actually used.
  To retain the former full bound, use `PacketProviders + TargetProviders + TcpProviders`.
- Provider builders preserve every unselected capability; repeated `with_udp`
  replaces UDP rather than nesting a forwarding adapter.

## Native submission timing eligibility

`netio::transmit::Timing::freshness_marker()` denotes submission start; use
`completed()` for the acceptance-return marker. Replies captured during an exact
successful native send can correlate; older or missing monotonic ingress cannot.
`sent_at`/latency use submission start, not proven wire departure or causality.
These semantics are retained in current output/v18; historical native evidence
keeps its original schema identity. See [scanner timing](scanner-evidence.md).

### Qualified scan measurements (output/v18)

Read `ProbeEvidence::measurement` before interpreting absence of `reply`; update
Rust struct literals with the appropriate typed measurement. New capture
`Source` literals need `observation_quality` (use `Unknown` unless the provider
explicitly reports local quality).
Raw pipeline no-reply events are provisional until `Event::Qualification`;
collectors apply these before endpoint inference. Exhaustive Rust event matches
must handle the added variant. Capture providers may explicitly implement
`Session::observation_quality`; the default keeps their quality unknown. This is
an honest adapter default, not a stronger guarantee inferred from zero counters.
See [consumer compatibility](consumer-compatibility.md#output-family-v18) for
stream scope, terminal behavior, and the revised RTT partition. Frozen v17
schemas/examples retain their former meanings.
