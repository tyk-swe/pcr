# Changelog

All notable changes to PacketcraftR are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- Structured command output moves to `packetcraftr.output/v8`, which adds
  scanner port planning and inference; the v6 and v7 families and schemas stay
  frozen. `scan::Request` replaces `transport` and `ports` with typed
  `endpoints: Vec<probe::ProbeEndpoint>` that may mix TCP and UDP, and
  `selected_ports()` is `planned_endpoints()`. `scan::Endpoint`,
  `scan::connect::Endpoint`, `scan::ProbeEvidence`, `scan::CorrelatedResponse`,
  and `scan::Aggregate` gain fields, and `scan::Event` gains `Unattributed`.
  `scan --connect` with UDP or ICMP endpoints reports `cli.scan_method` instead
  of `cli.error`. CLI scan output conversions take the published plan. See `docs/migration-unreleased.md`.
- `packetcraftr::Providers` is now a blanket marker over the capability
  interfaces `CaptureProviders`, `PacketProviders`, `TargetProviders`, and
  `TcpProviders`, so each `Client` workflow requires only the provider cluster
  it uses. `ProviderSet` gains `()`-defaulted type parameters plus the
  `capture`, `packet`, and `tcp` partial constructors and `with_resolver` /
  `with_tcp`; complete six-field literals and `SystemProviders` are unchanged.
  Custom `Providers` implementations move to the four capability traits. See
  `docs/migration-unreleased.md`.
- `packetcraftr_netio::capture::MAX_TIMEOUT` is `packetcraftr_netio::deadline::MAX_WAIT`,
  the one-hour ceiling every provider wait and bounded live operation
  accepts, and `packetcraftr_netio::SendEvidenceFault` is
  `packetcraftr_netio::transmit::SendEvidenceFault`. See
  `docs/migration-unreleased.md`.
- `dns::tcp::query` takes an `Arc<P>` so its admitted connect worker owns the
  provider; `P` and its stream must be `'static`. `dns::tcp::Request` gains
  `cancellation: Option<&Cancellation>`, and its `Error` and `Category` gain
  `Cancelled`. See `docs/migration-unreleased.md`.
- Error codes follow the failure's own classification. Live `send`,
  `exchange`, and other workflow build failures publish the build error's code
  (for example `policy.build_resource_limit`, `packet.codec`,
  `internal.codec_contract`) instead of `packet.build`. Offline analysis
  dissection failures publish the decode error's code; a layer-limit refusal
  reports `policy.analysis_resource_limit` like a byte-limit refusal, instead of
  `packet.decode`. Generated capture output from `fragment`, `send`, and
  `exchange` keeps `packet.capture_file` (exit 3) for non-I/O encoding failures
  instead of `io.runtime`, and replay interrupted while emitting a record
  reports `io.cancelled` or `policy.replay_limit` instead of `io.replay`.
- Forwarding ordinary preservation requires readable values on both sides;
  missing values are unevaluable. Explicit presence/absence checks are separate.
  v6 publishes check-specific evidence states and comparison labels.
- Forwarding observations are opaque and bound to a compiled rules instance and
  capture side. `verify` returns `forwarding::Error`; `analysis::Options` gains
  `plan` and a shared optional `deadline`. See the unreleased migration note.
- Analysis duration exhaustion reports `policy.duration_limit` consistently
  across packet processing and capture reads, replacing the generic
  `policy.analysis_resource_limit` classification for processing deadlines.
  Invocation duration expiry, including `rewrite --max-duration-ms`, reports
  that code with the remediation "reduce input or raise the finite invocation
  duration".
- `rewrite --rules-file` and `scan --udp-profiles` document load failures
  report `io.runtime` with the failing path instead of `io.capture_file` and
  its capture-stream remediation; an oversized rules document reports
  `cli.error` instead of `policy.transform_limit`.
- Packet documents use `packetcraftr.packet/v2`; structured command output uses
  `packetcraftr.output/v6`. Schemas and published examples migrate together.
  DNS questions use one typed list and section counts use `WireValue<u16>`.
  See `docs/migration-unreleased.md`.
- Rust APIs now use standard conversion and collection traits. Wire
  constructors become `TryFrom` (`Dns`, `Dhcpv4`, and `Dhcpv6` from
  `Bytes`/`Vec<u8>`/`&[u8]`; `Http` and `Tls` from `&[u8]`; `Tls` also from
  `Hello`), while `from_wire_with_limits` stays inherent. `field::Path` and
  `BuiltinProtocol` parse through `FromStr`; the inherent `Path::parse` is
  removed. Registry bindings take the `LinkType` newtype and
  `impl Into<Discriminator>` instead of bare integers, `Frame` length
  constructors take `Lengths { captured, original }`, and
  `analysis::scope::Interner::with_limits` takes
  `Limits { max_scopes, max_bytes }`.
  `Malformed::new` takes `Option<String>`, analysis HTTP/DNS collectors take
  `impl IntoIterator<Item = u16>`, `transform::VlanTag` is renamed
  `VlanRewrite` (with `From<link::VlanTag>`), `analysis::follow::Direction` is
  renamed `PeerDirection`, and `budget::Interrupted` is `#[non_exhaustive]`.
- CLI `output::contract::Command::require_format` returns the validated
  `Format` instead of `()`, so a command that cannot emit a format fails at
  dispatch rather than re-checking `Format` inside rendering.
- `document::Error::Parse.source` is an `error::Source` (was `String`),
  retaining the packet parser's typed error in the chain.
- `analysis::reassembly::tcp::Event::Retransmission` gains a `ranges` field
  listing the arriving segment's actual retransmitted sequence spans, which
  need not form a contiguous prefix.
- Shared probe APIs have canonical paths: `probe::{ProbeEndpoint,
  ProbeStatus, Transport}`. The old `scan`, `traceroute`, `dns`, and `fuzz`
  aliases are removed without compatibility aliases, and the executor seams
  they aliased are internal. See `docs/migration-unreleased.md`.
- `LayerCodec::decode` takes a refcounted `Bytes` view of the layer input
  instead of `&[u8]`; `dns::decode_name` and `http::parse_head` take `&Bytes`
  for the same reason. Byte-retaining codecs
  now slice the shared frame buffer instead of copying each retained range,
  eliminating a per-packet memcpy in the DHCP, ICMP, IGMP, raw, DNS, NTP, HTTP,
  and TLS decode paths. Callers holding borrowed bytes wrap them once with
  `Bytes::copy_from_slice`/`Bytes::from`.
- `scan::Batch` is now an alias of the shared `probe::Batch<scan::Probe>`, as
  `traceroute::Batch` already was. Executor implementations read the scan
  batch's single probe from the one-element `batch.probes` instead of
  `batch.probe`. See `docs/migration-unreleased.md`.
- `Layer` no longer has `as_any`/`as_any_mut`; `dyn Layer` upcasts to
  `dyn Any` and provides `is`, `downcast_ref`, and `downcast_mut` directly.
  Hand-written `Layer` implementations delete both methods. See
  `docs/migration-unreleased.md`.
- `error::Kind::Cli` is renamed `Kind::Usage` (`as_str` and its serde name
  become `"usage"`), so library classifications no longer name the CLI. Codes
  such as `cli.capture_filter` are unchanged, and machine output publishes a
  usage failure as `"kind": "usage"` with exit code 2. See
  `docs/migration-unreleased.md`.
- Capture-file formats move from `packetcraftr_core::analysis::pcap` to the
  top-level `packetcraftr_core::capture_file`, with the same items. It also
  owns link-type knowledge: `frame::LinkType` keeps its path and constants and
  gains `BUILTIN_ROOTS`, `root_protocol`, `for_root_protocol`, and `is_raw_ip`.
  `protocol::capture::{CaptureRoot, BUILTIN_CAPTURE_ROOTS}` are removed in
  favor of `LinkType::BUILTIN_ROOTS`. See `docs/migration-unreleased.md`.
- Live-policy vocabulary leaves core.
  `build::BuiltPacket::requires_live_opt_in` is replaced by the neutral
  `BuiltPacket::mode` field and the `contains_malformed()` and
  `contains_network_trailer()` methods; the predicate is now
  `packetcraftr::policy::requires_live_opt_in(&built)`, and the published
  `requires_live_opt_in` output field is unchanged.
  `budget::remaining_before` and `Cancellation::POLL_INTERVAL` move to
  `packetcraftr_netio::deadline::{remaining_before, POLL_INTERVAL}`.
  `Deadline::bounded_timeout` and `Deadline::for_wait` move to the
  `packetcraftr::deadline::DeadlineExt` trait. `Cancelled::into_boundary_error`
  and the exported `deadline_error_conversions!` macro are removed. Core
  `Deadline` gains `limit()` and `cancellation()` getters. See
  `docs/migration-unreleased.md`.
- The `packetcraftr_cli` library now holds the whole command-line application
  and exposes `packetcraftr_cli::main()`, which the `packetcraftr` binary calls.
  `output::contract::Format`, `output::stats::Table`, and
  `output::capture::Retention` no longer implement `clap::ValueEnum`; the CLI
  parses its own selectors and converts them with `From`. See
  `docs/migration-unreleased.md`.
- Core modules form acyclic layers: model (`field`, `layer`, `layout`,
  `packet`, `frame`, `codec`, `registry`, `matcher`), protocols (`protocol`),
  engines (`decode`, `build`, `transform`, `filter`, `expression`), and
  workflows (`analysis`, `fuzz`). `packet::semantics` moves to
  `protocol::semantics` with the same items. `protocol::raw` is removed: the
  `Raw`, `Padding`, and `Malformed` layers and their codecs belong to `layer`,
  and `parse_hex` moves to `layer::parse_hex`. See
  `docs/migration-unreleased.md`.
- CLI `output::contract::Command` is declared once with the command line it
  names: `Command::ALL` lists commands in `--help` order instead of a separate
  canonical order. `Command::formats()` lists each command's supported
  formats. Serialized command names and formats are unchanged. See
  `docs/migration-unreleased.md`.
- Built-in protocols are grouped by layer: GRE is `protocol::tunnel::Gre`,
  ICMP is `protocol::network::{Icmpv4, Icmpv6}`, and the IPv6 extension headers
  are `protocol::network::{Fragment, HopByHop, DestinationOptions,
  SegmentRoutingHeader}`; `protocol::{gre, icmp, ipv6}` are removed. See
  `docs/migration-unreleased.md`.
- Protocol wire APIs return the protocol's own error. `dns::DecodeError` is
  renamed `dns::Error`, and `Dns::to_wire` and the `Dns` `TryFrom`
  conversions return it instead of `codec::Error` (encoding failures are
  `dns::Error::Encode` with the codec error as source). `Http::try_from`
  returns `http::Error`. The new `tls::Error` replaces `codec::Error` in
  `Tls::try_from`, `Hello::to_wire`, `Extension::{server_name, alpn}`,
  and `tls::Outcome::Malformed`, with the same messages.
- TLS items are flat re-exports of `protocol::application::tls`: the
  `codec`, `model`, `parse`, `fingerprint`, and `names` modules are private,
  so `tls::codec::Tls` is `tls::Tls`, `tls::parse::parse_record` is
  `tls::parse_record`, `tls::names::version_name` is `tls::version_name`, and
  `tls::model::extension` is `tls::extension`. See
  `docs/migration-unreleased.md`.
- `Layer::field_path` and `Layer::set_field_path` take a parsed
  `&field::Path` instead of a string, so a path is parsed once at the
  document or command-line edge rather than on every call. `field::Path`
  implements `Display` in its own syntax. See `docs/migration-unreleased.md`.
- Built-in identity comes from the layer's type. `BuiltinProtocol::of` and
  `BuiltinProtocol::identifies` recognize only the built-in layer types, so a
  custom layer whose schema reuses a built-in protocol name (such as `ipv4`)
  is no longer read as that protocol by route semantics, matchers, or
  validation. `BuiltinProtocol::from_id` still maps a registry identifier by
  name. See `docs/migration-unreleased.md`.
- `protocol::semantics` reads built-in layers through their types and no
  longer exports the reflective field-name constants `SOURCE`, `DESTINATION`,
  `SOURCE_PORT`, `DESTINATION_PORT`, `SEGMENTS`, `SEGMENTS_LEFT`,
  `LAST_ENTRY`, `TARGET_PROTOCOL`, and `IPV4_OPTIONS`. Read the typed layer's
  fields instead.
- Core errors follow one convention: each module has one `Error`, sources stay
  typed, messages do not repeat their source, and every public error implements
  `Classified` (classification codes are unchanged). `packet::PacketError` is
  `packet::Error`; `layer::FieldError` and `field::PathError` merge into
  `field::Error`; `layer::ReflectiveFieldError` is `layer::Refusal`;
  `capture_file::{SelectionError, MapError, MergeError}`,
  `analysis::SessionError`, `filter::ProjectionError`, and
  `fuzz::TargetParseError` merge into their module's `Error`; `dns::name::Error`
  merges into `dns::Error`; and the reassembly `ResourceError`/`MalformedError`
  categories are `Resource`/`Malformed`. `codec::Error` gains `Rejected`, which
  keeps a protocol's typed error as its source, and drops `Eq`, as do
  `dns::Error` and `tls::Error`. `dhcp::Error::Limit`, `http::Error::Limit`,
  `analysis::Error::InvalidLimit`, and `protocol::semantics::Error::Field`
  carry typed reasons. Type-erased sources are the new `error::Source`. See
  `docs/migration-unreleased.md`.
- CLI output modules are named after their commands: `output::dns_analysis`
  is `output::dns_read`, `output::forwarding` is `output::verify_forwarding`,
  and `output::scan_connect` is `output::scan::connect`. The types and their
  JSON are unchanged. See `docs/migration-unreleased.md`.
- Core limits follow one convention: a configured ceiling is a `…Limits` type
  whose `validate()` runs where it is accepted, and a running allowance is a
  `…Budget`. `capture_file::ReaderOptions` is `ReaderLimits` and
  `Reader::with_options` is `Reader::with_limits`. `capture_file::Limits::advance`
  is replaced by `capture_file::Budget` (`new`, `charge`, `after`, `frames`,
  `captured_bytes`). `capture_file::Limits`, `MergeLimits` (whose source
  ceiling is the new `capture_file::MAX_MERGE_SOURCES`), `compression::Limits`, `scope::Limits`, the IP and TCP reassembly `Limits`,
  `dhcp::Limits`, `dns::Limits`, `packet::Limits`, and
  `forwarding::Limits` gain `validate()` (packetcraftr's
  `policy::WireLimits` and `policy::SocketLimits` too; for the last four every
  value is legal, so it always succeeds), and
  `application::Limits::validate` is public. Writers, `rewrite`, `select`,
  `map_frames`, and `merge` refuse a zero stream limit with
  `capture_file::Error::InvalidLimit` (`cli.capture_limit`).
  `ip::Reassembler::new`, `tcp::Reassembler::new`, and
  `scope::Interner::with_limits` validate and return a `Result`;
  `tcp::Resource::InvalidWindowLimit` is removed because an oversized window is
  refused at construction. `scope::Limits::limit` is `max_scopes`, at most the
  new `scope::MAX_SCOPES`. `analysis::Limits` holds `tcp` and `ip` reassembly
  limits instead of ten flat `max_tcp_*`/`max_ip_*`/`*_idle_expiry` fields,
  and `tcp.max_flows` (concurrent directional flows) is now set directly
  rather than derived from `max_flows`. `decode::Options` and `build::Options`
  hold their `max_layers` and `max_packet_size` in a shared `packet::Limits`.
  See `docs/migration-unreleased.md`.
- `packetcraftr_cli::output` publishes the versioned machine contract with
  CLI-owned types wherever the contract's field names or variants differ from
  the library's (`envelope::ErrorContext`, `network::InterfaceId`,
  `analysis::Scope`, `fuzz::Outcome`, and others). Fields whose library types
  already serialize to the published shape embed those types directly —
  `packetcraftr::Stats`, `probe::{Transport, ProbeStatus}`,
  `capture::StopReason`, core `diagnostic::{Diagnostic, Severity}` and
  `frame::Direction`, and netio `capture::{Stats, TimestampSource,
  TimestampPrecision, Realized, RealizedSettings}` — re-exported from their
  output modules; `output::diagnostic` and `output::probe` are removed.
  Conversions are `From`/`TryFrom` only: the `from_*`, `try_from_*`, and
  `complete_from_*` constructors, `Report::new`, `Detail::new`,
  `Worker::progress`/`native`, and `provenance::from_source_set` are removed,
  and a conversion that also yields diagnostics or stats returns
  `envelope::Published<T>`. `http::Issue` and `dns_read::Issue` are structs
  instead of newtypes, and `tls::SelectionCounts` is removed.
  `protocols::Detail` embeds a flattened `summary: Summary` instead of
  repeating its seven fields, and `protocols::FilterField::for_protocol` and
  `from_binding` are replaced by `TryFrom<(&str, &FilterFieldBinding)>`, which
  fails with `Error::Unpublished` for a binding variant the contract has no
  spelling for instead of omitting it from `filter_fields`. output/v6 JSON is
  unchanged. See `docs/migration-unreleased.md`.
- Core's public API is a flat facade: every item has one documented path and
  nothing hidden is used from another crate. `packet::link` is private and its
  `MacAddress`, `VlanKind`, and `VlanTag` are at `packet::`. `dns::name` is
  private: `dns::decode_name` is the one name decoder (`name::decompress` and
  `name::Decompressed` are removed) and `MAX_LABEL_LEN`/`MAX_NAME_LEN` are at
  `dns::`. `layer::raw_layout` is `layer::Raw::layout`. The ICMP correlation
  helpers are documented: `protocol::QuotedIcmpError` is `IcmpErrorKind`,
  `QuotedProbeTransport` is `QuotedTransport`, and `quoted_icmp_error_kind` is
  `quoted_icmp_error`. `reflective_layer!`, `layer::ReflectiveField`, and the
  `reflect_*` helpers are documented API for custom layers; the macro's
  `protocol:` expression must now be a constant expression (`children:` values
  already had to be). The `display_via_as_str!` macro is no longer exported,
  and the `frame::GlobalInterfaceId` alias is removed in favor of `u32`.
  `transform::Error::{Invalid, Unsupported, Limit}` carry the typed
  `transform::{InvalidInput, Unsupported, Limit}` reasons, and
  `fuzz::Error::{InvalidLimit, InvalidTarget, InvalidBasePacket}` carry
  `fuzz::{Constraint, TargetFault, BaseFault}`; messages and codes are
  unchanged. See `docs/migration-unreleased.md`.
- Route planning moved from `packetcraftr_netio::route` to
  `packetcraftr::route`: `plan`, `Plan`, `Options`, `Error`,
  `materialize`, and `Materialized`. netio keeps the route contract
  (`Provider`, `Decision`, `Scope`, `SelectionReason`, `SystemProvider`,
  `Error`). `Client::plan` returns `packetcraftr::route::Plan`.
  Transmission frames take a borrowed `transmit::Route` view (decision, link
  mode, lookup destination) instead of `&route::Materialized`, and
  `Frame::route()` returns it; build one with `Materialized::transmit_route`.
  `Materialized::for_prepared_layer2_frame` is removed. See
  `docs/migration-unreleased.md`.
- Neighbor resolution moved from `packetcraftr_netio::neighbor` to
  `packetcraftr::neighbor`: `Error`, `Request`, `Resolution`, and
  `Options`. The `Client` now resolves neighbors itself over its transmit and
  capture providers, so `Client<R, N, I>` is `Client<R, I>`, `Client::new`
  takes no resolver, and `probe::ExchangeExecutor<'a, R, N, I>` is
  `ExchangeExecutor<'a, R, I>`. `neighbor::Resolver`, `ActiveResolver`, and
  `SystemResolver` are removed; set the bounds with
  `Client::with_neighbor_options`, which validates them. `Client::send` and the
  send-set methods now require `I: capture::Provider` as well, since a Layer 2
  send may resolve a neighbor. `route::materialize` is no longer public: the
  client materializes admitted plans. `link::MAX_VLAN_TAGS` moved to
  `packetcraftr::neighbor::MAX_VLAN_TAGS`, and its cap now bounds only plans
  that run ARP/NDP discovery (see Fixed). Error messages and codes are
  unchanged. See `docs/migration-unreleased.md`.
- `interface::Provider::interfaces` returns the new
  `packetcraftr_netio::interface::Error` (`Unsupported`, `Discovery` with a
  required source) instead of `packetcraftr_netio::Error`. Its messages and
  codes (`capability.unsupported`, `io.interface_discovery`) match the old
  variants, and `From<interface::Error> for packetcraftr_netio::Error` keeps
  `?` working. See `docs/migration-unreleased.md`.
- netio providers share one shape: each capability is `<capability>::Provider`
  plus `<capability>::SystemProvider`, and every provider trait requires
  `Send + Sync`. Transmission is one `transmit::Provider` with
  `send(Outbound)`; `transmit::SystemProvider` sends Layer 2 or Layer 3
  through the backend built for that layer and returns
  `capability.unsupported` for a layer this build lacks. `transmit::Sender`,
  `Layer2Sender`, `Layer3Sender`, `SystemLayer2`, `SystemLayer3`, and
  `ModeSender` are removed, and `transmit::Frame` is renamed
  `transmit::Outbound`. `route::Provider::classify_error` is removed: the
  provider's `Error` must implement `Classified`, which the planner and route
  errors now read. `tcp::Provider` requires `Send + Sync` and `tcp::Stream`
  requires `Send`. See `docs/migration-unreleased.md`.
- A capture group is a `capture::Session`. `capture::group` is private; its
  types are `capture::{Group, GroupRequest, Source, Phase, MAX_SOURCES}`.
  `Group::new(&request)` validates and `group.arm(&provider, &deadline)`
  arms, and the group waits, reads, and stops through `Session`
  (`wait_ready`, `next_captured_frame`, `shutdown`). `Record` is gone:
  `Captured::source` names the source, and `Session::source_count`/`source_metadata` describe
  every source. `group::{Error, Cause, Failure}` fold into
  `packetcraftr_netio::Error` (`InvalidCaptureGroup`, `CaptureSource`,
  `CaptureSourceContract`, `CaptureGroupState`, `CaptureCleanup`) with the
  same `cli.capture_group`/`internal.capture_group` codes. After any failure,
  `Group::snapshot` still reports every admitted source and `shutdown` reports
  the cleanup failures. `packetcraftr::capture::{Cause::Native, Error::cleanup}`
  and `scan::PipelineError::cleanup` carry `packetcraftr_netio::Error`. See
  `docs/migration-unreleased.md`.
- Every provider call that can block takes the caller's core
  `budget::Deadline` by reference, which also carries its cancellation:
  `route::Provider::{lookup_with_preferences, lookup_interface}`,
  `interface::Provider::interfaces`,
  `capture::Provider::{arm_capture, timestamp_types}`,
  `capture::Session::{wait_ready, next_captured_frame}`, `tcp::Provider::connect`,
  `tcp::start_connect`, and `capture::Group::arm` (a group waits and reads
  through the same `Session` methods). `capture::Cancellable` is removed:
  native capture waits honor the deadline's cancellation themselves. `packetcraftr::route::plan`,
  `Client::plan`, and `replay::Transmitter::plan_frame` take the deadline their
  lookups receive, and `neighbor::Request` loses its `deadline` field.
  `route::Error` and `interface::Error` gain `Cancelled` and
  `DeadlineExceeded` variants, and `tcp::ConnectError` gains
  `DeadlineExceeded` (`io.deadline_exceeded`). See
  `docs/migration-unreleased.md`.
- netio errors follow the workspace error convention:
  - One unsupported representation: `packetcraftr_netio::Error::Unsupported`,
    `route::Error::Unsupported`, and `interface::Error::Unsupported`
    each carry the new `packetcraftr_netio::Unsupported { capability,
    message, source }`. Its `NativeCapability` (`Route`,
    `InterfaceEnumeration`, `Capture`, `Transmission(Mode)`) decides the
    class, so `capability.route` and `capability.unsupported` and the
    messages are unchanged.
  - The `packetcraftr_netio::SystemFault` alias is removed. Type-erased sources
    in netio errors and in `packetcraftr::dns::tcp::Error` are
    `packetcraftr_core::error::Source`, which exposes the wrapped error to
    `downcast_ref` directly.
  - `tcp::ConnectError` and the `io::Result` of `tcp::Provider::connect`,
    `ConnectOutcome::result`, `PendingConnect::poll`, and `tcp::start_connect`
    fold into `tcp::Error`. A provider's socket failure is
    `tcp::Error::Socket(io::Error)` (`From<io::Error>`, classified as the new
    `io.tcp_connect`), and a connection that never reached its provider reports
    `DeadlineExceeded` or `Cancelled` instead of a synthetic `io::Error`.
    Every other code is unchanged.
  - `SendEvidenceFault` implements `Classified`.
  - `tcp::Error::{Evidence, Spawn}`, `Error::InvalidSendEvidence`, and
    `SendEvidenceFault::UnrepresentableFrame` no longer repeat their source in
    their message; it appears in `causes`.

  See `docs/migration-unreleased.md`.
- Policy has one error type. `Policy::authorize` returns `policy::Error`, and
  `packetcraftr::Error::{Wire, PermissiveLiveOptInRequired}` move to
  `policy::Error::{UndecodableWire, PermissiveLiveOptIn}` (reached through
  `packetcraftr::Error::Policy`) with their codes unchanged.
  `packetcraftr::Error::UnsupportedOperation` is removed rather than moved,
  and its code `internal.unsupported_operation` is no longer reported (see
  Removed). `policy::Error` drops `Clone`, `PartialEq`, and `Eq`.
- Declared operation ceilings are named limits: `policy::{WireBudget,
  SocketBudget, BudgetOverflow}` become `policy::{WireLimits, SocketLimits,
  LimitOverflow}`, `Operation::Budgeted` becomes `Operation::Wire`, the
  operations' `budget()` accessors become `limits()`, and
  `dns::Error::BudgetOverflow` becomes `dns::Error::LimitOverflow`. The
  `policy.budget_overflow` code is unchanged.
- `Stats` is the one name for counters: `packetcraftr_netio::capture::Statistics`
  and `packetcraftr::scan::connect::Statistics` become `Stats`, and
  `capture::Session::statistics()` becomes `stats()`. Serialized names are
  unchanged.
- The per-workflow duration ceilings `scan`, `traceroute`, `dns`, and `fuzz`
  `MAX_DURATION`, `replay::MAX_REPLAY_DURATION`, `send::MAX_SEND_DURATION`, and
  `exchange::MAX_EXCHANGE_TIMEOUT` are removed. Each equaled
  `packetcraftr_netio::deadline::MAX_WAIT`, which every workflow now checks
  directly. See `docs/migration-unreleased.md`.
- Scan and traceroute each have their own error. `probe::Error { workflow,
  kind }`, `probe::ErrorKind`, and `probe::Workflow` are replaced by the
  `scan::Error` and `traceroute::Error` enums, whose variants are the former
  kinds that workflow raises; connect scan returns `scan::Error`. Codes,
  messages, coordinates, and causes are unchanged.
- One event-sink contract: `packetcraftr::Sink<E>` has an `Ack` answer type
  and `publish(event)`, and every `FnMut(E) -> Result<A, BoundaryError> +
  Send + 'static` closure implements it. The event entry points of scan,
  connect scan, traceroute, DNS, DNS batch, and fuzz (live and offline) take
  `S: Sink<Event, Ack = ()>` instead of a closure bound; a closure whose
  argument type was inferred from that bound names it. `progress::Sink` is
  renamed `runtime::Worker<T, A = ()>`, and its callback may answer a value
  that `emit` returns.
- `probe::{EPHEMERAL_SOURCE_PORT_BASE, ephemeral_source_port}` are no longer
  public.

  See `docs/migration-unreleased.md`.
- The `Client` owns its providers: `Client<P, K = SystemClock>` holds a
  `Providers` bundle (route, interface, capture, transmit, TCP, resolver),
  composed with `ProviderSet` or the native `SystemProviders`, and is built with
  `Client::new(registry, policy, providers)`. `with_clock`, `with_runtime`,
  `runtime()`, and `providers()` replace `with_progress_runtime` and
  `progress_runtime()`. `packetcraftr_netio::PacketIo` is removed.
- Send and exchange run on requests and sinks: `client.send(send::Request, S)`
  and `client.exchange(exchange::Request, S)` publish their events to a
  `Sink` and return the terminal `Report`; each workflow's `Collector` sink
  rebuilds the full `Aggregate`. `send_set`, `send_set_with_events`,
  `send_set_driven`, `send::SetOptions`, `send::SetReport`, and
  `exchange_with_events` are removed; `exchange::Options` splits into
  `exchange::Request` and the reusable `exchange::Collection`; the former
  `exchange::Summary` is `exchange::Report` and the former `exchange::Report`
  is `exchange::Aggregate`.
- `send::Error` and `exchange::Error` wrap the root preparation error
  `packetcraftr::Error`, which keeps only preparation failures. The send and
  exchange variants move to the workflow errors with unchanged codes:
  `SendOutput` and `InvalidSendOption` become `send::Error::{Output,
  InvalidRequest}`; `ExchangeOutput`, `ExchangeOutputAndCaptureShutdown`,
  `OperationAndCaptureShutdown`, `InvalidExchangeEvents`,
  `HeterogeneousExchangeRoute`, and `InvalidExchangeOption` become
  `exchange::Error::{Output, OutputAndCaptureShutdown,
  OperationAndCaptureShutdown, IncoherentEvents, HeterogeneousRoute,
  InvalidRequest}`.
- `clock::Clock` is `Clone + Send + Sync + 'static`, `now` takes `&self`, and
  `sleep(&self, delay, deadline)` returns early once the deadline's
  cancellation is signaled. The client anchors every deadline and send
  schedule on its clock.
- `route::Options.interface` is a `route::Interface` selector (`Id`, `Name`,
  or `Index`). A client resolves a name or index through its interface
  provider only after the operation is admitted; `route::plan` accepts only a
  resolved `Interface::Id` and otherwise fails with
  `route::Error::UnresolvedInterface`.
- Workflows are admitted only through the client: `policy::Authorizer`,
  `policy::PolicyAuthorizer`, and `policy::unsupported_operation` are removed
  from the public API, and target resolution is internal to the client, which
  resolves declared targets through its `resolver` provider. Use
  `Policy::authorize` and `Policy::resolve_target` to apply a policy directly.
- Live capture runs on the client: `client.capture(capture::Request, S)`
  replaces `capture::run`. `capture::Request::new(group, window)` replaces the
  provider, `GroupRequest`, and `capture::Options` arguments; the budget comes
  from the client's policy and cancellation from the client. A frame selector
  is set with `Request::with_selector`, and events reach a
  `Sink<capture::Event>` whose answer converts into `capture::Control` (`()`
  continues).
  `capture::Source` holds the source fields itself instead of a public
  `capture: netio::capture::Source`, and `Event::Started` carries
  `capture::Source` values.
- TCP connect scans run on the client: `client.scan_connect(scan::Request, S)`
  replaces `scan::connect::run` and `run_with_events` and connects through the
  client's TCP provider. Events are `connect::Event::Probe(ProbeEvidence)`
  (the former `connect::Probe`); the former `connect::Summary` is
  `connect::Report`, and the former `connect::Report` is
  `connect::Aggregate { report, endpoints }`, rebuilt by `connect::Collector`.

  See `docs/migration-unreleased.md`.
- Scan and traceroute run on the client: `client.scan(scan::Request, S)` and
  `client.traceroute(traceroute::Request, S)` publish their events to a `Sink`
  and return the terminal `Report`, and `scan::Collector` and
  `traceroute::Collector` rebuild the `Aggregate`. `scan::{run,
  run_with_events}` and `traceroute::{run, run_with_events}` are removed. Both
  requests gain `route: route::Options` and `collection: exchange::Collection`
  and no longer implement `Serialize`/`Deserialize`. The former `Summary` of
  each is its `Report`, and the former `Report` its `Aggregate`; both gain an
  `Error::IncoherentEvents` variant for a collector finished with another
  run's report.
- Pipelined scan execution is internal to the client: `probe::Executor` loses
  `pipeline_capacity` and `execute_pipeline`, `probe::{PipelineOptions,
  PipelineEvent}` are removed, and a request with `max_in_flight` above one
  always runs pipelined, so `capability.probe_pipeline` is no longer reported.
  `scan::PipelineError` is renamed `scan::PipelineFailure`. The
  `scan::Batch` and `traceroute::Batch` aliases are removed.
- `scan::ResponseClassification` and `traceroute::ResponseClassification` are
  renamed `CorrelatedResponse`. `traceroute::Completion` is renamed
  `traceroute::Termination`, and the report and aggregate field `completion`
  is `termination`; the published `completion` field is unchanged.
- Replay runs on the client: `client.replay(replay::Request, S)` publishes
  `replay::Event::Frame(FrameEvidence)` to a `Sink` and returns
  `replay::Report` (the former `replay::Summary`); `replay::Collector` rebuilds
  the `replay::Aggregate`. The request carries a `replay::Source` (`stream` or
  `seekable` for repetition), a `Selector` (default `AllFrames`), and
  `replay::Options`, which gains `allow_permissive_live`. `run_with_selector`,
  `run_repeated_with_selector`, `SystemAuthorizer`, `SystemTransmitter`, and
  `replay::Transmitter` are removed: the client's policy admits each frame and
  its interface, route, and transmit providers carry it.
  `policy::Authorizer::authorize_final_wire` is removed. `replay::Error::Output`
  keeps the sink's `BoundaryError` as its `source` (still `io.replay`), and
  `Error::output_at_source_index` is removed; `replay::Error` adds
  `IncoherentEvents` (`internal.replay_event_coherence`).
- DNS runs on the client: `client.dns(dns::Request, S)` returns the terminal
  `dns::Report` (formerly `Summary`) and `dns::Collector` rebuilds the
  `dns::Aggregate` (formerly `Report`); `client.dns_batch(dns::batch::Request,
  S)` returns `dns::batch::Report` (formerly `BatchReport`), publishes
  question-tagged `dns::batch::Event`s, and `dns::batch::Collector` rebuilds
  `dns::batch::Aggregate`. `dns::Request` gains `route` and `collection`.
  `dns::{run, run_with_events, run_batch, run_batch_with_events}`, the
  executor seam (`Exchange`, `Execution`, `TcpExchange`, `TcpExecution`,
  `TcpExecutor`, `TcpExchangeExecutor`, `with_dns_tcp`) are removed from the
  public API; DNS-over-TCP queries the client's `tcp` provider.
  `dns::tcp::exchange` is `dns::tcp::query`, `dns::EvidenceError` is
  `dns::IncoherentReport`, `MAX_QUESTIONS`, `QuestionStatus`, and
  `QuestionOutcome` (now `Question`) move to `dns::batch`.
  `dns::Error::Authorization` no longer converts from `BoundaryError`,
  `InvalidEvidence` carries a typed `dns::EvidenceFault`, and a TCP executor
  rejecting the workflow's own request is `TcpRequestRejected`.
- Live fuzz runs on the client: `client.fuzz(fuzz::Request, S)` admits the
  campaign through the client's policy and returns `fuzz::Report`;
  `fuzz::Collector` rebuilds the `fuzz::Aggregate`. `fuzz::Request` wraps
  core's campaign request and replaces `RunInput`, `LiveOptions`, and
  `LiveLimits` (`allow_malformed_live` is `allow_permissive_live`; the evidence
  bounds are `max_evidence_frames` and `max_evidence_bytes`). The live
  duplicates of core's campaign types are removed: `fuzz::Trial` pairs
  `packetcraftr_core::fuzz::Case` with the optional live `fuzz::Evidence`,
  whose `fuzz::Outcome` is `Response` or `Timeout`; `fuzz::Report` composes
  the campaign's core `Stats` with the traffic `Stats`, replacing `fuzz::Stats`
  and `fuzz::Summary`. `fuzz::run`, `fuzz::run_with_events`,
  `fuzz::run_offline_with_events` (use `packetcraftr_core::fuzz::run_observed`),
  and the public `fuzz::{Execution, ExecutionCase}` are removed.
  `fuzz::{Totals, IncoherentReport}` move to `packetcraftr_core::fuzz`. The
  published fuzz output is unchanged.

  See `docs/migration-unreleased.md`.
- The workflow crate's public surface is the client model: every workflow is
  a `Client` method, and the seams the client owns are internal.
  `probe::{Executor, Request, ExchangeExecutor, Batch, Execution}`,
  `clock::CancellableClock`, and `Clock::cancellation` are removed; the client
  carries cancellation to every workflow. The `progress` module is renamed
  `runtime` (`runtime::{Runtime, RuntimeSnapshot, Worker, Error,
  MAX_WORKER_CAPACITY}`; `EmitError` is `runtime::Error`). `SystemProviders` is a unit struct implementing
  `Providers` instead of an alias of `ProviderSet`, and `ProviderSet::system`
  is removed. The `capture::Selector` alias is removed (use
  `capture::Request::with_selector`), and `scan::PipelineFailure` is its
  type's own name. `dns::AttemptTransport` is `dns::TransportEvidence`, and
  `dns::AttemptEvidence::exchange` is `transport_evidence`: a TCP attempt is a
  query, not an exchange. `scan::connect::Probe` is
  `scan::connect::ProbeEvidence`. `fuzz::Error::Authorization` no longer
  converts from `BoundaryError`.

  See `docs/migration-unreleased.md`.
- Selectors live beside what they select. Core `filter::{FrameDecoder,
  FrameSelector}` decode and select complete frames under one byte budget;
  `filter::Error` adds `Decode` (the decoder's own error and classification)
  and `StreamIndexUnavailable`, and no longer implements `PartialEq`/`Eq`.
  `analysis::Options` adds `stream`, the conversation `Session::new` now
  selects directly instead of through a `tcp.stream == N` filter.
  `analysis::tls::{Selector, SniPattern}` select assembled sessions and
  `analysis::expert::Selector` selects findings; `analysis::Error` adds
  `SniPattern`. A `replay::Request` carries its selection as data: an
  optional `filter` (`FrameSelector`, set with `with_filter`) and a
  `replay::routing::Routing` of `routing::Rule`s (`Condition::Source` or
  `Condition::Filter`, each naming a `route::Interface`) with an optional
  fallback, at most `routing::MAX_RULES`. `Rule::parse_source` and
  `Rule::parse_filter` parse `SOURCE_ID=INTERFACE` and `EXPR=>INTERFACE`
  rules and refuse with `replay::routing::Error`. `replay::{Selector, AllFrames}`,
  `Request::with_selector`, and `replay::Options::interface` are removed.
  `replay::Error::Selection` carries a `filter::Error`, and
  `ConflictingInterfaces` and `Unmapped` (`cli.error`) replace
  `InvalidLimit { field: "interface" }` for a frame routed two ways or
  nowhere.

  See `docs/migration-unreleased.md`.
- Each module has one error type, named `Error` and used module-qualified:
  `packetcraftr_netio::route::SystemError` is `route::Error`, and
  `packetcraftr::runtime::Error` (formerly `progress::EmitError`) implements
  `Classified`. `packetcraftr::SentPacket` moves into the public `evidence`
  module (`packetcraftr::evidence::SentPacket`) beside the evidence `Error`.
  DNS wire handling is the `dns::wire` sub-domain: `dns::WireError` is
  `dns::wire::Error` (now `Classified`: `packet.dns_query` for a query that
  cannot be built, `packet.dns` for a response that breaks a wire rule, and
  the codec's or core DNS error's own class for `Encode` and `Decode`, which
  are transparent), `dns::{canonical_query_name, decode_response,
  decode_tcp_frame, encode_query}` are `dns::wire::…`, and
  `dns::QueryTypeParseError` folds into `wire::Error` (`QueryTypeSyntax`,
  `QueryTypeRange`). The UDP profiles document's data lives in core:
  `scan::profile::{Config, Payload, ResponseCheck, ByteCheck,
  MAX_PROFILE_PORTS, MAX_PROFILE_BYTES}` are
  `packetcraftr_core::document::udp_profiles::…`, and `scan::profile::Error`
  is an enum whose `Invalid` variant replaces the tuple struct and which also
  carries the document refusals (`Document`, `PortCount`, `Storage`,
  `ConflictingPort`, `MappedPorts`). Classification codes are unchanged.
  See `docs/migration-unreleased.md`.
- `packetcraftr_cli::output::verify_forwarding::Input` is a struct with
  `path`, `source`, and `selection_filter` fields instead of a tuple alias.
- Core limit vocabulary is uniform: `expression::Options` is
  `expression::Limits`, `filter::Options` is `filter::Limits` (each gains a
  public `validate()` with the same checks), `dns::DecodeLimits` is
  `dns::Limits`, `forwarding::VerifyLimits` is `forwarding::Limits`,
  `layout::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE}` moved to `packet::`,
  `frame::DEFAULT_SIZE_LIMIT` is `frame::DEFAULT_MAX_SIZE`, and the
  `capture_file` defaults are `DEFAULT_MAX_INTERFACES_PER_SECTION`,
  `DEFAULT_MAX_TOTAL_INTERFACES`, `DEFAULT_MAX_METADATA_BLOCKS_PER_FRAME`,
  `DEFAULT_MAX_METADATA_BYTES_PER_FRAME`, `DEFAULT_MAX_STREAM_FRAMES`, and
  `DEFAULT_MAX_STREAM_BYTES`. See `docs/migration-unreleased.md`.
- IPv6 Fragment headers with the reserved byte or the two reserved bits set, and
  Segment Routing headers with a non-zero flags byte, now decode instead of
  becoming `Malformed` layers, because RFC 8200 and RFC 8754 have receivers
  ignore those bits. The layers keep the bits and report
  `decode.ipv6_fragment_reserved` or `decode.srh_flags` warnings, so such
  fragments are counted and reassembled. Strict builds refuse the bits;
  permissive builds write them and report `build.ipv6_fragment_reserved` or
  `build.srh_flags` (SRH flags previously never built). Live authorization and
  response matching still refuse a Segment Routing header with non-zero flags.
  `network::Fragment` gains public `reserved` and `reserved_bits` fields, so
  struct literals that name every field need `..Fragment::default()`. Every
  IPv6 Fragment layer, including one whose reserved bits are zero, now also
  lists `reserved` and `reserved_bits` among its fields and layout in `dissect`
  and `read --dissect` JSON and NDJSON, in `capture --dissect` NDJSON, and in
  packet documents, and `protocols ipv6_fragment` lists both fields, so `read --field ipv6_fragment.reserved`
  reads a value where it was refused with `cli.projection_field`; consumers
  pinned to the previous field set see two additional fields. See
  `docs/migration-unreleased.md`.
- `tls::Extension` is now `{ kind, data }`: the `len` field, which always
  equalled the body length, is removed, so read `extension.data.len()` instead.
  `Hello.extensions` uses the same `Extension` type, and the `server_name` and
  `alpn` constructors are `Extension::{server_name, alpn}`. Wire bytes,
  reflected `hello.extensions` values, and JA3/JA4 are unchanged. See
  `docs/migration-unreleased.md`.
- `protocol::semantics::Error` no longer has the `LayerIndexOutOfRange` and
  `SegmentCountUnrepresentable` variants, which no reachable code path
  produces; delete any match arms that name them. See `docs/migration-unreleased.md`.
- `packetcraftr_core::fuzz::{Summary, Report}` no longer have a `diagnostics`
  field, which no campaign ever filled (per-case diagnostics stay on
  `Case::diagnostics`), and `fuzz::CaseFailure::new` is removed; build a
  `CaseFailure` with `CaseFailure::with_source`. The published fuzz envelope
  still emits `diagnostics: []`. See `docs/migration-unreleased.md`.
- `packetcraftr_core::codec::LayerDecodeContext` drops its
  `allow_trailing_padding` field, which no codec read; delete it from struct
  literals. Link-padding classification stays with
  `Registry::allows_trailing_padding` and the decode session. See
  `docs/migration-unreleased.md`.
- `packetcraftr_cli::output::capture::Event` is removed. Capture NDJSON `frame`
  records are emitted as `output::read::Frame`, which now implements
  `StreamRecord`; the JSON is unchanged. See `docs/migration-unreleased.md`.
- Display filters reject an unquoted word that is neither separated bytes nor
  quoted text as a value on byte and MAC fields and on byte-sliced fields.
  Examples are an unseparated hex run (`deadbeef`, `c000`) and a malformed
  separated word with one-digit or empty groups or mixed `:` and `-`
  separators (`47:45:5`, `c0:0`, `aa:bb-cc`), as in
  `raw.bytes contains 160301ff`, `ethernet.source[0:2] == c000` and
  `verify-forwarding --expect raw.bytes=deadbeef`. The filter fails with a
  `cli.filter` usage error (`filter::Error::UnquotedByteWord`) that names the
  word and advises writing bytes as two-digit groups with separators such as
  `c0:00` or, on byte fields, quoting the word. Before, on byte fields these
  compiled into an ASCII text comparison that matched only frames carrying
  those literal characters, never the intended bytes, and on MAC fields they
  failed as an incompatible literal with the remediation `compare the field
  against a value of its own type`. Because sliced fields read bytes,
  hex-looking words on sliced Text fields such as
  `tls.sni[0:4] == cafe` now need quotes too. Unsliced Text fields, quoted
  text, `0x` numbers and words with a group longer than two characters or a
  non-hex character (`contains GET`, `2026-09-29`, `host:80`) are unchanged.
  Every other incompatible literal keeps its remediation, `compare the field
  against a value of its own type`. See `docs/migration-unreleased.md`.
- `exchange::Report` no longer has the `diagnostics` field, which was always
  empty, so it is now `Report { unanswered, stats }`. Diagnostics still arrive
  as `Event::Diagnostic`, and `exchange::Collector` still collects them into
  `Aggregate::diagnostics`. Machine output is unchanged. See
  `docs/migration-unreleased.md`.
- `runtime::Runtime::new` now returns `Result<Runtime, runtime::CapacityError>`
  and refuses a worker capacity above `MAX_WORKER_CAPACITY` (8) instead of
  silently lowering it to the ceiling. `CapacityError` carries the refused value
  and the maximum and classifies as `cli.worker_capacity` (usage). A capacity of
  zero stays valid and still refuses every publication, and `Runtime::default()`
  is unchanged. The CLI only requests 1 or the maximum, so its behavior and
  machine output are unchanged. See `docs/migration-unreleased.md`.
- `decode::DecodedPacket::original` is removed; read the exact bytes through
  `decoded.frame.bytes()`. See `docs/migration-unreleased.md`.
- Replay frame admission is internal to the crate. `policy::Operation::Replay`,
  `policy::ReplayFrame`, and `policy::Operation::shape()`, which only labeled
  the removed `UnsupportedOperation` error, are removed; match on the
  `Operation` variant instead. `Policy::authorize` no longer accepts a replay
  operation; the client's policy admits each replay frame internally.
  `replay::FrameEvidence::source_interface_id` is removed because it always
  equalled `frame.interface`; read `evidence.frame.interface`. Replay output,
  error codes, and capture bytes are unchanged. See
  `docs/migration-unreleased.md`.
- New public struct fields break struct literals outside the crate.
  `capture_file::MergeLimits` gains `order: MergeOrder` and
  `max_reorder_frames: usize` (end a literal with `..Default::default()`),
  `transform::rules::Rule` gains `map: Option<AddressMap>` (it has no
  `Default`, so set `map: None`),
  `codec::LayerDecodeContext` gains `hop_limit: Option<u8>`, the TTL or hop
  limit of the enclosing IP header (`None` when unknown), and
  `expression::Limits` gains `max_generated_bytes` (end a literal with
  `..Limits::default()`). Several of these types are themselves new since
  0.5.0-beta.3. See `docs/migration-unreleased.md`.
- The live request types gain the fields behind the new options.
  `traceroute::Request` and `traceroute::Probe` gain `payload_size: u16`,
  `dont_fragment: bool`, and `dscp: u8`; `exchange::Request` gains `stop:
  exchange::StopCondition` (`Window` keeps the previous behavior); and
  `replay::Options` gains `max_gap: Option<Duration>` (`None` keeps it).
  Struct literals outside the crate must name the new fields. See
  `docs/migration-unreleased.md`.
- `protocol::BuiltinProtocol` is not `#[non_exhaustive]` and gains `Eapol`,
  `Etherip`, `Gtpu`, `Lldp`, `Stp`, `Syslog`, `Tftp`, and `Vrrp`, so exhaustive
  matches need new arms. `protocol::network::ndp::MessageOption` is now
  `#[non_exhaustive]` and gains typed variants for the Prefix Information,
  Redirected Header, MTU, Route Information, and RDNSS options (kinds 3, 4, 5,
  24, and 25), which decoded as `MessageOption::Other` before when they fit
  their layout; `MessageOption::value()` returns an owned `Bytes` instead of
  `&Bytes`. See `docs/migration-unreleased.md`.

### Added

- Scanner port planning and state inference (roadmap M6). `scan --ports`
  accepts catalog names (`ssh`), `@presets` (`@web`, `@mail`,
  `@name-services`, `@infrastructure`, `@legacy-services`, `@all`), and
  `tcp:`/`udp:` prefixes beside numbers and ranges, and `--exclude-ports`
  removes endpoints before any stage plans them. `--transport tcp,udp` plans
  both transports under one budget with distinct endpoints. Every endpoint
  publishes a `port_hint` from the bundled, provenance-recorded port catalog
  and an `inference` (state, rule, and supporting, conflicting, unanswered, and
  failed attempts) beside its unchanged attempt outcomes; silent UDP is
  `open_or_filtered`, and socket deadlines and local errors are operational
  failures, never port states. Late, duplicate, and ambiguous replies are
  retained as `unattributed` evidence under `--max-undecoded`. `--method
  raw|tcp-connect|auto` publishes the requested and selected method; explicit
  methods are never replaced. `--curated-udp-payloads` adds bundled UDP
  profiles for seven protocols, with operator profiles winning visibly.
  `scan --list` publishes the expanded port selection. Results name the
  catalog and payload data versions.
- `scan --targets-file`/`--exclude-file` bounded manifests (with `-` stdin),
  `scan --list` target planning, and scoped `fe80::/10%zone` targets carried
  through selection, connect sockets, and raw route planning. Malformed or
  oversized manifests fail as `source:line:` before any provider call, and
  `scan --list` warns once per coalesced duplicate declaration with its
  source. Structured output moves to `packetcraftr.output/v7` (target-list
  branch, optional `scope` fields, exact `retained_evidence_bytes`); the v6
  family and its schema/fixture stay frozen.
- The isolated Linux launcher's `scoped_ipv6_targets` scenario: list,
  ordinary-connect, and raw TCP SYN scans of zone-qualified link-local
  targets over namespace-local veth pairs that share one address pair, so
  only the zone selects the peer. Native-isolated release evidence now
  requires it.
- The [scanner corpus](docs/scanner-corpus.v1.json)
  (`packetcraftr.scanner-corpus/v1`), its
  `scanner_fixture` example driver (deterministic injected providers on the
  real scan and traceroute paths, never native I/O), and the
  `scripts/benchmark-scanner.py` on-demand 88-condition benchmark with a
  pinned Nmap 7.991 agreement check; corpus expectations are independent of
  Nmap. The M2 milestone stays in progress pending methodology review and the
  unsupported-workflow limitations.
- The `native_loopback` macOS/Windows evidence suite (seven ignored
  scenarios, `packetcraftr_test_host_loopback` build cfg) and the manual
  reviewed-native workflow on disposable hosted runners; actual platform
  recordings are pending, so M3 stays in progress.
- A [core scanner roadmap](docs/roadmap/README.md), one specification per
  milestone, and a source-backed Nmap gap matrix document planned discovery,
  scanning, identification, performance, and cross-platform work. These are
  future plans, not newly implemented features.
- The completed first roadmap milestone documents the [scanner claims and
  evidence model](docs/scanner-evidence.md) — host observations, port
  inference, attempt outcomes, and operational failures as separate
  vocabularies, with every current scan output field assigned to one — and the
  [scanner data policy](docs/scanner-data-policy.md) governing provenance,
  license review, versioning, maintenance, and coverage for bundled port,
  service, OS, and vendor data. No scan behavior or output schema changes.
- `ReaderLimits::max_options_per_block` (default 1,024) bounds the options
  retained from one PCAPNG section, interface, or packet block; a block above
  the ceiling fails with `policy.capture_stream_limit`. Exhaustive
  `ReaderLimits` literals need the new field.
- `packetcraftr http2` inspects cleartext HTTP/2 and h2c-upgraded TCP streams
  offline: RFC 9113 frames, stateful HPACK decoding, stream/message lifecycle,
  and per-connection startup/status evidence, with eleven HTTP/2-specific
  analysis limits and NDJSON `http2_frame`, `http2_message`, `http2_issue`,
  `http2_connection`, and `complete` records under `packetcraftr.output/v6`.
  DATA bodies are counted and discarded, never retained. The public
  `analysis::http2::Collector` and `Event`/`Message`/`Frame`/`Issue`/
  `Connection` types expose the same engine. Examples cover
  `examples/captures/http2-multiplexed.pcapng` and
  `examples/captures/http2-upgrade.pcapng`. Ordinary capture EOF reports
  incomplete open connections with bounded partial evidence instead of TCP
  eviction; a reuse of a cleanly closed tuple emits a new generation without
  relabelling the earlier one; observer deadlines are enforced at record
  observation and at connection finalization. An unaccepted h2c offer survives
  as an `incomplete_upgrade` issue retaining the original HTTP/1 request head
  and its physical sources without fabricated HTTP/2 stream IDs; an accepted
  upgrade keeps the real request on stream 1 with `upgrade_head`. Four
  libfuzzer targets (`http2_wire`, `http2_hpack`, `http2_segmentation`,
  `http2_pipeline`) run in the scheduled fuzz workflow.
- `packetcraftr_core::packet::Packet::iter_of` and `iter_of_mut` iterate every
  layer of one concrete type in packet order (double-ended, no allocation).
  The mutable iterator clears cached encoded payload lengths whenever a match
  exists, even if dropped unconsumed; a no-match call leaves the cache intact.
- `packetcraftr_core::frame::Frame::is_truncated` reports whether the
  captured length is below the frame's declared original length.
- Classification codes new in this release, each for a failure that
  previously had no classified error of its own (or, for `cli.worker_capacity`,
  was not a failure):
  - `cli.layer_index` (usage): `packet::Error::IndexOutOfBounds`, a layer
    index outside the packet.
  - `cli.worker_capacity` (usage): `runtime::CapacityError`, a `Runtime`
    requested with a worker capacity above `runtime::MAX_WORKER_CAPACITY`,
    which used to be lowered silently.
  - `internal.registry`: `registry::Error`, a protocol, alias, link type,
    matcher, or filter field registered twice or inconsistently.
  - `internal.unresolved_interface`: `route::Error::UnresolvedInterface`, a
    route planned with an interface selector no client resolved first.
  - `internal.send_event_coherence`, `internal.scan_event_coherence`, and
    `internal.traceroute_event_coherence`: a `Collector` given events that do
    not form one publication, like the existing `internal.*_event_coherence`
    codes of the other workflows.
  - `io.send_clock`: `send::Error::Clock`, the pacing clock failing while a
    paced send could still continue.
  - `packet.semantics`: `protocol::semantics::Error`, route-bearing packet
    fields that are malformed or ambiguous.
  - `packet.tls`: `protocol::application::tls::Error::Invalid`, a TLS record
    or handshake that breaks a wire rule or bound.
- `packetcraftr_core::error::BoundaryError::as_causes` lists a boundary
  error's message followed by its captured causes, for a wrapper that reports
  it as its source without repeating its text.
- `scan::MAX_IN_FLIGHT` (1024) names the most probe response windows one scan
  overlaps; request validation and the pipeline share it.
- `packetcraftr::evidence::Error` is public, implements `Classified`
  (`internal.live_io_invariant`), and names why the evidence an executor
  returned is inconsistent with its step, including the new `PermitMismatch`.
- `packetcraftr_netio::resources::WORKER_CAPACITY` names the capacity of the
  one native worker pool (16). `tcp::MAX_PENDING_CONNECTIONS` equals it, so a
  TCP connect is refused only while the whole pool is busy, and
  `capture::MAX_SOURCES` is 15, so a full capture group leaves a slot free for
  the Linux netlink route worker; a group naming 16 interfaces is refused up
  front with `cli.capture_group`.
- `packetcraftr_core::error::Classified` is implemented for
  `std::convert::Infallible`, so a provider that cannot fail satisfies a
  `Classified` error bound.
- `packetcraftr_netio::deadline` states the provider deadline convention and
  adds `remaining`, `expires_at`, and `detach` for providers that follow it.
  `packetcraftr::deadline::PASSIVE_LOOKUP_TIMEOUT` is the allowance a passive
  route or interface lookup gets when its operation has no deadline; the CLI
  gives `routes`, `interfaces`, and `plan` lookups that allowance within the
  invocation deadline.

- `packetcraftr_core::fuzz::Totals` checks a campaign's case counts and cases
  for coherence (`TryFrom<&Report>`, `TryFrom<&Stats>`, `check_cases`, and
  `TryFrom<&packetcraftr::fuzz::Aggregate>` for a live campaign), failing with
  `fuzz::IncoherentReport`. The CLI's `internal.fuzz_event_coherence` check
  now uses it. `fuzz::Campaign::stats` reports what preparation generated and
  built.

- The versioned input documents and their rules are library API, so other
  consumers read them exactly as the CLI does. Core `transform::rules::Rules`
  reads `packetcraftr.rewrite/v2` documents (`Rules::parse`, failing
  with `transform::rules::Error`), builds one rule from direct edits
  (`Rules::single`), reports the VLAN growth a map needs
  (`maximum_growth`), and applies the rules in order to a frame with a
  caller-compiled filter (`try_map_filters`, `apply`).
  Core `document::udp_profiles::parse` reads a
  `packetcraftr.udp-profiles/v1` document into its assignments as neutral
  data (`document::udp_profiles::Error`), and
  `packetcraftr::scan::profile::compile` compiles them into per-port
  profiles. A profiles document whose `any` or `dns` response carries an
  unknown field, such as `checks` or `min_length`, is refused as `invalid UDP
  profiles`, as the published schema requires. Core `document::recipe::parse`
  reads recipe text as a JSON or YAML packet document or a layer expression
  (`document::Format::{from_path, sniff}`, `document::recipe::Error`), and
  `document::payload::Target` fills an empty bytes field from outside the
  recipe (`document::payload::Error`). `transform::fragment_link_type` frames an
  Ethernet, IPv4, or IPv6 recipe for `transform::fragment`. Document formats,
  CLI flags, and error codes are unchanged.
- `protocol::network::ndp` types Neighbor Solicitation and Neighbor
  Advertisement bodies with their source and target link-layer address options
  (`NeighborSolicitation`, `NeighborAdvertisement`, `MessageOption`,
  `solicited_node_multicast`). Decoding keeps reserved bits and unknown
  options, and a decoded body re-encodes byte for byte. `ndp::Error`
  implements `Classified` (`packet.codec`). The models are not
  registered layers, so dissection output is unchanged.
- `packet::MacAddress::for_ip_multicast` maps an IPv4 or IPv6 multicast group
  to its Ethernet group address.
- `packet::MacAddress::BROADCAST` names the Ethernet broadcast address, and
  `protocol::link::Arp::OPERATION_REQUEST` and `Arp::OPERATION_REPLY` name the
  RFC 826 operation codes (1 and 2). `Arp::default()` still builds a request,
  and wire bytes are unchanged.

- `protocol::headers` is a public, bounded walker over raw link, VLAN, and IP
  header bytes (`LinkHeader`, `EthernetHeader`, `IpHeader`, `Ipv4Header`,
  `Ipv6Header` with its extension chain, and option iterators). Code that
  edits or inspects bytes a codec round trip would not reproduce uses it
  instead of parsing headers by hand; `transform::rewrite` and
  `transform::fragment` now share it, and field edits use it for checksum
  coverage. `protocol::headers::Error` implements `Classified`, and
  `transform::Error::Header` carries it with the same codes as before
  (`packet.transform_input`, `packet.transform_unsupported` for a jumbogram,
  `policy.transform_limit` for VLAN or extension depth).
  `packet::link::VlanTag::{from_tci, tci}`, `VlanKind::from_ether_type`, and
  the `ip_protocol::{ESP, ICMPV6, NO_NEXT_HEADER}` numbers support it.

- `registry::Builder::allow_trailing_padding` records that a link protocol's
  frames may carry trailing padding after the network payload, and
  `Registry::allows_trailing_padding` reports it. Decoding and building read
  this property instead of a fixed list of built-in link protocols, so a
  custom link protocol registered with it behaves like Ethernet.

- Independent forwarding detail-byte and comparison-scratch budgets, input
  fingerprints, decode/filter context, correspondence-only and identity-overlap
  diagnostics, and demand-driven physical comparison analysis.
- Versioned `ci-v1` / `workstation-v1` offline resource presets with explicit
  override precedence and resolved resource diagnostics.
- A strict bounded downstream forwarding consumer, a frozen v6 fixture,
  mutation tests, and a checksummed reproducible offline regression harness.
- Composed compression/capture, capture transformation, forwarding-semantic,
  HTTP segmentation, and HTTP pipeline fuzz targets; forwarding/HTTP
  measurement workloads.
- A detached public API consumer test, compact pre-merge decoder-oracle checks,
  explicitly reviewed native validation, and an opt-in passive native capture
  smoke runner with honest platform capability reporting.
- Task-oriented onboarding and explicit verification, compatibility, preset,
  and native-validation contracts.
- `Packet` implements `Extend` and `&Packet` implements `IntoIterator`,
  `analysis::SourceSet` dereferences to `[SourceFrame]`, `LinkType` implements
  `Display`, and the `as_str`-backed enums (`error::Kind`, `FieldKind`,
  `BuiltinProtocol`, `scan::Classification`, traceroute `ResponseKind` and
  `Completion`, `fuzz::CaseOutcome`, `ProbeStatus`, `dns::Outcome`,
  `QuestionStatus`, and netio `Capability`, `Mode`, and `OverflowPolicy`)
  implement `Display`.
- Portable TCP connect scans expose bounded socket outcomes and cleanup, with
  explicit multi-target/CIDR selections, exclusions, and stable deduplication.
- Replay maps source interfaces or filters to output interfaces and supports
  finite repeated passes under shared budgets over a validated capture snapshot.
- Rolling raw-packet scan windows share ready capture sources, pacing, deadlines,
  and evidence bounds; per-port UDP profiles add DNS and masked-byte validation.
- Generic exchange correlation attributes structured DNS-over-UDP replies by
  application identity: the registered `dns` matcher verifies the reversed
  UDP flow, response direction, transaction identifier, opcode, and the
  complete ordered question section (ASCII case-insensitive wire names), so
  concurrent requests sharing one tuple stay distinct while wrong-ID,
  wrong-question, malformed, or undecodable replies can no longer succeed
  through the weaker UDP tuple match. Identical outstanding requests stay
  ambiguous, and non-DNS UDP plus quoted-ICMP error evidence are unchanged.
- Multi-interface capture shares queue/operation budgets, readiness, and cleanup,
  with per-source evidence and bounded PCAPNG size/time rotation and stop/ring retention.
- Native capture settings: `capture` accepts `--capture-buffer-bytes`,
  `--timestamp-source`, and `--timestamp-precision`, applied to the driver per
  interface before activation and rejected with typed errors when unsupported.
  The kernel buffer is separate from the PacketcraftR queue budgets. Reports
  carry per-source `capture_settings` distinguishing requested, applied, and
  confirmed-effective values (`effective` stays `null` where the backend
  cannot report one), and `interfaces --timestamp-types` lists the timestamp
  types an interface advertises, marking clock domains capture cannot select.
- DHCPv4/DHCPv6 fixture construction and typed options, including overloaded
  fields, relay messages, DUIDs, address associations, and retained unknown wire.
- Bounded capture header rewriting and ordered JSON rules with checksum repair,
  VLAN replacement, preserved interface identity, and atomic compressed output.
- `rewrite` field assignments patch fixed-width decoded fields in place over
  original capture bytes through `--set <protocol>[#occurrence].<field>=<value>`
  or `packetcraftr.rewrite/v2` rule documents (`assign`). Supported fields are
  `ipv4.ttl`, `ipv6.hop_limit`, `tcp.sequence`, `tcp.acknowledgment`, TCP/UDP
  ports, and `dns.id`, and a value is an unsigned integer
  (`transform::FieldAssignment::value` is a `u64`).
  `--checksum-mode repair|preserve` selects recomputed or retained covering
  checksums, and `--dry-run` emits a bounded requested/derived change report
  without publishing the destination.
- Dependency-preserving `export` selects complete streams and reconstructed or
  incomplete IP groups, then atomically copies their original capture records.
- Cleartext HTTP/1 headers and sourced TCP message inspection through `http`,
  including bounded body framing, request links, trailers, and incomplete evidence.
- Offline `dns-read` inspection frames reassembled TCP DNS and correlates scoped
  UDP/TCP transactions, preserving source frames, retries, duplicate/orphan
  responses, partial messages, and capture-clock regressions.
- Bounded offline `verify-forwarding` compares an ingress and an egress capture
  under explicit `--identity`, `--preserve`, and `--expect FIELD=VALUE` rules.
  Each side runs through the shared analysis pipeline with its own
  `--ingress-filter`/`--egress-filter` selection; identity pairs only unique
  one-to-one key groups while repeated keys stay ambiguous and unpaired. The
  report lists unique matches, unmatched observations, unkeyed and ambiguous
  groups, attributable field violations, and counted omissions — evidence, not
  device-attribution claims. A completed `fail` or `inconclusive` verdict exits
  1 with one terminal output record.
- Explicit bounded IPv4/IPv6 fragmentation and the offline `fragment` command.
- Ordered multi-capture merging with source/interface provenance and atomic file publication.
- Gzip/Zstd capture input/output with encoded/decoded-byte and window ceilings.
- Registered field projection from `read`/`dissect`, with missing
  values, repeated layers, nested fields, stream indexes, and bounded row output.
- Bounded TLS ClientHello/ServerHello fixtures with SNI/ALPN helpers, ordered
  opaque extensions, nested template/fuzz targets, and derived fingerprints.
- Bounded named object fields and nested reflection/template/filter/fuzz paths.
- Structured DNS question, record, EDNS and response construction through Rust
  and recipes, sharing the encoder with live DNS queries. Untouched decoded DNS
  retains exact original bytes; explicit edits derive lengths and counts.
- Cartesian packet sets in core and `build`/`exchange`, with repeatable `--axis`,
  checked expansion limits, and streamed build packet/completion events.
- Offline `--decode-as` for compatible TCP/UDP codecs, shared with `--tls-port`
  across dissection, filtering, and analysis commands.
- Replay `--bps` and Rust `Timing::BitRate`, pacing exact submitted frame bytes
  from cumulative totals under existing operation budgets.
- Bounded UDP scan payloads from `--udp-payload-hex` or `--udp-payload-file`,
  included in checksums, traffic budgets, and exact sent-evidence validation.
  Valid DNS, DHCP, NTP (NTPv3 and NTPv4 messages), VXLAN, and Geneve payloads
  on their registered ports materialize as exact typed layers, including inner
  frames, while payloads that do not decode as their registered protocol still
  require strict construction.
- Direct DNS `--tcp`, available without native packet-I/O features, retaining
  socket authorization, bounded framing, response validation, and retries.
- `packetcraftr_netio::deadline::remaining_before` is the one helper every
  live crate uses to turn a deadline into a remaining wait; the previous netio-private copy
  is gone. The CLI library exposes `output::hex` for the compact hex rendering shared by
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
- Independent TShark decoder validation on every CI run, with the full
  generated corpus on the weekly run; isolated Linux native validation on main
  pushes, weekly runs, and manual CI dispatch; and warnings-as-errors
  documentation profiles on every PR. Releases retain exact-commit evidence and
  explicitly identify unexercised Windows/macOS runtime lanes.
- Opt-in EDNS v0 requests advertise a bounded UDP payload size and optionally
  set the DO bit. DO requests DNSSEC data; it does not enable signature validation.
- DNS `--type` accepts bounded decimal and `TYPE<n>` codes alongside named
  aliases, preserving exact question codes and unknown response RDATA.
- Offline DNS inspection decodes answer, authority, and additional records,
  including EDNS and exact unknown RDATA. Core exposes bounded DNS record
  decoding shared by live queries, with typed failures for malformed or
  truncated messages and explicit message, record, name, and TXT limits.
- `build --output pcap|pcapng` writes single packets and expanded template
  sets to capture files through an explicit `--link-type`, validated against
  the emitted bytes, with deterministic or supplied `--timestamp` values.
  Generated captures read back through `read` and replay through providers.
- `--axis` accepts inclusive unsigned ranges `START..END[:STEP]` with decimal
  or `0x` endpoints alongside `[VALUES]` lists, checked against the packet
  ceiling before any range materializes; reversed ranges, zero steps, and
  malformed spans fail with typed errors.
- `--payload-file LAYER.FIELD=PATH` fills an empty bytes-typed recipe field
  from a file inside the packet input limit, keeping saved packet documents
  self-contained.
- NTPv3/v4 client, server, and broadcast messages decode and construct on
  UDP/123, with typed signed poll/precision exponents, exact 64-bit
  timestamps, four-byte reference identifiers, and preserved extension bytes.
  Unsupported versions, control modes, and truncated inputs stay raw;
  `--decode-as udp.port=PORT:ntp` overrides other ports.
- ICMP/ICMPv6 expose typed body views — echo identifier/sequence/rest plus
  family-specific pointer, MTU, and gateway fields — that read and write
  through the preserved opaque body bytes, keeping malformed and unknown
  wire content faithful.
- TCP options type EOL, NOP, MSS, window scale, SACK-permitted/SACK blocks,
  and timestamps in wire order. Unknown kinds, nonstandard lengths, and
  unparseable tails stay byte-exact as raw or trailing entries, and typed
  options are editable through expressions, filters, projection, templates,
  and packet documents.
- Scan reports round-trip statistics: `scan::Summary`/`Report` and the
  TCP-connect `socket_stats` carry `rtt` — sent, received, and lost counts
  plus min/avg/max over one sample per received probe — across aggregate
  JSON, NDJSON `complete` records, and text output. ICMP echo correlation
  now uses the typed identifier/sequence fields.
- `stats` reports a compact capture summary: matched-span `duration`,
  `average_packet_size`, `packets_per_second`, and `bytes_per_second`
  derived from observed timestamp extremes (regressions cannot produce a
  negative span; rates stay absent on zero spans), plus the capture's
  declared `interfaces` with link type and snap length in frame-reference
  ID order.
- `expert` now surfaces capture-level evidence as findings:
  `capture.frame_truncated` when a record's captured length is below its
  wire length, and `capture.clock_regression` when a matched frame's
  timestamp falls below the capture's high-water mark — both warnings
  attributed to the frame that carried the evidence, with interface
  context when the source declares it.
- `read` and the analysis commands (`stats`, `expert`, `follow`, `tls`,
  `dns-read`, `http`, `export`) accept `--start-epoch`/`--stop-epoch`
  selecting an inclusive epoch-second window at exact sub-second precision;
  reversed bounds and fractions past nanoseconds are rejected, frames without
  timestamps are never kept, and skipped frames still count toward read limits.
- `follow --write DIR` saves each selected direction's payload as
  `TRANSPORT-INDEX-{client,server}.bin`, staged in DIR and published
  atomically without overwriting existing files; both files share one
  `--max-application-output-bytes` budget, and reports list published paths
  under `written`.
- Live commands accept repeatable `--allow-destination ADDRESS[/PREFIX]`
  constraints restricting destinations to exact addresses or canonical CIDR
  networks, enforced at target authorization, on packet-declared
  route-bearing addresses, and on the destination the final wire bytes
  actually carry; constraints only narrow permission, and denials report the
  effective constraint set under `policy.destination_not_allowed`. `fuzz`
  accepts them only with `--live`, like its other live-only policy options;
  offline runs reject them with a usage error naming `--live`.
- `send` accepts the same `--axis` template expansion as `build`/`exchange`
  plus `--repeat N` (replays the whole expansion in order) and `--rate N`
  (paces transmission starts to `N` packets per second); the checked
  expansion-times-repetition total shares one packet/byte budget, pacing
  schedules past the operation ceiling fail before transmission, and text,
  hex, and raw formats emit each confirmed frame progressively so partial
  progress survives later failures.
- `dns` accepts multiple NAME positionals and repeatable `--reverse ADDRESS`,
  deriving PTR questions under `in-addr.arpa`/`ip6.arpa` via the new
  `dns::reverse_name`; `client.dns_batch` executes a
  bounded batch (up to `dns::batch::MAX_QUESTIONS`) under one shared deadline and
  report each question `completed`, `failed`, or `unattempted` in input order.
- `capture` accepts `--dissect` and repeatable `--field PATH` on text and
  NDJSON output. `--dissect` decodes each emitted frame once and publishes its
  layer stack and decode diagnostics — NDJSON `frame` records gain a `decoded`
  object beside the preserved captured bytes and interface metadata, while
  text prints the layer list. `--field` streams bounded `fields` rows per
  matched frame under `--max-projection-bytes`. Decoding shares the
  `--filter`/`--decode-as` registry, a frame is decoded at most once across
  selection and emission, and decoded state never accumulates across frames.
- `packetcraftr documentation --directory DIR` generates shell completions
  (`completions/`: Bash, Elvish, Fish, PowerShell, Zsh) and man pages (`man/`:
  one per command) from the finalized command definitions; release archives
  package both trees and the archive verifier requires them.
- Linux Arm64 (`aarch64-unknown-linux-gnu`) release archives join the matrix
  for both `all-features` and `pcap-free` variants, built and smoke-tested on
  an arm64 runner with the same linkage, archive-verification, checksum, and
  attestation checks as the existing targets.
- Runnable library examples in their owning crates:
  `packetcraftr-core`'s `build_decode_filter` and `capture_analysis` (offline
  build/dissect/filter plus the analysis pipeline over an in-memory capture),
  and `packetcraftr`'s `client_composition` (explicit destination allowlist,
  finite operation budgets, and local providers — no live traffic). CI runs
  them under the portable profile.
- `analysis::Session` in `packetcraftr-core` owns the offline-analysis
  lifecycle over a capture reader: it narrows `analysis::Options::plan` to the
  union of the compiled filter's `filter::Requirements` and the collector's
  declared `analysis::CollectorNeeds` (keeping conversation indexing capture-global so
  `max_flows` accounting stays per-transport), forwards IP events ahead of the
  records that reveal them, delivers each collector event to a caller-supplied
  sink in capture order, captures `scopes` before `finish`, drains the
  trailing events `finish` returns through the same sink, and reports the
  empty-selector verdict from `frames_matched`. `http`, `dns-read`, `expert`,
  `follow`, and `tls` now supply only a collector and an event sink; `follow`
  uses the split observe/finish phases so its missing-selector verdict still
  precedes collection teardown.
- `protocol::headers` gains `Ipv4Header::walk_prefix` and
  `Ipv6Header::walk_prefix`, which walk a datagram prefix whose declared
  length may exceed the bytes present; `Ipv6ExtensionChain`, an iterator
  over the extension headers at any offset; and
  `Ipv6Extension::fragment_offset_and_flags`, the Fragment header's raw
  offset/flags word.
- `protocol::network::ip_protocol` gains `ICMPV4` (1), `IGMP` (2), `IPV4` (4),
  `IPV6` (41), `GRE` (47), and `SCTP` (132), so `rewrite`'s transport-checksum
  repair, `fragment`, and quoted-ICMP matching name the IP protocol numbers they
  branch on.
- `packetcraftr_core::filter::Context::frame` builds the filter context for a
  caller that evaluates one frame at a time and assigns no derived packets or
  conversation indexes.
- `packetcraftr_core::analysis::expert::Summary::record` tallies one `Finding`
  into a summary's totals, per-severity counters, and per-code counts, so
  callers that select a subset of findings keep the same tally rules as
  `Collector`.
- `policy::DEFAULT_MAX_PACKETS_PER_OPERATION` and
  `policy::DEFAULT_MAX_BYTES_PER_OPERATION` name the default per-operation
  packet and byte ceilings that `Policy::default()` and the CLI `--max-packets`
  and `--max-bytes` defaults share.
- `filter::Requirements::union` combines two sets of filter requirements, so a
  caller that needs both a filter's and a projection's context no longer merges
  the four flags by hand.
- Link-layer control codecs, each bound to its standard parent and listed by
  `protocols` (build, dissect, and exact round trip): `stp` for IEEE
  802.1D/802.1w BPDUs (configuration, topology change notification, and rapid
  configuration) under LLC SAP 0x4242, with typed bridge IDs, flags, and timers
  and `decode.stp_*` / `build.stp_*` diagnostics that strict builds refuse;
  `lldp` at EtherType 0x88cc under Ethernet, VLAN, QinQ, SNAP, and Linux cooked
  captures, which keeps the TLV chain verbatim (`Lldp::tlv_iter`) and reports
  mandatory-TLV order, truncated TLVs, a missing End of LLDPDU TLV, a Time To
  Live value that is not 2 bytes, and bytes after the End TLV as
  `decode.lldp_*` / `build.lldp_*` diagnostics; and `eapol` (IEEE 802.1X) at
  EtherType 0x888e with a derived body length and the EAP or key body carried
  as a raw layer, where a declared length past the frame is kept as a malformed
  layer. STP and EAPOL accept Ethernet padding after their self-delimiting
  bodies. Body fields that a Topology Change Notification or unknown BPDU type
  does not carry read as their defaults and are never encoded.
- `vrrp` codec for VRRP versions 2 and 3, bound to IP protocol 112, with
  checksum, TTL, destination, address-count, length, and version diagnostics
  (`decode.vrrp_*`, `build.vrrp_*`). A decoded message rebuilds to the same
  bytes, including a missing or short version 2 authentication trailer and
  version 2 over IPv6 in permissive mode; strict builds refuse version 2 over
  IPv6.
- `protocol::network::ndp` types Router Solicitation, Router Advertisement, and
  Redirect messages (`RouterSolicitation`, `RouterAdvertisement`, `Redirect`)
  and the Prefix Information, Redirected Header, MTU, Route Information, and
  RDNSS options as typed values, with `to_icmpv6`. Unmodelled options and
  options whose length does not fit their layout stay `MessageOption::Other`,
  so a decoded body still re-encodes byte for byte.
- `protocol::network::mld` and `protocol::network::igmpv3` type MLDv1 and MLDv2
  messages (Query, Report, and Done, with MLDv2 multicast address records) and
  IGMPv3 membership queries and reports (with group records) as helpers over
  the generic `Icmpv6` and `Igmp` layers, with bounded record and source
  counts. Like the NDP helpers, they are not registered layers, so dissection
  output is unchanged.
- `etherip` codec for EtherIP (IP protocol 97, RFC 3378) carrying an Ethernet
  frame, plus bindings for IP protocol 137 (MPLS-in-IP) and 143 (Ethernet
  next header) and UDP port 6635 (MPLS-in-UDP).
- `gtpu` codec for GTP-U v1 on UDP 2152. A G-PDU decodes its inner IPv4 or IPv6
  packet by the payload's first nibble, while echo and other message types keep
  their payload as a raw layer. Optional header fields and extension-header
  bytes stay verbatim, and bytes after the declared length are accepted as
  padding that rebuilds strictly.
- `tftp` codec (RFC 1350 and the RFC 2347 options) on UDP 69 and `syslog` codec
  (RFC 5424 and RFC 3164) on UDP 514. Both keep their strings as raw bytes, so
  wire bytes, trailing bytes, and malformed input are preserved. TFTP transfer
  ports are ephemeral, so decode DATA and ACK traffic with `--decode-as
  udp.port=N:tftp`.
- Display filters: quoted text accepts the escapes `\n`, `\r`, `\t`, `\0`,
  `\\`, `\"`, and ASCII `\xNN`, and `b"..."` byte-string literals carry
  arbitrary bytes, so `raw.bytes contains b"\x16\x03\x01"` and `raw.bytes
  contains "\r\n\r\n"` work. A non-ASCII escape in plain text is a syntax error
  that names its offset. `verify-forwarding --expect` values take the same
  literals.
- Display filters: `field & MASK` tests the bits of an unsigned field, alone to
  mean the masked value is nonzero or before a comparison, as in `tcp.flags &
  0x12 == 0x12`. A mask on a field that is not unsigned is a compile error.
- Display filters: inclusive `A..B` range literals of unsigned numbers, IPv4
  addresses, or IPv6 addresses work with `==`, `!=`, `in`, and as set members
  (`udp.dstport in 1024..65535`, `ip.src in 192.0.2.1..192.0.2.50`). Reversed,
  mixed-kind, and malformed ranges are compile errors with offsets, and
  `verify-forwarding --expect` accepts ranges.
- Display filters: the `startswith`, `endswith`, `icontains`, and `iequals` text
  operators work on text, bytes, MAC, and list fields (`dns.qname endswith
  ".example.com."`). A list is searched element by element, and case folding
  is ASCII only. Known limits: these operators and `contains` compile on a list
  of numbers or addresses such as `dns.qtype` or `tls.cipher_suites` but never
  match, because the field schema does not record element kinds, and a list of
  objects such as `tcp.options` or `dns.questions` is a compile error.
- Display filters, projections, and forwarding rules accept `[*]` (every
  element) and `[-1]` (the last element) after a list field, as in
  `dns.answers[*].type == 1` and `dns.answers[-1].ttl > 20`, and `#last` or
  `#-1` for the innermost matching layer, as in `ipv4#last.destination`. A
  `[*]` projection column is always a list. Forwarding verification never
  establishes a violation through these selectors on a truncated or incompletely
  decoded capture.
- Display filters: `len(field)` is the size of a bytes, text, MAC, or address
  value (or of each element of a list), and `count(field)` is the number of
  elements in a whole list, as in `len(raw.bytes) > 1400` and
  `count(dns.answers) == 0`. They are functions only when `(` follows the word
  directly (the name is case-insensitive), so `len (raw.bytes)` is an unknown
  field. `len(frame.protocols)` is refused; use `count(frame.protocols)` or
  `frame.layer_count`.
- Display filters, projections, and forwarding checks read the frame facts
  `frame.time_nsec`, `frame.direction`, `frame.truncated`, `frame.layer_count`,
  and `frame.protocols`. `frame.layer_count` and `frame.protocols` come from
  what the decoder produced, so forwarding verification treats them as
  unevaluable on a truncated or incompletely decoded capture, while
  `frame.time_nsec`, `frame.direction`, and `frame.truncated` cannot name
  forwarding identity or preservation fields. `frame.reassembled` is not
  supported.
- `expert` reports TCP findings that need more than one frame:
  `tcp.syn_retransmission`, `tcp.connection_refused`,
  `tcp.handshake_unanswered`, `tcp.synack_mismatch`, `tcp.not_closed_at_end`
  (Info), `tcp.out_of_order`, `tcp.fast_retransmission`,
  `tcp.ack_unseen_segment`, `tcp.data_after_close`, `tcp.fin_retransmission`,
  and `tcp.window_update` (Info). A SYN-ACK that acknowledges the wrong
  sequence leaves the SYN pending, so a later correct SYN-ACK is still seen and
  a SYN that never gets a valid answer reports `tcp.handshake_unanswered`.
  Known limits: `tcp.out_of_order` watches at most four open gaps per direction
  and a fifth fills silently; a handshake that follows an idle expiry is judged
  against the expired SYN; and findings are judged only on frames that pass
  `--filter`, so a filter that keeps one direction of a conversation can report
  `tcp.handshake_unanswered` or `tcp.not_closed_at_end` for a handshake the
  full capture completed.
- `merge --order append` writes each input whole in argument order and keeps
  every timestamp verbatim, so captures that regress in time (such as
  `examples/captures/clock-regression.pcap`) merge without error and the output
  may be non-monotonic. The default `--order chronological` keeps refusing a
  regressing input with `packet.capture_merge_order`. Core exposes
  `capture_file::MergeOrder`.
- `merge --max-reorder-frames N` (at most 65536,
  `capture_file::MAX_REORDER_FRAMES`) gives each input a bounded look-ahead
  window that repairs small timestamp inversions, such as those of multi-queue
  captures, before the chronological merge; a frame displaced beyond the window
  is still refused. It is accepted with a single input, which it then sorts,
  and conflicts with `--order append`. Frames read into the window count
  against the existing frame and byte budgets.
- `rewrite --map-ip OLD=NEW` and `--map-mac OLD=NEW` remap addresses
  many-to-many. An IP side is an address or an equal-length prefix whose host
  bits carry over (`192.0.2.0/24=198.51.100.0/24`). Entries repeat, at most
  4096 across both options, overlapping sources are refused, the outer source
  and destination are matched independently, and lengths and checksums are
  repaired. The options conflict with `--rules-file` and the fixed address
  flags. Core exposes `transform::AddressMap`, `IpMapping`, and `MacMapping`,
  and `Rules::with_address_map`.
- `rewrite --set` and rewrite/v2 `assign` accept `ipv4.identification`,
  `ipv4.dscp_ecn`, `tcp.window`, `icmp.identifier` and `icmp.sequence` (and
  the `icmpv6` forms), `dhcpv4.transaction_id`, `vxlan.vni`, and `geneve.vni`.
  IPv4 header, TCP, UDP, ICMP, and ICMPv6 checksums are repaired, or left alone
  under `--checksum-mode preserve`, and a value wider than its field is a
  usage error.
- `read --normalize` with `--output pcap` writes a classic PCAP from PCAP or
  PCAPNG input. It keeps the link type, snapshot length, original lengths, and
  the nanosecond or microsecond timestamp resolution of the source, and refuses
  without rounding what classic PCAP cannot hold: more than one interface, a
  packet direction, a missing timestamp, other timestamp resolutions, a
  timestamp the resolution cannot represent exactly, a frame longer than the
  snapshot length, and an empty selection.
- `read --frames RANGES` (such as `2-3,10` or `10-`) and `--every N` select
  frames by their one-based source position in every `read` path: stream,
  `--field`, `--normalize`, and capture output. Skipped frames still count
  against the input budgets, and `frame.number` and stream numbering keep the
  source position.
- `dissect --hex -` reads hexadecimal text from redirected stdin and `dissect
  --hex-file PATH` reads it from a file. Both accept `0x` prefixes and
  whitespace, colon, or dash separators, so `packetcraftr --output hex build
  ... | packetcraftr dissect --hex -` works. The text is read through a bound
  derived from `--max-packet-size`, and text that decodes to no bytes is
  rejected as `cli.input_source` (exit 2).
- `--tree` on `dissect`, `read --dissect`, and `capture --dissect` prints each
  layer's fields as an indented tree in text output. Decoded wire values are
  shown unchanged, derivable fields such as lengths and checksums are marked,
  and the text is escaped and bounded by `--max-tree-bytes`. `--tree` without
  `--dissect` (`cli.tree_requires_dissect`) or with a machine output format
  (`cli.tree_unsupported_format`) is a usage error.
- `traceroute --payload-size`, `--dont-fragment`, and `--dscp` shape the
  probes: zero bytes appended to UDP and ICMP echo probes (up to 9000), the
  IPv4 Don't Fragment flag, and the DSCP codepoint of the IPv4 TOS or IPv6
  traffic class. The defaults keep the previous probe, TCP probes carry no
  payload, and `--dont-fragment` is refused for an IPv6 destination.
- `exchange --stop-when-answered` ends the response window once every request
  has at least one retained response, instead of waiting out `--timeout-ms`.
- `replay --max-gap-ms` clamps each captured inter-frame gap, after `--speed`
  scaling, so long idle periods do not stall a replay. It applies to original
  and scaled timing and conflicts with `--rate`, `--bps`, and `--timing
  immediate`, which is rejected before any input is opened.
- `packetcraftr build --session tcp|udp` expands a client-to-server recipe into
  a deterministic conversation: a TCP handshake, MSS-sized request segments
  with their ACKs, an optional response from `--session-response-file`, and a
  FIN, RST, or open close, or a UDP request with one reply frame. The other
  options are `--session-mss`, `--session-close`, `--session-client-isn`,
  `--session-server-isn`, and `--session-step-ns`. Output is at most 4096
  frames, byte-identical for equal inputs, and every frame, including capture
  timestamp representability, is checked before any output is written. A TCP
  conversation acknowledges after `(window - 1) / mss` segments, so the data in
  flight stays below the advertised window and `expert` reports no
  `tcp.window_full`. A UDP request keeps its typed payload layers, while a TCP
  request and every response are raw bytes: strict mode refuses a raw reply
  from a registered UDP port such as 53 (use `--mode permissive`, which warns),
  an empty `--session-response-file` is an error, and a `--session-step-ns`
  whose timestamp the capture format cannot represent exits 3 with
  `packet.capture_file` and empty stdout. Core exposes the builder as
  `packetcraftr_core::conversation` (`Conversation`, `Options`, `Protocol`,
  `Close`, and `Error`).
- `packetcraftr topics [NAME]` prints built-in references for packet
  expressions, display filters, output formats, and exit codes. Embedded
  examples are checked against the real parsers in tests.
- `fuzz` rebuilds each decoded case, offline and live, and reports
  `fuzz.roundtrip_mismatch` (the first differing byte, with its layer and
  field), `fuzz.roundtrip_unbuildable`, or `fuzz.roundtrip_skipped` when a codec
  decodes something its own encoder does not reproduce. Lossy protocols report
  at info severity, malformed layers are not checked, and the rebuild is
  bounded by the campaign byte budget and never retained. A live case keeps the
  verdict reached when it was prepared. `fuzz::is_roundtrip_diagnostic`
  identifies these diagnostics.
- Packet expressions accept the byte generators `repeat(BYTE,COUNT)`,
  `zeros(COUNT)`, and `cyclic(LENGTH)`, and `0b`, `0o`, and underscore-separated
  integer literals, so `raw(bytes=repeat(0x41,1400))` builds a 1400-byte
  payload. Generated bytes share one budget per expression,
  `expression::Limits::max_generated_bytes` (1 MiB by default), which two
  `build --set` overrides spend together.
- Layer fields can be selected by protocol name, as
  `<protocol>[#occurrence].<field>` (`ipv4#2.ttl` is the inner IPv4 header),
  wherever a zero-based `LAYER.FIELD` was accepted: `--axis` on `build`,
  `send`, and `exchange`, `--payload-file`, and `fuzz --field`, which also
  accepts `*` for the protocol or the field.
  Selectors are case-insensitive and resolve once against the recipe, so
  reports and reproductions keep numeric layer indexes. The new repeatable
  `build --set SELECTOR=VALUE` overrides recipe fields (at most 64, in order)
  before axes expand. Core exposes the grammar as the `layer::selector` module,
  `fuzz::Target::select`, and `document::payload::Target::resolve`.

### Changed

- Offline analysis, dissection, packet building, and display filters do less
  work per packet: TCP reassembly copies delivered bytes by slice, capture
  readers keep one buffer per record, compressed captures are read through a
  buffer, HTTP/1 heads are searched with SIMD, TLS records are parsed in place,
  and `in { .. }` sets are indexed. In the core benchmarks TCP reassembly is
  about 90% faster, HTTP/2 analysis 66%, packet decode and rebuild about 40%,
  and a 256-member set lookup 97%. Output, limits, and diagnostics are
  unchanged.
- Human field trees reach standard output in one write per packet instead of
  one flushed write per line; interruption is checked between packets.
- A capture group's waits classify like a single session's: `wait_ready`
  with a spent deadline reports `io.capture_readiness`, and a wait whose
  remainder exceeds the one-hour ceiling reports `cli.capture_timeout`,
  where both previously reported `cli.capture_group`.
- Text output no longer shows Rust `Debug` formatting. Durations read as
  milliseconds to the microsecond (`12.345ms`, `none` when absent) in the
  `scan`, `traceroute`, `dns`, `replay`, `stats`, `tls`, `expert`, and
  `follow` text renderers; scopes read `interface 3` or `interface none` and
  `encapsulation vlan:10,network:192.0.2.1<->198.51.100.2` (or `none`); a UDP
  profile's validation is spelled as in JSON (`confirmed`); and the stats I/O
  bucket origin is a Unix timestamp. JSON and NDJSON are unchanged.
- A `replay` output failure names what failed (`write stdout failed`,
  `write replay record failed`, `write capture output failed`, or `replay
  frame output failed`) and lists the error it carries as its first cause,
  instead of repeating that error's text in the message. Codes are unchanged.
- A live packet whose routing headers cannot be read is refused as
  `traffic policy cannot authorize packet routing semantics: its live
  destinations cannot be read` (or `its outer IP source cannot be read`) with
  the packet's own failure as its first cause, instead of repeating that
  failure in the message. Wire bytes that do not form a frame are refused
  with the new `policy::Error::WireFrame`, which keeps the frame error as its
  typed source. Codes are unchanged (`policy.invalid_packet_semantics`).
- A `rewrite --rules-file` document that is not valid JSON of its schema's shape
  reads `invalid rewrite rules` with the parser's reason as its first cause,
  instead of repeating that reason in the message. An unsupported schema and
  a rule count outside 1 to 64 now have distinct messages
  (`unsupported rewrite rules schema S; expected ...` and `rewrite rules hold
  N rules; expected 1 to 64`). A `scan --udp-profiles` document reads the
  same way: `invalid UDP profiles` with the parser's reason as its cause,
  `unsupported UDP profiles schema S; expected packetcraftr.udp-profiles/v1`,
  and `UDP profiles hold N assignments; expected 1 to 256`. Codes and exit
  codes are unchanged.
- A `replay` frame that matches `--map-interface` or `--map-filter` rules
  naming different interfaces now reports `replay frame N matches conflicting
  output interfaces` as its message, and a frame no rule maps without an
  `--interface` fallback reports `replay frame N has no output interface
  mapping`, instead of `replay frame selection failed at source index N-1`
  with that sentence as its only cause. A refused `--sni` pattern or
  `--map-interface`/`--map-filter` rule keeps its message and now lists the
  library's refusal in `causes`. Codes, exit codes, and coordinates are
  unchanged.
- Workflow failures no longer repeat the text of the error they carry: the
  message names what failed and the carried error is the first cause. For
  example a refused scan reads `scan authorization failed` with the policy
  denial in `causes`, and a failing sink reads `send progressive output
  failed`. This covers the authorization, execution, and output failures of
  send, exchange, scan, traceroute, DNS, fuzz, replay, and capture, the replay
  capture-read, selection, and transmission failures, the scan pipeline
  failure, route and interface lookup failures, neighbor I/O and cleanup
  failures, and the policy's undecodable-wire refusal; a scan or traceroute
  cancellation or target-selection failure reports its own message without a
  `scan:` or `traceroute:` prefix. Codes, exit codes, and coordinates are
  unchanged.
- `replay` publishes each transmitted frame from a runtime worker, so a
  replay's `resources` report lists the `client_progress` runtime, and the
  replay deadline runs on the client's clock and cancellation.
- A pipelined scan (`max_in_flight` above one) reads its duration limit and
  probe start schedule from the client's clock, like a serial scan, instead
  of the system clock; waits for captured frames stay on the capture group.
  A UDP-profile scan builds its operation-local registry once per scan
  instead of once per probe.
- `capture` publishes its frames on a runtime worker, so
  `--resource-diagnostics` lists a `capture_progress` worker for it, and a
  TCP connect `scan` lists its `scan_connect` worker in every output format,
  not only NDJSON. A capture read interrupted by cancellation reports the
  cancellation itself; the code stays `io.cancelled`.
- DNS `packet.dns_query` and `capability.dns_tcp` failures no longer repeat
  their cause in the message: it reads `DNS query construction failed` or
  `DNS-over-TCP execution is unavailable on attempt N`, and the cause appears
  once in `causes`. Codes are unchanged.
- `dns`, `scan`, and `traceroute` run on a client with one event runtime, so
  their `resources` report lists a single `workflow_progress` worker row; the
  idle `client_progress` row beside it is gone.
- Live `fuzz` publishes its cases through its client's one runtime, so the
  resources report lists a single `fuzz_progress` worker row in every format,
  instead of an idle `client_progress` row plus, under NDJSON, a
  `fuzz_progress` row.
- `send`, `exchange`, and `plan` resolve `--interface` inside the client, after
  the operation's destinations (and for `send` and `exchange` its budget) are
  authorized, as DNS, scan, traceroute, and live fuzz already did. A refused operation no longer
  enumerates interfaces, and one command enumerates them once. Codes and
  messages are unchanged.
- `--payload-file` refusals keep `cli.error` and exit code 2, but their text
  changed: the message names the option (`--payload-file requires
  LAYER.FIELD=PATH` or `--payload-file cannot fill its recipe field`) and the
  first cause gives the reason without the option name, for example
  `payload field nope is unknown on layer 2`.
- Neighbor discovery builds ARP requests and neighbor solicitations from core
  layers and reads replies through the dissector; the frames on the wire are
  unchanged. An advertisement is now accepted behind the IPv6 extension headers
  the codecs type (Hop-by-Hop, Destination Options, Segment Routing, AH) and
  refused behind any other routing header type or a malformed AH header, which
  the hand-written walk used to step over.
- Single capture sessions apply the 64 KiB capture-filter limit that capture
  groups applied: `capture::Request::validate` checks it and
  `capture::SystemProvider` refuses a longer filter before opening an
  interface, with `cli.capture_filter`. A group's oversized filter now reports
  `cli.capture_filter` too, instead of `cli.capture_group`, and the
  `cli.capture_group` and `internal.capture_group` failures publish a
  remediation. A group source failure's message names the source and phase
  ("capture source 0 (eth0) failed during receive") and publishes the
  source's own failure as a cause.
- `packetcraftr_netio::route::SystemProvider` rejects a preferred source of
  the other address family (`io.route_selection`) in builds without
  `native-route` too, before reporting the missing capability
  (`capability.route`).
- `rewrite` and `fragment` validate every IPv6 extension header and IP option
  they step over. A malformed length in a source-route, Home Address,
  routing, fragment, or AH header now reports `packet.transform_input` where
  it was refused as `packet.transform_unsupported` without reading its length.
  Messages for malformed link and IP headers come from the header walker (for
  example "truncated IPv6 extension header" instead of "invalid packet
  transform input: truncated IPv6 extension").
- Error messages no longer repeat their source's text; the source moves to the
  published `causes` (for example "analysis consumer failed at frame 7" with
  cause "application output exceeds --max-application-output-bytes"). Rejected
  fuzz cases publish "mutation was rejected" or "mutated packet was rejected"
  with the refusal as a cause. Malformed-layer reasons and diagnostics keep
  their full text, and classification codes are unchanged.
- `protocol::semantics::Error` (formerly `packet::semantics::Error`) messages
  describe the packet instead of a transmission denial (for example
  "destination cannot be determined because the ipv4 layer is malformed: …"
  instead of "malformed ipv4 layer may hide a live destination: …"). Live commands still refuse such packets with
  `policy.invalid_packet_semantics`; only the reason text changes.
- `dns-read --dns-port` adds ports to 53 instead of replacing it, as README
  documents and `http --http-port` already behaves.
- Display filters read eight two-digit hex groups (`47:45:54:20:2f:69:6e:64`)
  as a byte run, like runs of every other length; an IPv6 literal spelled that
  way needs a four-digit group, `::`, or `/128`. A byte slice starting at or
  past a field's end (`[len]`) selects no value, and projection column and
  forwarding field names keep the typed slice (`raw.bytes[0:1]`).
- Strict builds refuse IPv4 option lists the decoder cannot walk (permissive
  builds report `build.ipv4_options`) and trailing coverage paddings listed
  with an outer boundary before an inner one.
- The DNS exchange executor refuses a client capture wider than the request's
  evidence bounds with `cli.dns_executor` before any I/O, instead of failing
  afterwards with `internal.dns_evidence`.
- The UDP-profile schema states the loader's rules: names are bounded in
  characters and exclude control characters.
- `--retention` is reported as a `policy` resource setting, capture text output
  spells stop reasons and retention as JSON does, and DNS batch text omits the
  per-question counters it could not report.
- Pipelined `scan` (`--max-in-flight` above 1) picks each probe's winning
  response with the serial rule: highest rank, then lowest responder address,
  then shortest latency, then lowest exact frame bytes. Equally ranked
  responses no longer go to whichever arrived first, so the same captured
  evidence yields the same probe outcome in either execution mode.
- Pipelined `scan` prepares its probes through the same staged preparation as
  `exchange`, so a cumulative wire-byte overflow reports the policy byte limit
  instead of `policy.scan_pipeline_limit`.
- HTTP analysis accumulates reassembled header bytes in bulk runs ending at
  each line feed instead of one byte per loop iteration, removing the per-byte
  upgrade-membership lookup and terminator rescan while keeping bare CR/LF
  rejection, header caps, and boundaries byte-exact.
- Display-filter `contains` compiles its needle into a `memchr::memmem`
  searcher once at filter-compile time instead of sliding a window over the
  field bytes per frame, making the scan linear-time (~84× faster on a
  64 KiB payload in the perf fixture).
- `export`, `merge`, `rewrite`, and capture snapshotting buffer staged file
  output in 64 KiB chunks instead of issuing one write syscall per record,
  removing the syscall bottleneck on large captures. Output bytes are
  identical.
- `read` without `--field` rejects JSON output with the shared
  "this output format requires --field selections" message.
- Forwarding verification serializes each keyed observation's identity once
  instead of twice, preserving canonical key bytes and charging the scratch
  budget before retaining each serialized chunk.
- Replay decodes each captured frame with the trusted registry once instead of
  twice, reusing the pre-route decode for the final route-aware source check.
- Offline analysis avoids repeated source-provenance unions and unnecessary IP
  expiry scans while preserving source attribution and budget accounting.
- Capture encoding avoids redundant preparation and small writes while preserving
  validation and wire output; neighbor-cache hits avoid scanning unrelated entries.
- Every native call that can block past a deadline runs on one process-wide
  worker pool of `resources::WORKER_CAPACITY` slots: capture reads, Linux route
  netlink, macOS routing-socket queries, Windows IP Helper calls, and ordinary
  TCP connects. Pooled threads are reused, never outnumber the pool, and only
  take work from callers in the same network namespace. TCP connects no longer
  spawn a thread each, and macOS and Windows route queries no longer block the
  caller past its deadline. Sends stay on the caller's thread. The
  `native_process` resource row now covers the whole pool, TCP connects
  included, and reports `supported: true` with capacity 16 in every build
  profile; `tcp_connect_process` counts the TCP connects' own admissions
  against the same capacity. A connect scan or capture waits for or is refused
  a slot while other native work holds the pool, under the existing
  `io.tcp_connect_capacity` and `io.capture` codes.
- Linux netlink submissions, capture shutdown, and worker cleanup wait on
  condition variables instead of sleeping between checks; the remaining
  sliced waits exist only to notice a caller's cancellation.
- Linux route lookups share a netlink worker (thread, Tokio runtime, and socket)
  per network namespace behind the native worker budget, submitting requests
  over bounded channels instead of respawning all three per destination.
  Queued requests honor their original deadlines and survive socket replacement;
  each idle worker retains one admission slot in native resource snapshots.
- Packet filters short-circuit decisive boolean operands, and projections avoid
  temporary allocations when retaining field values and accounting for byte budgets.
- Workflow and netio errors retain their original typed sources instead of
  flattened display strings: probe `ErrorKind` implements `std::error::Error`
  with `#[source]` fields, `source()` chains reach the underlying `io::Error`
  on worker-reaper and capture-output failures, route materialization,
  authorization, send-execution, and DNS-classification failures keep their
  typed causes, and `fuzz::CaseFailure` implements `Error`. Crate-private
  `deadline_error_conversions!` macros and the exported `display_via_as_str!`
  macro keep the repeated conversion and `Display` impls in one place.
- Default CLI builds align workflow dependency features with workspace builds,
  avoiding redundant workflow and CLI recompilation when switching between
  them. Native capabilities, portable builds, debug information, and release
  overflow checks are unchanged; see `CONTRIBUTING.md` for measurement commands.
- CI denies Clippy warnings across portable, default, Layer 2 only, Layer 3
  only, and full-native profiles on Linux, macOS, and Windows. PRs also compile
  every fuzz target with locked dependencies on the pinned nightly.
- **Breaking:** `policy::Policy` gains an `allowed_destinations` constraint
  list bounded by `MAX_DESTINATION_CONSTRAINTS`; the new
  `policy::DestinationConstraint` type parses exact addresses and canonical
  CIDR networks. Its `Network` variant wraps `target::Network`, so allowlist
  entries, scan targets, and `--exclude` share one CIDR parser and matcher;
  a signed prefix such as `/+24` is rejected on every surface.
- Writer commands (`export`, `merge`, `rewrite`, `follow --write`) publish
  through one staged-output path: an occupied destination — including a
  dangling symlink — is refused before any input is read, and every staging,
  sync, and publish failure classifies as `io.output_file` (previously
  `io.runtime` or `io.capture_file` depending on the command).
- `filter::Error` implements `Classified` in core and is the single owner of
  display-filter classification. A filter that needs `frame.time_epoch` on a
  frame without a timestamp reports `packet.timestamp_unavailable` (exit 3)
  from every command, including `read --field`, `capture`, `replay`, and
  `rewrite`, which previously reported `packet.error` or `cli.filter`.
- **Breaking:** `send` aggregates results into a `frames` list with per-frame
  `pass`/`index` metadata plus `passes_completed`, replacing the single-frame
  `frame`/`route` result; `send::Client::send` gains set-sending entry points
  (`send_set`, `send_set_with_events`, `send_set_driven`) over
  `send::SetOptions`/`send::SetReport`.
- **Breaking:** `analysis::Options` gains a `time_bounds` field; the new
  `frame::TimeBounds` type holds inclusive `SystemTime` bounds compared at
  full precision during frame selection.
- **Breaking:** the TCP `options` layer field is now an ordered list of typed
  option objects instead of a byte string; `options=hex("…")` byte input still
  parses into the typed form. `packetcraftr.packet/v2` documents and machine
  output reflect the new shape.
- **Breaking:** `Template::axis` accumulates Cartesian axes; `expansion_len`
  returns a checked result. DNS `Request::transport: TransportMode` replaces
  `tcp_fallback`; unknown serialized request fields are rejected. Scan requests
  and probes gain `udp_payload`, and `scan::Probe` is no longer `Copy`.
- Output/v6 supersedes the earlier unreleased v3–v5 schemas, adding build streams,
  bit-rate timing, and successful direct TCP DNS with `fallback_attempted=false`.
  Schemas, examples, release assets, and migration notes follow the new contract.
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
- PR CI folds documentation and validation failure fixtures into the Linux
  job. Release-archive builds and smoke checks run in the release workflow, and
  isolated native validation runs outside PRs.
- Rust DNS `Request` gains an optional `edns` field, and `encode_query` takes
  that option as its fifth argument. `None` preserves the original query bytes.
- DNS `query_type` values are integers in `0..=65535` in summaries and events.
- Rust DNS `QueryType` is a numeric value with `new`/`code` methods and uppercase
  named constants. Its serde representation is an integer; `Display` retains
  human-readable aliases. See [the migration notes](docs/migration-unreleased.md).
- DNS TCP fallback requires explicit provider composition. Native socket
  ownership moves to netio; the workflow retains DNS framing, shared deadlines,
  and evidence. Library clients query over their `tcp` provider; the CLI
  explicitly selects the standard-library TCP provider.
- Release archives share one verifier for required assets, binary identity,
  exact offline packet bytes, and complete NDJSON output on Unix and Windows.
- Netio interface-snapshot and packet-routing validation retain their original
  typed error sources. Route errors `InvalidSourceRouting` and
  `InvalidSegmentRouting` gain an optional `source` field; classification codes
  remain unchanged. See [the migration notes](docs/migration-unreleased.md).
- DNS record and name types move to `packetcraftr_core`; malformed declared
  records now produce offline diagnostics instead of a header-only DNS layer.
- Private-item rustdoc checks join the public documentation gate for the
  portable, pcap-free, and full-native CI profiles. Linux process tests gate
  on capability cfgs emitted by the CLI build script
  (`packetcraftr_test_procfs`, `packetcraftr_test_util_linux`,
  `packetcraftr_test_dev_full`) instead of raw `target_os` checks and fail
  explicitly when a facility is missing. TLS handshake parsing, IP reassembly merge
  planning, and workflow admission/activation paths split along documented
  responsibility boundaries without changing public paths or behavior.
- Linux route selection resolves the kernel's output interface with a filtered
  link get and retains only that interface's addresses from the address dump.
  Collecting all local addresses now only runs for local routes whose selected
  source lives on another interface; the kernel address dump remains host-wide.
- The `--max-application-*` limit flags document what each budget counts
  (messages, streams, in-flight buffers, retained evidence, and source spans),
  and `--start-epoch`/`--stop-epoch` help states that values are nonnegative;
  defaults, ranges, and parsing are unchanged. `build-manifest.py` reports
  malformed or incomplete release metadata with explicit diagnostics instead
  of tracebacks, and bounds its `rustc`/binary probes.
- `scan` (including `--connect`), `dns`, `traceroute`, `exchange`, and `fuzz`
  now run through one shared workflow driver that chooses between the
  streaming and collecting engine entry points under the negotiated output
  format. The driver checks the interrupt token and the installed invocation
  deadline before every NDJSON event emission — previously only `fuzz`
  checked — and once more after a collecting run completes, before the
  report renders: an interrupt landing in that window now exits cancelled
  instead of printing the report.
- `dns` retry delays, the wait between `dns` batch questions, and `replay`
  source-timing and inter-pass waits use the shared execution context's
  pacing order: check, start accounting the delay, sleep, check both
  cancellation and `--max-duration-ms`, surface a clock failure, account the
  delay, then add it to elapsed statistics. A wait that overruns
  `--max-duration-ms` while the clock also fails now reports the duration limit
  instead of the clock failure, and a batch question stopped that way is
  unattempted rather than failed. `dns` elapsed statistics include a retry
  delay only once that delay has been accounted.
- Serial `scan` and `traceroute` pace and execute probe batches through one
  shared execution context with a fixed step order: the execution permit is
  checked before evidence validation, a batch's statistics are merged before
  an interruption observed after that batch surfaces, and time is accounted
  after validation. When a batch execution fails while the operation is
  cancelled or out of time, the run now reports the cancellation or
  `--max-duration-ms` limit instead of the executor failure.
- Live `fuzz` paces and executes cases through the same execution context.
  After a `--rate` delay it checks both `--max-duration-ms` and cancellation
  before it reports a failed rate timer, so a delay that fails its timer and
  also spends the duration budget now reports `policy.fuzz_resource_limit`
  instead of `io.fuzz_clock`. A case's execution permit, sent bytes and
  evidence are validated, and its statistics merged, before an interruption
  observed after that case surfaces, so invalid evidence is reported even
  when the campaign was cancelled or ran out of time during that case. Time
  is accounted after validation.
- A live `fuzz` case whose exact bytes cannot be prepared on the route its
  executor reported now fails with `fuzz::Error::UnverifiableRoute`, which
  keeps the preparation error as its source, instead of `InvalidEvidence`
  with that error's text. The code (`internal.fuzz_evidence`) and message are
  unchanged; the error's `causes` now list the preparation error.
- Native libpcap and Npcap failures keep the status and error-buffer text the
  API reported as their source, instead of formatting them into the message
  with no source. Codes are unchanged; the text moves from the message to
  `causes`. A failed Windows system-directory lookup keeps its OS error, and
  IP Helper adapter enumeration that never stabilizes keeps its
  buffer-overflow status. A `connect` scan attempt stopped before its provider
  ran publishes the same socket error kind (`TimedOut` or `Interrupted`), and
  its message now names the spent deadline or the cancellation.
- Documentation generation, staged output writes (the `stage`, `inspect`,
  `sync`, and `publish` steps behind `export`, `merge`, `rewrite`, and
  `follow --write`), `follow` payload writes, failed input opens and reads
  (`open PATH failed`, `read packet input failed`, and the frame and UDP
  payload variants), `capture --write` file I/O failures (`capture file PATH`),
  NDJSON encode and write failures (deadline, serialization, and write,
  including the bounded writer's `write NDJSON output failed`), capture-file
  output to stdout (`write stdout failed`, `flush stdout failed`, or the
  capture write and initialize variants), and temporary capture storage
  failures (`create temporary capture output failed`, or its read, rewind,
  initialize, or write variant) no longer repeat their underlying error in the
  error `message`. The message names what failed, and the underlying error (the
  operating-system error for an input open, read, or write) appears once in
  `causes` (after `caused by:` in human output), as the first entry except for
  an NDJSON stdout write failure, whose `causes` list the bounded writer's
  `write NDJSON output failed` first and the operating-system error second.
  Error codes (`io.output_file`, `io.capture_file`, `io.stdout`, and the others),
  kinds, remediation, and exit codes are unchanged.
- `rewrite --source-mac` and `--destination-mac` accept dash-separated
  addresses (`02-00-00-00-00-01`) as well as colon-separated ones, matching the
  grammar that packet expressions, packet documents, and filters already
  accept; dashes were previously refused. A malformed address now always reports `invalid
  hexadecimal MAC address; expected six two-digit bytes separated by ':' or
  '-'`, replacing both `MAC addresses require six colon-separated hexadecimal
  bytes` (wrong shape) and `invalid hexadecimal MAC address` (bad digits); the
  exit code (2) and `cli.error` code are unchanged.
  `packetcraftr_core::packet::MacAddress` gains `FromStr`, which reports a
  malformed address as the new `packet::Error::InvalidMacAddress` (classified
  `cli.error`).
- PCAPNG interface description and packet blocks with a malformed option list
  now report the structural error (truncated option, non-zero end-of-options
  length, or non-zero bytes after the end marker) even when an earlier
  `if_tsresol`, `if_tsoffset`, or `epb_flags` option also has an invalid length
  or repeats; previously that value error was reported first. Accepted captures
  are unchanged.
- `--http-port` and `--dns-port` show the value name `<PORT>` (was
  `<HTTP_PORTS>` and `<DNS_PORTS>`) in help, man pages, completions, and usage
  errors. `--max-application-retained-bytes` describes its decoded-object
  charge as "a flat decoded-object expansion multiplier (DNS name compression
  can exceed it)" where it said "conservative", on `http` as well as `dns-read`
  because the flag is shared; `--resource-diagnostics` publishes that text as
  the setting's `scope`, and man pages and completions follow.
- `traceroute` reports a UDP probe plan whose destination ports run past 65535
  as, for example, `invalid traceroute destination port: base UDP port 65500
  plus probe 89 exceeds 65535`, naming the index of the last probe where it
  named the probe count (`plus 90 unique probe(s)`). The code
  (`cli.traceroute_limit`) and exit code (2) are unchanged.
- Live `fuzz` reports a case whose executor returned inconsistent evidence with
  the shared evidence wording, `successful exchange statistics do not account
  for every fuzz probe` and `successful exchange reported N sent bytes for M
  exact frame bytes` where it said `successful live execution must account for
  exactly one attempted and completed packet` and `sent receipt and byte
  statistics disagree`, and capture-statistics failures read `capture
  statistics are invalid: ...` where they read `invalid capture statistics:
  ...`. The campaign duration is no longer re-checked between these checks, so
  a matched response without a timestamp or slower than the case timeout,
  returned after the duration expired, reports `internal.fuzz_evidence` where
  it reported `policy.fuzz_resource_limit`.
- `fuzz` Boundary mutations probe the target field's real accepted width and
  use its zero, one, half-range, maximum minus one, maximum, and maximum plus
  one (kept as rejected-input evidence), where a fixed list of 0, 1, and the
  8-, 16-, 32-, and 64-bit maximums applied before. A seed or `--first-case`
  that reproduced a Boundary case on an earlier build may now yield different
  values; Random, BitFlip, and Malformed reproductions are unchanged. Probing
  is capped at 64 set attempts per field and falls back to the fixed extremes
  for a limit that needs more, such as an exotic non-power-of-two one; no
  built-in field does.
- UDP ports 5353 (mDNS) and 5355 (LLMNR) dissect as `dns`, so the `dns`
  command types its probes to ports 53, 5353, and 5355 alike as DNS. A
  record whose class carries the mDNS cache-flush bit (the top bit, RFC 6762)
  decodes its A, AAAA, SRV, TXT, and other typed IN rdata instead of unknown
  rdata, and the record keeps its full 16-bit class. Datagrams on UDP 69, 514,
  2152, 5353, 5355, and 6635 and on IP protocols 97, 137, and 143 that decoded
  as `raw` now decode as typed layers, so `dissect` and `read --dissect` output
  for such captures changes, and so do filters that matched their raw payloads.
- The `--decode-as` UDP allowlist and its help text now also accept `gtpu`,
  `tftp`, and `syslog`. Generated man pages and shell
  completions change with the help text.
- Setting a `syslog` layer's `format` moves the header defaults that were left
  untouched: switching to `rfc3164` clears the RFC 5424 version and nil fields,
  so `syslog(format="rfc3164", message="...")` builds without blanking each
  header field, and switching back after a real change restores them. Values
  set explicitly stay, and a legacy message still refuses them.
- Analysis does not scope GTP-U or EtherIP inner flows by TEID or tunnel: they
  have no encapsulation identifier, which needs an output schema change.
  Identical inner tuples carried between the same outer IP pair in different
  TEIDs or EtherIP tunnels share one scope and stream. Known limitation.
- `dissect --link-type` accepts link types by name or number through the
  parser `build --link-type` uses: `null`, `bsd-null`, `ethernet`, `bsd-raw`,
  `raw`, `loop`, `bsd-loop`, `linux-sll`, `sll`, `ipv4`, `ip`, `ipv6`,
  `linux-sll2`, and `sll2`; any other decimal DLT is still a number.
  `build --link-type` validates its value while arguments are parsed, so an
  unknown name is a `cli.error` usage failure (exit 2) listing the accepted
  names, and it is no longer reported as "--link-type requires PCAP or PCAPNG
  output" for a non-capture output.
- `read --normalize` with `--output pcap` converts to classic PCAP instead of
  failing, and its error for any other format reads "--normalize requires PCAP
  or PCAPNG output" (`cli.capture_normalize_format`, exit 2).
- `expert` emits an Info `tcp.not_closed_at_end` finding for an established TCP
  connection still open when the capture ends, so aggregate finding counts,
  summaries, and totals grow by one note per such connection. It reports
  `tcp.connection_refused` instead of `tcp.reset` for a reset that answers a
  SYN or SYN-ACK, `tcp.fast_retransmission` instead of `tcp.retransmission` for
  the acknowledged-edge segment resent after three duplicate acknowledgments,
  and `tcp.out_of_order` instead of the retransmission label for a segment that
  fills a gap already reported as `tcp.previous_segment_not_captured`. See
  `docs/migration-unreleased.md`.
- A malformed `fuzz --field` or an unresolvable selector fails with
  `cli.selector` (usage, exit 2) instead of `cli.fuzz_limit`, and the
  `--payload-file` syntax error reads `--payload-file requires
  <protocol>[#occurrence].<field>=PATH or LAYER.FIELD=PATH`. `fuzz --field`,
  `--axis`, `--set`, and `--payload-file` read one selector grammar, so field
  names are case-insensitive in all of them.
- A display filter that reads `frame.time_epoch` or `frame.time_nsec` on a
  frame without a timestamp fails with `display filter requires frame.time_epoch
  or frame.time_nsec, but the frame has no timestamp`; the code
  `packet.timestamp_unavailable` is unchanged. The `cli.filter_unsupported_field`
  hint for `tcp.stream` and `udp.stream` now names `stats`, `expert`, and
  `export`, which number conversations, and no longer names `follow`, which has
  no `--filter`. `packetcraftr topics filters` lists exactly where those fields
  work: `stats`, `expert`, `export`, `verify-forwarding`, and `read` with
  `--field`.
- `examples/documents/output-protocols-success.json` lists the new protocols and
  now matches `protocols --output json` row for row (the `dns` matcher is
  `true`).

### Removed

- Retired optional local harnesses that CI and release never invoked:
  `scripts/check-http2-oracle.py`, `scripts/check-native-capture.py`, and
  `scripts/measure-analysis.py`. Decoder-oracle packet generators now live in
  `scripts/check-decode-oracle.py`. Isolated native validation remains
  `scripts/test-native-isolated.py`.
- The `internal.final_wire_authorization`, `internal.target_resolution`, and
  `internal.unsupported_operation` codes are no longer reported: they
  classified an authorizer that lacked final-wire authorization or target
  resolution, and an operation handed to an authorizer built for another
  workflow. Those capabilities are now separate internal traits and each
  workflow admits its own operations, so the failures cannot occur.
- Rust: the equivalent public paths `packetcraftr_core::{Packet, PacketError}`
  (use `packet::`), `build::{Context, Mode, DEFAULT_MAX_LAYERS,
  DEFAULT_MAX_PACKET_SIZE}` (use `codec::` and `packet::`),
  `protocol::application::{Dns, Tls}` (use `dns::Dns` and `tls::Tls`),
  the `protocol::application::tls::{codec, fingerprint, model, names, parse}`
  submodule paths (use the flat `tls::` re-exports),
  `analysis::pcap::DEFAULT_SIZE_LIMIT` (use
  `frame::DEFAULT_MAX_SIZE`), and `packetcraftr::dns::tcp::SocketFault` (use
  `packetcraftr_core::error::Source`).
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
  `packetcraftr::replay::{Authorizer, Operation, ReplayFrame, WireBudget}`
  re-exports; import `Operation` from `packetcraftr::policy` (`WireBudget` is
  now `WireLimits`); `PolicyAuthorizer`, `Authorizer`, and `ReplayFrame` have no
  replacement.
- **Breaking:** the `packetcraftr_netio::link::{MacAddress, VlanKind, VlanTag}`
  re-exports; import them from `packetcraftr_core::packet`.
- The `#[doc(hidden)]` `packetcraftr_core::layer::{malformed_layout,
  padding_layout}` exports.
- **Breaking:** `packetcraftr::dns::ResponseMetadata::response_code_name` and
  `ValidatedResponse::response_code_name`; use the canonical
  `packetcraftr::dns::response_code_name` function.
- **Breaking:** `packetcraftr::dns::{MAX_MESSAGE_BYTES, MAX_RECORDS,
  MAX_NAME_POINTERS}`; the DNS decode ceilings are defined once, in
  `packetcraftr_core::protocol::application::dns` (values unchanged: 65535,
  4096, and 128), and `MessageLimits` validates against those values. Import
  them from core; `dns::MessageLimits::default().max_message_bytes` gives the
  default message-size limit. See `docs/migration-unreleased.md`.

### Fixed

- Serial raw scans retain queued replies processed after expiration as late
  evidence, and label replies as duplicates only when the probe has a winner.
- Serial raw scans label in-window replies rejected by the response limit as
  duplicate evidence, preserving the late label for arrivals after the window.
- Raw scans reserve evidence capacity for outstanding probes before retaining
  extra replies, so early duplicates cannot crowd out later winning frames.
- The scan help exclusion example uses `ssh`, which is in the bundled port catalog.
- `scan --transport` accepts one argument per occurrence, preserving positional
  targets after the option while retaining comma-separated and repeated values.
- The output v8 schema accepts port zero in JSON and NDJSON scan listings,
  matching accepted numeric port selections.
- Raw scans retain winning replies before duplicates under tight evidence
  budgets, and serial scans retain eligible late unsolicited captures.
- Unqualified port presets expand in the requested transport order.
- Pipelined raw scans keep settled packets charged against the preparation byte
  budget and evict the oldest cached packets when admission needs space.
- Raw scans reject pre-send capture markers when matching settled probes, so
  stale frames cannot consume late-reply evidence budgets.
- Port selection returns an error instead of panicking when a caller-supplied
  catalog preset references a missing entry.
- TCP connect scans report coalesced duplicate target declarations in text,
  JSON, and NDJSON completion diagnostics.
- Invalid target-planning durations report the requested milliseconds instead
  of zero, saturating only values above `u64::MAX` milliseconds.
- Invalid `scan` target and exclusion declarations retain their typed error
  codes and remediations while reporting argument or manifest provenance.
- The scanner benchmark rejects corpora without the required scheduling
  windows `[1, 2]`, preventing incomplete case inventories from reporting
  complete coverage.
- Pipelined raw scans charge each probe's owned zone and interface-name strings
  against the preparation byte budget before collecting batches and during admission.
- Windows IPv6 zones resolve using `Ipv6IfIndex`, including when it differs from
  the IPv4 interface index; native identity checks accept either current index.
- Raw and TCP-connect scan text output includes IPv6 scope zones in endpoint
  labels, so identical link-local addresses on different interfaces stay distinct.
- TCP connect scans charge owned zone and interface-name strings against the
  evidence byte budget before publishing probes and include them in retained
  evidence statistics.
- `scan --udp-payload-file -` accepts empty redirected stdin, matching empty
  payload files while retaining the 65507-byte limit.
- `rewrite`, `export`, `merge`, and `follow --write` bind staging, publication,
  and rollback to the parent directory opened before input is read. On Linux
  with procfs they address the directory handle, so a parent path retargeted
  during the run (a swapped symlink or a renamed and replaced directory) cannot
  redirect the output or its staged bytes; elsewhere the directory identity is
  re-verified before publication and rollback, and a change is refused with
  `io.output_file` ("changed since staging"). Follow rollback removes exactly
  the files it published and keeps reporting the requested paths. Destinations
  naming a directory (a trailing separator or `/.`) are refused at staging
  ("requires a file name").
- Offline HTTP/2 validates every `Connection` and `Upgrade` list member of an
  h2c offer or 101 response, requires an absolute-form h2c target authority to
  match `Host`, requires `:protocol` to be a non-empty token, and rejects the
  fields RFC 9110 prohibits in trailers (framing, routing, request modifiers,
  authentication, cache control, and content processing fields).
- Offline HTTP/2 reports a server response on a client stream above the
  server's own earlier GOAWAY `last_stream_id` as a Confirmed stream-scoped
  `response_after_goaway` instead of an unprocessed response, confirms
  provisional idle-stream diagnostics as soon as a later client stream id
  proves the lower id was never opened (not only at a clean FIN), and releases
  provisional idle-stream evidence for a promised id only after the promise is
  admitted.
- Offline HTTP/2 attributes a connection-fatal frame error to the malformed
  frame alone when its declared length is buffered, leaving later coalesced
  frames as terminal evidence, reports positive-length DATA after a
  capture-early 204/205/304 response as a Confirmed `bodyless_response_body`
  violation instead of an indeterminate unknown-stream issue, and clears
  retained pending-opener entries when a connection drains.
- Release archives ship the HTTP/2 example captures and `output-http2-*`
  documents that the README and docs reference, and every published example
  document is validated against its declared schema.
- Reconcile provisional idle-stream diagnostics at a clean initiator FIN,
  validate h2c request-target forms, and reject Host routing fields in trailers.
- Preserve directional END_STREAM state across peer resets before admitting
  later promises, headers, or DATA as in-flight traffic.
- Reject pushed-stream reuse after PRIORITY errors and impossible delayed
  parents after a clean client FIN.
- Retain idle PRIORITY errors and capture-delayed resets, and defer pushed
  requests until their capture-delayed parent opens.
- Reconcile pending SETTINGS and WINDOW_UPDATE ordering before confirming stream
  overflow, without treating unacknowledged increases as proven; compare Host and
  :authority using URI host, address and port normalization.
- Confirm remaining stream-window overflow on a clean sender FIN and validate
  exactly one Host authority before accepting an h2c upgrade request.
- Require a target authority or Host fallback for HTTP(S) requests, validate
  generic URI authorities on other schemes, and reject content in TRACE requests.
  Retain invalid priority state on capture-delayed response HEADERS.
- Retain delayed request messages after invalid early response fields or DATA,
  while preserving confirmed response failures and rejecting later response activity,
  including response follow-ups interleaved with a delayed request body.
- Preserve semantic failures in capture-delayed response headers, reject
  trailers on 204/304 responses, and terminate idle-stream WINDOW_UPDATE errors.
  Keep h2c header settings separate from the mandatory on-wire preface.
- Reject malformed fallback Host authorities and duplicate Host fields in
  HTTP/2 requests while preserving their original header evidence.

- Evaluate HTTP/2 SETTINGS overflow before credit from later peer WINDOW_UPDATE
  frames, using bounded snapshots rather than cross-direction capture order.

- Validate classic CONNECT host/port targets, preserve delayed-response final and
  END_STREAM state, reconcile positive concurrency limits after peer FIN, and
  apply transient SETTINGS changes only to eligible existing streams. Treat
  skipped stream IDs as closed and retain payload-free reverse FIN evidence.

- Retain bounded unresolved HTTP/2 credit debt after message completion for later
  FIN reconciliation, and exclude intermediate values inside a SETTINGS frame
  from usable DATA credit.

- Preserve early HTTP/2 response ordering when client openers are capture-delayed,
  associate payload-free reverse TCP resets, correct reserved-stream issue scope,
  and charge decoded SETTINGS vectors against retained-output limits.

- Confirm HTTP/2 DATA credit exhaustion after the granting direction cleanly
  closes, retaining uncertainty for possible pending SETTINGS credit and valid
  negative windows caused only by a SETTINGS decrease.

- Invalidate retained HTTP/2 messages on stream failure even after their active
  slot has closed while awaiting SETTINGS acknowledgment reconciliation.

- Reconcile provisional HTTP/2 flow-window overflow when senders end, retain both
  unmatched ACK heads at EOF, and correct closed-stream/push-limit diagnostics.
  Deferred message emission now releases completed push slots and rejects later
  HEADERS on an already-ended sender.

- Byte-complete HTTP/2 messages now remain in their charged stream state while
  an early SETTINGS acknowledgment is unresolved, then emit Complete after
  reconciliation; unresolved ACK failures still prevent complete message output.

- Offline HTTP/2 defers capture-early SETTINGS acknowledgments in bounded
  directional buffers until peer SETTINGS can reconcile them, preserving
  incomplete evidence while acknowledgment is unresolved. Flow-window overflow
  distinguishes delayed DATA from proven violations; URI paths validate their
  characters and percent escapes, and malformed bodies close affected streams.

- Offline HTTP/2 terminates DATA violations on reserved push streams and closes
  malformed field-section streams after retaining their decoded evidence. Early
  peer response blocks/DATA preserve ordering uncertainty without discarding
  later requests, and HTTP(S) authorities validate URI host/port syntax.

- Offline HTTP/2 keeps capture-delayed peer resets uncertain, closes rejected
  promised streams, rejects userinfo in HTTP(S) authorities and forbidden field
  control bytes, and interrupts long HPACK/Huffman decoding at cancellation or
  deadline checkpoints while preserving the original interruption error.

- Preserve uncertainty for capture-delayed resets, unproven pre-ACK HPACK
  shrinks, and partial request heads at EOF; known zero concurrency limits and
  causally established table minima remain enforced. Unsolicited SETTINGS ACKs
  now stop subsequent message processing. Embedded self-dependent HEADERS priorities
  close their stream after HPACK decoding, and fully captured unprocessed
  messages still validate content length.
- Flush confirmed PRIORITY, stream-window underflow, premature DATA, and
  concurrency violations without misclassifying uncertain peer closure. Enforce
  causally proven HPACK decreases before pending increases, retain post-reset
  push correlation, and classify unmatched midstream HTTP/1 responses at EOF.
- Terminate confirmed GOAWAY, idle-window, connection-window, and push-parent
  violations; flush only the affected stream on stream-window overflow. Preserve
  in-flight push reservations after a peer reset and reject conflicting CONNECT
  authority/Host values.
- Retain early HTTP/1 prelude responses in bounded source-tracked buffers until
  partially captured request heads can be matched across capture ordering.
- Stop HTTP/2 analysis after confirmed initial-SETTINGS, window-overflow,
  idle-reset, disabled-push, and invalid h2c-settings connection errors.
  Preserve unsolicited/interim HTTP/1 prelude errors, method-dependent response
  semantics after malformed headers, pending frame-size increases, and sourced
  late-GOAWAY corrections for completed exchanges.
- Keep malformed HTTP/2 priority status across CONTINUATION, preserve the final
  response after malformed informational headers, and reject idle-stream DATA,
  invalid SETTINGS, invalid request-target forms, and content on 205 responses.
  Bound duplicate SETTINGS diagnostics and compression provenance processing,
  charge retained message metadata, and emit sourced corrections when a later
  GOAWAY excludes an already-emitted request.

- Preserve HTTP/2 stream-local frame errors and HPACK state, accept advertised
  HPACK table increases before ACK, and charge retained frame provenance.
  Reject unsafe push methods, non-CONNECT `:protocol`, literal path fragments,
  and forbidden framing fields on h2c 101 responses.

- Coalesce duplicate HTTP/2 SETTINGS window changes so acknowledgment work
  is linear in active streams while preserving intermediate overflow checks.

- Offline HTTP/2 analysis accepts all HTTP token methods during h2c startup,
  preserves refused upgrade evidence while allowing later retries, retains
  pushed HEAD semantics, rejects empty CONNECT authorities, and tolerates
  peer frames already in flight when a stream reset is observed.

- The forwarding reference consumer rejects malformed retained detail collections
  and typed preservation evidence, including partial evidence, before interpreting
  a verdict. Invalid Unicode
  rule strings now produce a contract error instead of an unhandled traceback.

- TCP connect scan regressions coordinate worker admission and logical deadlines
  so timeout and route checks remain reliable under scheduling load.

- Detached consumer validation writes valid UTF-8 Cargo manifests when the
  checkout path contains non-BMP Unicode characters, including emoji.
- The offline forwarding regression harness accepts relative output directory
  names beginning with `-` without parsing generated capture paths as CLI options.
- Analysis measurement reports distinguish allocator-run exits and produced
  profiles, and include input metadata for pipe and handshake measurements.
- `dissect --hex` accepts leading whitespace before a `0x` or `0X` prefix,
  consistently with hexadecimal input from files and standard input. All three
  sources reject hexadecimal text that decodes to no bytes as missing input.
- Shell completion generation reports write failures as `io.documentation`
  errors (exit 5) instead of panicking, including when the destination is full.
- Response matching and transport attribution require every encapsulated IP
  envelope and intervening tunnel protocol to match the reversed request path,
  including intermediate envelopes, while preserving source-routing endpoints.
- Native capture activation honors the caller's deadline and cancellation while
  libpcap or Npcap is blocked, retaining worker admission until cleanup finishes.
- Isolated native validation retains a matching child report's specific error
  alongside the parent launcher failure, preserving diagnostic detail.
- Library TCP connect scans reject interface, preferred-source, and explicit
  link-mode overrides before scheduling any connections.
- Detached provider deadlines retain inherited cancellation through every
  parent, including native worker waits and TCP connect workers.
- DNS TCP connects, including UDP fallback, use the admitted native worker
  pool and carry the client's cancellation signal. A stalled connect no
  longer holds the workflow after cancellation or its finite wait expires.
- DNS TCP waits wake on connection completion, so short attempt windows
  are available for query I/O instead of being consumed by polling sleeps.
- TCP connect scans preserve completed connections' verdicts and latency
  when an earlier event sink is slow. Pending attempts still expire on the
  client's clock. Native route and interface worker waits use wall time
  even when the caller supplies a frozen clock.
- Capture activation and timestamp discovery recheck the deadline after
  interface discovery. Unsupported capture paths honor cancellation and
  expiry before reporting an unavailable capability.
- Send and exchange template failures keep their detailed typed source in
  `causes` without copying its text into the wrapper message.
- `--payload-file SELECTOR=PATH` preserves non-UTF-8 filenames and parent
  directories instead of rejecting the entire argument as non-UTF-8. The
  selector remains text, and spaces, Unicode, and `=` in paths keep their
  existing behavior.
- Route lookup honors the caller's deadline and cancellation instead of the
  backends' own timeouts (2 seconds per operation and 3 seconds per response
  on Linux netlink, 2 seconds on macOS routing sockets). A lookup the deadline
  stops fails with `io.deadline_exceeded`; a netlink timeout was reported as
  `io.route` before. Interface enumeration and the capture interface check
  over netlink follow the same deadline.
- `neighbor::Options::validate` keeps the capture-limit refusal as the
  `source` of `neighbor::Error::InvalidOptions` (a new field) instead of
  flattening it into the message, so it is reported once, as a cause. The
  message now reads "capture bounds are invalid"; the code stays
  `cli.neighbor_limit`.
- A neighbor request frame that core refuses to encode or build keeps that
  refusal as the `source` of `neighbor::Error::InvalidRequest` (a new
  `Option<error::Source>` field) instead of flattening it into the message, so
  it is reported once, as a cause. The message now reads "discovery frame does
  not build" or "neighbor solicitation does not encode"; the code stays
  `internal.neighbor_invariant`.
- DHCP limits above 65535 message bytes, 4096 options, or nesting depth 8 are
  refused with `dhcp::Error::InvalidLimit` (`policy.dhcp_limit`) instead of
  being silently lowered to those ceilings, which are now public as
  `dhcp::{MAX_MESSAGE_BYTES, MAX_OPTIONS, MAX_NESTING}`.
- DNS decode limits above 65535 message or TXT bytes, 4096 records or TXT
  strings, or 128 name pointers are refused with `dns::Error::InvalidLimit`
  (`policy.dns_limit`) instead of being silently tightened, and the ceilings
  are public as `dns::{MAX_MESSAGE_BYTES, MAX_RECORDS, MAX_NAME_POINTERS}`.
- The filter reference distinguishes protocol schema list selectors from
  reserved `frame.protocols`, which supports whole-list comparisons and
  `count(frame.protocols)` without element selectors.
- A strict build accepts link padding inside a packet rooted at `vlan` or
  `vlan8021ad`, as decoding already produces it, instead of failing with
  `PaddingWithoutLinkLayer`.
- `dns-read`, `http`, `fragment`, `merge`, `export`, and `rewrite` print text
  output through the terminal-sanitizing writer, as every other command does,
  and `capture` no longer prints interface names and saved-file paths in its
  text summary unsanitized. `dns-read` and `http` text spells statuses,
  optional values, and frame lists as the JSON document does instead of Rust
  `Debug` formatting, HTTP header names are escaped like their values, and
  `dns-read` prints each message's questions and records. DNS records print
  in one line shape across `read`, `dissect`, `capture`, `dns-read`, and
  `dns`. These six commands also gain `--help` examples.
- Offline analysis commands (`stats`, `expert`, `follow`, `tls`, `dns-read`,
  `http`, `export`, `verify-forwarding`) reject a `--max-duration-ms` above
  one hour with `cli.analysis_limit`, the code they already publish for a
  zero duration. They previously accepted any duration, including ones no
  deadline could represent, while every live workflow was capped at one hour.
- Replay text output reports a stdout write failure even if the invocation
  deadline expires while the write is blocked.
- `exchange --output ndjson` no longer fails with
  `policy.exchange_duration_limit` whenever a request goes unanswered; events
  published after the collection window get their own finite allowance.
- `replay --interface NAME` or `--interface INDEX` no longer fails its first
  frame with `internal.replay_evidence` once the selector resolves to the
  complete interface identity.
- TCP connect scans wait for native connect admission held by cancelled or
  finishing attempts instead of failing with `io.tcp_connect_capacity`.
- Linux routes multicast destinations instead of reporting
  `io.route_not_found`, and reports an unassigned preferred source or a vanished
  interface hint as macOS and Windows do. macOS reads the interface netmasks XNU
  trims (addresses were reported as /32 and /128) and reports a missing route
  as `io.route_not_found`. Capture filters receive their BPF netmask in host
  byte order, so `ip broadcast` matches directed broadcasts.
- ARP and NDP resolution accepts replies on the same VLAN whatever their
  priority or drop-eligible markings.
- Capture sources publish `overflow_policy` as `drop_newest` and
  `drop_oldest`, the spellings the v6 schema requires.
- Generated capture output and `read` or `replay` format rejections no longer
  leave an empty gzip or zstd container on stdout.
- `merge`, `rewrite`, and replay PCAPNG output are bounded by the capture-wide
  interface ceiling rather than the per-section `--max-interfaces`.
- Parse-error documents name the command when `--resource-preset` precedes it,
  an unwritable NDJSON parse-error record reports its write failure once, and
  input, follow, generated documentation, send output, and capture consumer
  failures keep their underlying I/O causes.
- `--version` of Layer 2 and Layer 3-only builds lists `native-route`.
- TLS ALPN text escapes the wire octets instead of the UTF-8 of U+FFFD for
  names that are not UTF-8, in layers and session summaries, and supported
  group 0x0013 is named `secp192r1`.
- Linux cooked captures whose link addresses exceed the 8-byte slot (IPoIB)
  dissect and rebuild byte-exactly; BSD NULL and LOOP families numbered 4 or 6
  no longer select IPv4 or IPv6; PPPoE stage codes are checked under GRE and
  SNAP parents; and a raw IPv6 option-header Next Header stays raw when built.
- HTTP analysis reports header-count and start-line limits as `limit`, pcapng
  merge and map refuse the undefined packet direction instead of rewriting it,
  export plans define every scope their incomplete datagram groups name, and
  IPv6 fragment reassembly charges a replaced prefix copy at its admission
  peak.
- Packet expressions reject `bytes(...)` and `hex(...)` bodies without an
  opening quote, a space in a field assignment path is named as such, and a
  hand-built malformed layer naming `IPv4` in another case meets the same
  destination guard as `ipv4`.
- Target selection reports the 100000-candidate budget when a network overruns
  it, instead of the remainder.
- The root and `dissect` help examples decode without diagnostics,
  `--decode-as` help and README list every accepted protocol, and flags without
  help text gained descriptions.
- The YAML packet-document fuzz seed is a valid packet/v2 document, the release
  archive verifier requires the rewrite v2 schema, and CONTRIBUTING and
  CODEOWNERS name current paths.
- DNS reports RCODE 11 as `dso_type_not_implemented` instead of `unknown`.
  `decode.unknown_binding` and `decode.missing_codec` diagnostics carry their
  `layer`. Scan pipeline refusals name the bound that failed, and TLS, UDP
  encapsulation-port, VXLAN, Geneve, resolved-address-limit,
  destination-constraint-count, and document-limit messages or remediations
  name what is actually at fault.
- `builtin::registry_with_tls_ports` refuses port 0, TCP's raw-fallback
  discriminator. On Windows, an Npcap runtime without `pcap_free_tstamp_types`
  reports timestamp selection as unsupported instead of leaking the listed
  types.
- Forwarding verification keeps incomplete layer occurrences unevaluable even
  when only one scalar value was decoded, preventing false preservation and
  expectation failures after truncation. Explicit occurrence selectors retain
  readable fixed-size header evidence.
- Forwarding aggregate publication measures the complete pretty-printed JSON
  envelope and newline before writing, enforcing the consumer's 16 MiB ceiling.
- Forwarding stream indexes retain canonical numbering after fragmented
  conversations without using reconstructed packets as comparison evidence.
  Resource diagnostics include indexes and IP reconstruction required by rules
  as well as filters. The reference consumer rejects comparison counters that
  contradict the capture census.
- Capture preparation, metadata reads, repeated analysis, comparison and
  pre-publication checks share an invocation deadline. Reader clock scopes
  restore correctly on errors and callback unwinding; committed files remain
  committed after a later reporting failure.
- Unrequested forwarding conversation indexes no longer exhaust the flow budget
  before physical-frame selection.
- Restore native Windows Layer 2 builds by passing default native settings
  when opening the Npcap transmit handle.
- Timestamp-type discovery safely handles empty lists from libpcap and Npcap
  when only the default timestamp type is supported.
- Forwarding verification uses physical-frame evidence, keeps exhausted identities
  unkeyable, shares the field budget across all observation cells, counts reordered
  pairs independently of detail limits, and rejects nonliteral expectation values.
- Rewrite v2 rule loading rejects unknown assignment properties instead of
  silently ignoring them, matching the published schema.
- Repair inner checksums before enclosing transport checksums when editing
  tunneled packet fields, preserving valid outer UDP checksums in VXLAN.
- DNS matching preserves sequence-aware TCP correlation, and UDP probes validate
  inner tunnel endpoints and transport identity before reporting an open port.
- TCP reassembly reports the actual retransmitted sequence spans of an
  arriving segment, so sourced analysis no longer drops provenance for the
  unique bytes of a gap fill that overlaps pending data at its middle or
  end. This corrects `internal.application_sources` failures in HTTP and
  DNS-over-TCP collection.
- `Transfer-Encoding` values parse as `1#transfer-coding`: commas and
  semicolons inside quoted-string parameters no longer split codings, and
  optional whitespace before parameters is accepted, so a quoted parameter
  cannot masquerade as a final `chunked` coding.
- HTTP chunk sizes tolerate whitespace before the chunk-extension delimiter
  (`3 ;x=y`), while whitespace inside or before the hexadecimal digits stays
  invalid; a tolerated extension no longer disables the direction's
  pipelined analysis.
- DNS, DHCPv4, and DHCPv6 borrowed wire conversions reject oversized input
  before allocating a copy.
- macOS route parsing accepts Darwin's aligned zero-length default netmask,
  and local routes may select a source assigned to another local interface.
- HTTP analysis advances its application generation when TCP reassembly
  confirms tuple reuse after a capture began midstream.
- Pipelined scans consume replies already queued within their ingress windows
  before classifying expired probes as timeouts.
- `read` and replay finalize initialized capture compression after processing
  failures, preserving completed output records and the primary error.
- `rewrite`, `export`, and `merge` recheck interruption after syncing staged
  output, so cancellation or an expired rewrite deadline prevents publication.
- Capture-time bounds skip timestamp-less records without losing input-budget
  accounting; stream projections use the complete frame and byte totals.
  Timestamp parsing rejects fractions the host cannot represent exactly.
- TCP option parsing stops at EOL and preserves the remaining bytes as opaque
  padding; construction checks the 40-byte wire ceiling before copying data.
- DNS batches retain pacing between questions and reject mixed server identities
  before authorization. Send sets validate packet counts and pacing before CLI
  discovery and honor cancellation supplied by an injected clock.
- Capture projections reject unavailable stream indices; generated captures
  validate emitted root headers, and output cleanup preserves secondary errors.
- Empty ICMP `rest` fields accept payload files, list axes retain whitespace
  compatibility, passive planning validates allowlist limits, and clock-regression
  findings retain interface context.
- DNS batches authorize the combined UDP and TCP traffic budget before discovery,
  stop on output failure, and include confirmed traffic from failed questions in
  their totals, including deadline and cancellation failures.
- `read --field` validates and applies epoch bounds with and without stream
  fields, preserving source frame numbers and input-budget accounting.
- `follow --write` synchronizes every staged file before publishing any
  destination, so synchronization failures leave retries unobstructed.
- `build` finalizes initialized capture compression on failure, preserving frames
  already written even when a later packet cannot be encoded.
- IPv6 fragment reassembly retains the offset-zero fragment's unfragmentable
  prefix and Fragment Next Header and accepts the per-fragment variation
  RFC 8200 §4.5 permits, including when the offset-zero fragment arrives last.
- IPv4 and IPv6 reassembly merge fragment ECN codepoints per RFC 3168 §5.3,
  preserve DSCP, recompute checksums, and fail closed when CE and Not-ECT
  fragments mix.
- `build` retains normal signal termination while waiting for recipe input,
  then uses cooperative cancellation while building and publishing packets.
- Exchange packet sets authorize expanded destinations before route preparation,
  so an axis can replace a denied recipe destination with permitted addresses.
- JSON `build` output remains one complete document when interrupted during
  publication; cancellation is reported on stderr with exit code 130.
- Topic errors and binary-to-terminal refusals return I/O exit 5 if their
  diagnostic cannot be written to stderr, matching other command errors.
- Capture-reader help now states that `--max-interfaces` bounds descriptions per
  input PCAPNG section, with a separate 65,536-description capture-wide ceiling.
  Normalization's selected-output interface ceiling is documented separately;
  input filtering and the existing limits keep their behavior.
- Release evidence requires versioned, complete named decoder/native results,
  pinned decoder identity, input/tool digests, exact corpus frame counts,
  matching TLS JA3 evidence, and successful native scenario/launcher exits.
  Missing parent namespace IDs and contradictory or duplicate results are
  rejected. Producers and release validation share the evidence contract.
- Release evidence preflight keeps each download attempt separate when reusing
  an output directory, so a missing current report cannot reuse an earlier
  run's evidence. Failed retries remove only the generated aggregate success
  report and retain downloaded artifacts for diagnosis.
- IPv6 destination classification includes the RFC 9637 `3fff::/20`
  documentation prefix under the same policy as `2001:db8::/32`, without
  accepting adjacent addresses or relaxing other destination checks.
- TLS limit documentation distinguishes logical handshake/alert buffering from
  retained hello summaries, allocation capacity, and total process memory.
- `routes` failures keep the provider's classification, context, and cause
  chain instead of collapsing to a generic I/O message. DNS query construction
  errors and neighbor operation-and-cleanup errors expose their cause through
  `std::error::Error::source`, so `causes()` and rendered help include it.
  Neighbor operation-and-cleanup failures list the operation's cause chain and
  the cleanup error's cause chain in `causes` (for example the libpcap text of a
  failed ARP send), where they listed only the two headlines, and
  `exchange::Error::{OperationAndCaptureShutdown, OutputAndCaptureShutdown}`
  expose the primary failure through `std::error::Error::source`. Codes,
  messages, and exit codes are unchanged.
- Unix and Windows release archives include the resource-diagnostics output
  examples required by archive verification.
- Release archives include the clock-regression and scoped-VXLAN captures and
  reference outputs used by the analysis resource guide's runnable examples.
- TCP pending growth no longer recopies its retained range on adjacent or
  reverse extension. Bounded payload pages and interval metadata are charged
  independently; transient output/history allocations are admitted before commit.
  Tight memory budgets may reject earlier because page slack and peaks are charged.
- Packet-document semantic budgets are independent of object-key order in JSON
  and YAML, including byte arrays, address widths and nested lists. Temporary
  staging remains bounded separately from semantic node/list/payload limits.
- TCP retransmission history uses an explicitly sized ring instead of assuming
  `VecDeque::try_reserve_exact` returns an exact capacity.
- Live DNS truncation errors report the message byte the truncated field
  required.
- Bounded JSON output sizing distinguishes budget exhaustion from serializer
  failures: a value that fails to serialize now reports an internal error with
  the original source instead of the `--max-application-output-bytes` policy
  error, which remains reserved for actual limit exceedances.
- Offline DNS analysis no longer retains an entire capture-record allocation
  behind each emitted UDP message wire and the decoded name/rdata slices
  derived from it. Retained messages now own only their DNS payload, so the
  resource charge tracks the visible evidence instead of the source frame.
- The v6 forwarding consumer requires every retained match to carry the exact
  check set its declared rules produced: missing, additional, reordered, or
  substituted check descriptors (kind, field, declared literal) are rejected
  instead of only validating the checks that happen to be present.
- Invalid hexadecimal input reports the index of the byte holding the bad
  digit. `dissect --hex`, `--udp-payload-hex`, and raw or padding `hex=` values
  reported a digit position in the separator-stripped string, so `aa bb zz`
  said `invalid hex at byte 4`, and a bad low digit got a different number than
  a bad high digit in the same byte. Both digits of a byte now report that
  byte's index, so `aa bb zz` says `invalid hex at byte 2`.
- Resource diagnostics publish `--max-packet-size` on `build`, `dissect`, and
  `fragment` with unit `bytes` instead of `count`, matching the byte ceiling
  the flag sets. `--max-layers` remains a count.
- IPv4 options are read the way the encoder writes them when a TCP, UDP, or
  ICMPv6 layer follows. The transport checksum is computed from the zero-padded
  options, so a source route that ends short of its declared length but is
  completed by the encoder's padding (`83:07:04:c6:33`) is checksummed against
  the route the packet carries. Strict builds of such routes now succeed and
  report `build.ipv4_options_padded`, as an IPv4 layer alone already did;
  before, they failed with `failed to encode layer udp at index 1` (or `tcp`).
  Permissive builds of options the decoder cannot walk no longer fail when
  those layers follow: they build, report `build.ipv4_options`, and compute the
  transport checksum against the IPv4 header destination, as an IPv4 layer
  alone or followed by SCTP already did. Strict builds still refuse those
  options, though the cause text now describes the padded bytes (for example
  `IPv4 option 2 has invalid length 0` instead of `IPv4 option is missing its
  length byte` for `hex("0102")` before a TCP layer); the error code, layer,
  and exit code are unchanged. Options past 40 bytes still fail in both modes
  with the same error.
- A TLS layer whose last record continues in the next segment now rebuilds from
  its own packet document. `incomplete: true` was refused as a read-only field,
  so re-importing a dissected first segment of a TLS flight failed; the rebuilt
  layer keeps the flag and the same retained records, and a non-boolean
  `incomplete` is rejected as a wrong-type error.
- DHCPv4 and DHCPv6 recipes that supply one field under two spellings, such as
  `dhcp(xid=1,transaction_id=2)` or both `chaddr` and `client_hardware_address`
  in a packet document, are rejected (for example with `both xid and
  transaction_id were supplied`), as every other layer already did. Before, the
  alphabetically later key silently won and the other value was discarded.
- The protocol catalog no longer lists `raw_ip` as a parent of `ipv4`, `ipv6`,
  `tcp`, `udp`, `icmpv6`, and the other IP protocols. `raw_ip` is a decode-only
  root that picks IPv4 or IPv6 from the version nibble, so `protocols <name>`
  and `Registry::parent_bindings` published `raw_ip` bindings that never
  applied, and `Registry::child_for("raw_ip", n)` answered for protocol numbers
  it never dispatches on. Raw-IP capture decoding is unchanged.
- IPv4 reassembly accepts a repeated offset-zero fragment whose TTL differs from
  the retained one, such as the ingress and egress copies of a forwarded
  fragment in a `tcpdump -i any` capture. It was refused as
  `InconsistentIpv4Header`, which aborted the whole analysis run; the
  reassembled datagram keeps the first offset-zero fragment's TTL, and DSCP,
  identification, flag, and option differences are still refused.
- TCP reassembly no longer reports a one-byte keep-alive probe as conflicting
  data. A one-byte segment at the last delivered sequence number (SND.NXT-1)
  whose byte differed from the delivered one was classified as a conflicting
  retransmission, which stopped DNS and HTTP decoding of that direction for the
  rest of the connection. It is still reported as a retransmission with
  `conflicting` false, so decoding continues; wider overlaps and one-byte
  overlaps carrying SYN, FIN, or RST still report changed content. `expert`
  follows the same rule: an ACK-less one-byte segment at SND.NXT-1 with a
  different byte is now reported as the Warning `tcp.retransmission` instead of
  the Error `tcp.retransmission_conflicting`, and a keep-alive that carries ACK
  is still reported as `tcp.keep_alive`.
- `analysis::export::plan` no longer inherits `Options.plan` or
  `Options.stream`, as it already did not inherit `Options.filter`. A
  non-indexing plan such as `Plan::physical(Requirements::default())`, or a
  stream selector, used to leave a selected stream in `unmatched_streams` with
  none of its source frames exported. The selected stream is now matched and its
  physical dependencies are exported. `Options.time_bounds` still applies. The
  CLI `export` output is unchanged.
- Display filters accept the reserved `frame.*`, `tcp.stream`, and `udp.stream`
  names with the protocol head in any ASCII case, like every other protocol
  head, so `TCP.stream == 1` and `Frame.number == 1` compile instead of failing
  as unknown fields. The field name after the head stays case-sensitive
  (`frame.LEN` is still unknown). `verify-forwarding` now rejects
  `Frame.number`, `TCP.stream`, and the other capture-local names as
  capture-local whatever the case of the protocol head, where it previously
  rejected the mixed-case spellings as unknown fields (`frame.NUMBER` is still
  an unknown field). A typo after an index, as in
  `dns.answers[0].bogus == 1`, is reported as an unknown field instead of a
  byte-slice error. A pasted non-ASCII character, such as a curly quote or an
  escaped `\é`, is named in the syntax error instead of its first UTF-8 byte
  (for example `â`).
- Capture rewrites that fail on one frame (a mapper or field-edit failure, or a
  mapper that changes frame identity or time) report `context.source_frame` with
  that frame's one-based number, as selection failures already did.
- Failed allocations while reading a capture (classic record data, pcapng
  blocks, section headers, and packet data) now report
  `policy.capture_stream_limit` (exit 6) with the requested size in the message,
  instead of `io.capture_file` (exit 5) or `packet.capture_file` (exit 3,
  "repair the malformed record").
- MAC addresses and hexadecimal numbers require hexadecimal digits. Field
  assignments and expression values, `rewrite --source-mac` and
  `--destination-mac`, `rewrite --vlan` hexadecimal numbers, and `--axis`
  hexadecimal range bounds refuse a leading `+` (`+1:22:33:44:55:66`, `0x+10`)
  instead of parsing it as a valid value, and a packet-expression `0x` integer
  such as `0x+40` is refused as an invalid hexadecimal integer instead of being
  read as `0x40`. Expression values and packet-document MAC fields also refuse
  a MAC that mixes `:` and `-` separators; in an expression, such a value is now
  text rather than a MAC address.
- `fuzz` reports a base-packet list or object above `--max-list-items`, and
  value nesting deeper than the fixed 64-level limit, as
  `policy.fuzz_resource_limit` naming `max_list_items` (or the nesting depth)
  with a matching remediation, instead of blaming the `--max-total-bytes`
  budget. The nesting failure advises flattening the packet's lists and
  objects, since a higher `--max-list-items` cannot clear it, and the
  `--max-list-items` failure does not mention nesting. `--max-list-items` help
  now says it bounds every list and object in the base packet. Library callers
  see the new `fuzz::Error::{ValueItems, ValueNesting}` where they previously
  saw `ValueTooLarge`.
- The `fuzz` boundary strategy no longer emits a Text value longer than
  `--max-field-bytes` (the 16-byte control sequence at limits below 16); default
  limits generate the same cases.
- `fragment --max-fragments 0` reports "packet transform requires max_fragments
  in 1..=8192" instead of claiming 0 exceeds 8192, and its help states the 1 to
  8192 range. It is still `policy.transform_limit` (exit 6). Library callers see
  the new `transform::Error::LimitRange { field, min, max }` for `max_fragments:
  0`, where they previously saw `Error::Limit`. Values above 8192 still return
  `Error::Limit`.
- Editing a field that is not an unsigned integer (for example `rewrite --set
  ipv4.source=1`) reports "field edit targets a field that is not an unsigned
  integer" instead of blaming the value as "not unsigned". The code stays
  `packet.transform_input`.
- Machine-output errors for a progressive output worker that cannot start
  (`internal.progressive_output`) and for a failed system-randomness draw while
  planning DNS queries (`io.dns_entropy`) now publish the operating-system cause
  in `causes` instead of an empty array.
- Capture filter validation is linear in the filter length. A filter at the 64
  KiB limit made of colons or `1:` pairs no longer stalls arming for tens of
  seconds before the capture starts.
- Numeric `portrange N-M` capture filters (for example `udp portrange 6000-6010`
  or `tcp portrange 0x10-0x20`, each half decimal or `0x` hex within `u16`) are
  accepted instead of being rejected as symbolic names. `portrange 80-http` and
  hyphenated operands elsewhere, such as `host 1-2`, are still rejected.
- Library DNS requests are now refused at validation when `transport` is `Tcp`
  or `UdpThenTcp` and the route sets an interface, a preferred source, or a link
  mode other than `Auto`. `dns::Request::validate`, and so `client.dns` and
  `client.dns_batch`, returns the new `dns::Error::UnsupportedTcpRoute`
  (`capability.dns_tcp`) before authorization, target resolution, or any
  traffic. Previously such a request passed validation: `UdpThenTcp` sent its
  UDP query on the overridden route and failed only if the server truncated the
  answer, so a non-truncating server let it succeed, and direct `Tcp` failed
  only after authorization and resolution. Use `TransportMode::Udp` for
  interface, source, or link-mode overrides.
- Replay names an unmatched numeric `--interface`, `--map-interface`, or
  `--map-filter` interface selector in its `io.device` error (`network device 9
  is unavailable: ...`), instead of reporting a device with an empty name.
- A replay whose total inter-pass pause (`inter_pass_delay` across the `repeat -
  1` gaps between passes) exceeds the duration limit is refused with an error
  naming that total, such as `replay duration 5400s is invalid; maximum is
  3600s`, instead of the per-pass delay, which read as within the limit.
- Replay with original or scaled timing keeps the newest capture timestamp as
  its pacing reference when timestamps step backwards, as in captures from
  interleaved interface clocks. The backward step is no longer paid again by the
  next frame, so a capture stamped 10s, 9s, 11s replays with delays of 0, 0, and
  1s instead of 0, 0, and 2s.
- `Client::exchange` admits its sink's runtime worker before neighbor discovery,
  so a runtime with no free worker refuses the exchange with
  `internal.progressive_output_worker_exhausted` without transmitting any ARP or
  NDP frame, as the other workflows already do.
- `exchange --timeout-ms 0` and `exchange::Request::validate` reject a zero
  collection window with the usage error `cli.exchange_limit` (exit 2) before
  the recipe is parsed, instead of failing during preparation with
  `io.deadline_exceeded` (exit 5). The message now states that the timeout must
  be greater than zero.
- TCP connect scans keep a probe whose connection the peer reset after the
  handshake but before the socket's endpoints were queried. It is reported as
  connected with no local address instead of failing the whole scan with
  `io.tcp_connect_evidence`; other endpoint-query failures and a mismatched peer
  endpoint still fail the scan.
- Route planning rejects an unreadable VLAN stack (priority above 7 or VLAN id
  above 4095) before consulting the route provider, so a provider failure can no
  longer mask the packet defect. The 8-tag `MAX_VLAN_TAGS` cap now applies only
  to plans that run ARP/NDP discovery: a Layer 2 packet with more than 8 VLAN
  headers plans when its destination MAC is explicit or a broadcast or multicast
  address, instead of failing with `InvalidNeighborVlan`.
- A `Client` now forgets the interface it resolved from a name or index when
  the route provider rejects it: a failed route lookup, a failed interface
  lookup, or a provider that selects a different interface than requested.
  Before, a device re-created under a new index (or whose index was reused) kept
  failing every `plan`, `send`, and `exchange` that selected it by name or
  index, with `io.interface_not_found` or `internal.route_contract`, until the
  `Client` was rebuilt. Now the failing plan still reports its error, and the
  next one enumerates interfaces again and succeeds. A cancelled or expired
  lookup, and a failure caused by the packet or by policy, keeps the remembered
  interface.
- Target exclusions and `--allow-destination` entries, both exact addresses and
  CIDR networks, now match an IPv4-mapped IPv6 address (`::ffff:10.0.0.5`)
  against IPv4 entries through its embedded IPv4 address. Before,
  `--exclude 10.0.0.5` did not exclude `::ffff:10.0.0.5`, so a connect scan
  could still reach the excluded host, and an IPv4 allowlist entry
  (`--allow-destination 10.0.0.5` or `10.0.0.0/24`) refused the mapped spelling
  of an allowed host with `policy.destination_not_allowed`. The mapped match
  applies at every allowlist stage, including the final wire-byte check. An
  IPv4-compatible address (`::10.0.0.5`) and a mapped address for a different
  host stay refused.
- A progressive-output wait interrupted by cancellation while the sink callback
  is still running now counts toward `cleanup_retaining_capacity`
  (`Runtime::snapshot().timed_out_retaining_capacity`) like a timed-out wait,
  instead of reporting an active worker with 0 retained capacity.
- The `policy.traffic_unit_limit` remediation now reads "reduce the
  connections, messages, or DNS attempts, or deliberately raise the
  packet/socket traffic-unit budget", and `policy.traffic_byte_limit` reads
  "reduce the application or query bytes, or deliberately raise the
  wire/application byte budget". A refused TCP connect scan is no longer told
  only to reduce DNS attempts.
- Generated PCAP and PCAPNG output is no longer capped by core's default writer
  ceiling of 10,000 frames and 256 MiB. `exchange`, `send`, and `fragment` size
  the writer to the frames their own budgets admitted, and `build` sizes it from
  `--max-template-packets` and `--max-packet-size`. An `exchange` or `send`
  capture of more than 10,000 frames, or a raised `build` packet set, used to
  fail with `policy.capture_stream_limit` after the packets were already sent or
  the output had begun.
- Stdout write failures in text, hex, raw, and JSON output and in the
  `--output text` analysis commands (a closed pipe or full disk) now report
  `io.stdout` with its remediation, as capture and NDJSON output already did,
  instead of `io.runtime` with neither. The message reads `write stdout failed`
  and the operating-system error is its only cause, not also repeated in the
  message.
- `exchange` collapses build diagnostics by code in its JSON aggregate and text
  output, as `send` and `build` do. Permissive runs whose packets share one
  warning (for example `build.unbound_layers` across a large `--axis` set)
  published and printed one copy per sent packet; each code now appears once, in
  first-seen order. NDJSON `sent` events still carry their own diagnostics.
- `dns-read` text output brackets IPv6 flow endpoints (`[2001:db8::1]:53 ->
  [2001:db8::2]:49152`) like `follow`, `stats`, and `dns`. It printed
  `2001:db8::1:53`, which reads as a different IPv6 address. IPv4 text output
  and all machine output are unchanged.
- `http --http-port 0`, `dns-read --dns-port 0`, and `http
  --max-http-body-bytes` outside 1..=268435456 are rejected as usage errors
  (exit 2, kind `cli`, naming the flag) instead of reporting a
  `policy.application_limit` error (exit 6) that claimed a limit such as
  `http_ports=256` was exceeded.
- `http` and `dns-read` report a zero or above-ceiling
  `--max-application-messages`, `--max-application-streams`,
  `--max-application-buffer-bytes`, `--max-application-retained-bytes`, or
  `--max-application-source-spans` (ceilings 100,000, 100,000, 256 MiB, 256
  MiB, and 100,000), and more than 256 distinct service ports counting the
  built-in ones, as `cli.analysis_limit` (usage, exit 2, for example `invalid
  analysis limit max_messages=0: must be non-zero`) instead of
  `policy.application_limit` (policy, exit 6), whose message claimed that a
  limit such as `max_messages=100000` was exceeded even for a value of 0. A
  valid limit reached during analysis, such as `--max-application-messages 1`,
  still reports `policy.application_limit`. `application::Limits::validate`,
  `analysis::http::Collector::new`, and `analysis::dns::Collector::new`
  (limits, ports, and for HTTP `max_http_body_bytes`) return
  `application::Error::Analysis(analysis::Error::InvalidLimit { .. })` where
  they returned `application::Error::Limit`.
- A TCP reset ends a partial HTTP or DNS-over-TCP message as `reset` in `http`
  and `dns-read` output instead of `evicted`. A reset evicts both directions
  before it closes them, so the run used to publish an `evicted` issue for each
  direction plus the `reset` issue and end the open message as `evicted`; it
  now publishes the one `reset` issue and the message as `reset`. A reset
  segment's payload no longer counts toward `--max-application-source-spans`,
  because the pipeline drops it before reassembly and no delivery ever
  consumed its span.
- `stats --top N` on the endpoints, ports, and conversations tables keeps the N
  busiest rows, ranked by frames then bytes with key order breaking ties, and
  lists them busiest first, instead of keeping the first N keys, which kept
  every TCP row ahead of any UDP row and the lowest addresses whatever they
  carried. The protocols table stays ranked by frames, the io table keeps its
  first N buckets in time order, and output without `--top` is unchanged.
- `send`, `exchange`, and `plan` validate `--interface` before resolving a
  hostname `--destination`. An invalid selector such as `--interface 0` now
  fails with the usage error (exit 2) without issuing a DNS lookup, where it
  previously ran the lookup first and could report `io.hostname_resolution`
  (exit 5) instead. Because the selector is now read ahead of the
  `--destination` policy checks, an invalid `--interface` combined with a denied
  or unparsable `--destination` reports the usage error rather than the
  destination error; a packet-declared destination denial still reports first.
- `scan --udp-payload-file` reports a payload file over 65507 bytes as a usage
  error (`cli.error`, exit 2, "UDP payload input exceeds 65507 byte limit"),
  matching `--udp-payload-hex`, instead of a `policy.decode_resource_limit`
  decode-budget failure (exit 6) about a captured packet; read failures on that
  file now say "read UDP payload input failed" instead of "read frame input
  failed".
- `--output pcap capture` writes live frames to classic PCAP instead of writing
  the file header and then failing on the first frame with `interface metadata
  cannot be represented in pcap` (`packet.capture_file`). Classic PCAP carries
  no interface IDs, so they are dropped; PCAPNG output keeps them.
- Packet-expression syntax errors report the byte offset of the offending
  construct within the whole expression. Errors inside layer arguments, lists,
  objects, and byte or quoted literals said `at byte 0` or an offset inside a
  sub-slice, so `ethernet()/ipv4(ttl=)` named byte 0 for a missing value at byte
  20. `expression::parse_value` reports offsets in the text it was given.
- DNS `--dnssec-ok` responses keep the RRSIG, DS, NSEC, and NSEC3 records that
  answers, negative answers, and referrals carry, instead of rejecting them as
  unrelated. RRSIGs at the question or CNAME-chain owner that cover the queried
  type or CNAME stay in answers. DS, NSEC, NSEC3, and RRSIGs covering NS, SOA,
  DS, NSEC, or NSEC3 stay in authorities when they belong to the queried name's
  ancestors or their zone. They appear as unknown-type records with exact RDATA.
  Unrelated DNSSEC records, and RRSIGs in the additional section, are still
  rejected. A rejected authority record now reports `authority is not an
  IN-class SOA/NS/DS/NSEC/NSEC3 record (or its RRSIG) for the validated
  question's zone` in `rejected_records[].reason`, where it said `authority is
  not an IN-class SOA/NS ancestor of the validated question`. Other rejection
  reasons are unchanged.
- DNS-over-TCP queries honor cancellation after the connection is established.
  Previously only the connect wait saw the signal, so a server that accepted the
  connection and stayed silent held the workflow for the whole attempt window
  (up to an hour with `--timeout-ms`) until a second interrupt forced exit.
  Write and read waits now re-check the signal every 25 ms, and a query
  cancelled after it was sent reports the query bytes it wrote in the
  statistics.
- Replay paces from the first frame it transmits instead of from the start of
  the run. The first frame's one-time setup (reading the capture, enumerating
  interfaces, looking up the route, authorization) no longer shortens the gaps
  that follow, so `--timing original`, `--speed`, `--rate`, and `--bps` keep the
  captured or requested spacing instead of sending the first frames back to
  back. With `--repeat`, the first frame of each pass under `--timing original`
  and `--speed` is anchored the same way. Setup time counts against
  `--max-duration-ms`: a frame whose target, measured from the start of the run,
  would pass the limit is refused with `policy.replay_limit` before it is
  authorized or routed.
- Serial scans and traceroutes refuse a `collection` that captures more frames
  or bytes than `max_evidence_frames` or `max_evidence_bytes` retain with
  `cli.scan_limit` or `cli.traceroute_limit` before any capture or send, instead
  of failing after transmission with `internal.scan_evidence` or
  `internal.traceroute_evidence`. Traceroute likewise refuses a `collection`
  whose `max_responses` is below `probes_per_hop` up front, instead of failing
  at its executor with `cli.traceroute_executor`. Pipelined scans
  (`--max-in-flight` above one) publish the `scan.undecoded_limit` warning once
  when undecodable frames pass `max_undecoded`, as serial scans do, instead of
  silently omitting the rest.
- A repeated interrupt no longer leaves staged output behind. `export`, `merge`,
  `rewrite`, and `follow --write` remove their `.tmpXXXXXX` staging file before
  the second interrupt exits 130; previously the forced exit skipped cleanup and
  a temp file, possibly gigabytes, stayed beside the destination.
- `read --normalize`, `rewrite`, and `merge` refuse a capture that declares a
  frame check sequence, because the PCAPNG output cannot record it and readers
  would treat the FCS bytes as payload. `read --normalize` and `rewrite` fail
  with `packet.capture_transform_metadata` and `merge` with
  `packet.capture_merge_metadata` (exit 3), all with the same reason,
  `declared frame check sequence`, for both formats. A capture declares one only
  through a PCAPNG `if_fcslen` option whose value is not a single zero byte (a
  malformed length counts as declared), or a classic PCAP network word with the
  FCS-length-present flag (bit 26) and a nonzero FCS length (bits 28-31). An
  `if_fcslen` of 0, and network-word bits above the link type that declare no
  FCS, are accepted. `read --normalize` previously exited 0 and wrote frames
  that still ended in the FCS bytes under an interface with no FCS declaration.
  `capture_file::Reader::refuse_declared_fcs` reports the declaration.
- A reply that a retention limit refused is no longer reported as its request's
  absence. Before, a reply matched to a request but refused by `max_responses`
  or the capture frame or byte limit left that request in `unanswered`, and
  scan, traceroute, and DNS published a timeout for it, with only a warning
  diagnostic. Unrelated and undecodable frames also filled the shared frame
  limit and could crowd out the genuine reply; they now leave one frame slot
  free for each request still awaiting a reply. Under the default `fail`
  overflow policy, a refused matched reply ends the exchange with `io.capture`
  naming the request and the limit, and a workflow exchange (scan, traceroute,
  DNS) fails the same way only when the unsolicited-frame, frame, or byte limit
  refused a frame that the workflow accepts for exactly one request while that
  request has no reply. Unrelated traffic, checksum-failed frames, and frames
  the workflow accepts for several requests leave the request unanswered when a
  limit refuses them, so a silent port on a busy interface reports a timeout
  instead of aborting the scan. Under a lossy overflow policy, `exchange` keeps
  the warning diagnostics and no longer lists the request as unanswered; scan,
  traceroute, and DNS have no response to report for it and still publish a
  timeout next to the warning. When held-back frame slots lower the ceiling for
  unrelated frames, the `exchange.capture_frame_limit` warning names the
  effective limit and the number of slots held for pending replies next to the
  configured limit.
- `dns --help` no longer ends its examples with a stray `--help`, which made
  the last example print help instead of querying. `scan --help` no longer says
  that executors lacking window support reject `--max-prepared-bytes`; no
  executor rejects it. It also states that `probe_sent` NDJSON receipts and
  `error.scan` pending transmissions appear only with a window
  (`--max-in-flight`) above one, and that a window of one publishes final probe
  events only.
- Dissection now says why a TLS hello or a DNS-over-TCP message published no
  fields. A complete ClientHello or ServerHello message that breaks a wire rule
  or limit (for example more than 64 extensions) carries an Info
  `tls.handshake_unparsed` diagnostic with the parse error, instead of silently
  publishing no `handshake_type`, `sni`, `ja3`, or `ja4`. A complete
  length-prefixed DNS message on TCP that exceeds a decode limit (for example
  more than 512 records) stays a `raw` layer but carries an Info
  `dns.message_unparsed` diagnostic with the limit error; over UDP the same
  message already publishes `decode.malformed_layer`.
- `read --field` and `--filter` evaluate the physical frame whether or not a
  stream index is requested. Previously, selecting or filtering on `tcp.stream`
  or `udp.stream` let the frame that completes a fragmented datagram match on,
  and report, the reassembled TCP/UDP header. Those fields are now null and such
  filters no longer select that frame, matching `read` without a stream field.
- `export --max-selected-frames 0` and a value above 1,000,000 are rejected as
  usage errors (exit 2, kind `cli`, `cli.analysis_limit`, naming
  `max_selected_frames`) instead of reporting a `policy.export_limit` error
  (exit 6) that claimed the selection exceeded `max_selected_frames=1000000`.
  `analysis::export::Selection::validate` and `analysis::export::plan` return
  `analysis::export::Error::Analysis(analysis::Error::InvalidLimit)` for these
  values; `analysis::export::Error::Limit` remains for a selection that really
  overruns its limit and for more than 4096 selectors.
- `dns-read` and the library DNS collector charge emitted messages and
  transaction tracking against one cumulative `max_retained_bytes` ceiling
  (`--max-application-retained-bytes`). The two were counted separately, so a
  capture could be charged up to twice the limit before the run stopped with
  `application analysis exceeds max_retained_bytes`. A capture whose combined
  charge exceeds the limit is now refused, so raise the limit if a run that used
  to pass now stops.
- Replay refuses a `--rate` whose frame period rounds to zero nanoseconds or
  overflows a duration (for example `--rate 5000000000` or `--rate 1e-300`) with
  `cli.replay_limit` before it transmits anything. Previously it sent the first
  frame and then aborted with `packet.replay_timing` at the second.

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
