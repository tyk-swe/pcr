# Changelog

All notable changes to PacketcraftR are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

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
  renamed `PeerDirection`, and `budget::Interrupted` plus the capture-group
  `Failure`/`Error` structs are `#[non_exhaustive]`.
- CLI `output::contract::Command::require_format` is generic and returns a
  narrowed proof enum (`AggregateFormat`, `ToolFormat`, `BuildFormat`,
  `CaptureFormat`, `DissectFormat`, `SendFormat`, `ExchangeFormat`,
  `ReadFormat`, `FollowFormat`) instead of `()`, so a command that cannot
  emit a format fails at dispatch rather than re-checking `Format` inside
  rendering.
- `document::Error::Parse.source` is an `error::Source` (was `String`),
  retaining the packet parser's typed error in the chain.
- `analysis::reassembly::tcp::Event::Retransmission` gains a `ranges` field
  listing the arriving segment's actual retransmitted sequence spans, which
  need not form a contiguous prefix.
- Shared probe APIs have canonical paths: `probe::{Executor, Execution, Error,
  ProbeEndpoint, ProbeStatus, Transport}`. The old `scan`, `traceroute`, `dns`,
  and `fuzz` aliases are removed without compatibility aliases. See
  `docs/migration-unreleased.md`.
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
  such as `cli.capture_filter` and CLI output are unchanged: the CLI's
  `output::envelope::Error.kind` is the new CLI-owned `envelope::ErrorKind`,
  which still publishes a usage failure as `"cli"` with exit code 2. See
  `docs/migration-unreleased.md`.
- Capture-file formats move from `packetcraftr_core::analysis::pcap` to the
  top-level `packetcraftr_core::capture_file`, with the same items. It also
  owns link-type knowledge: `frame::LinkType` keeps its path and constants and
  gains `BUILTIN_ROOTS`, `root_protocol`, `for_root_protocol`, and `is_raw_ip`.
  `protocol::capture::{CaptureRoot, BUILTIN_CAPTURE_ROOTS}` are removed in
  favor of `LinkType::BUILTIN_ROOTS`. See `docs/migration-unreleased.md`.
- Live-policy vocabulary leaves core (ADR 0002).
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
- Core modules form acyclic layers (model, protocols, engines, workflows;
  see the crate docs). `packet::semantics` moves to `protocol::semantics`
  with the same items. `protocol::raw` is removed: the `Raw`, `Padding`, and
  `Malformed` layers and their codecs belong to `layer`, and `parse_hex` moves
  to `layer::parse_hex`. See `docs/migration-unreleased.md`.
- CLI `output::contract::Command` is declared once with the command line it
  names: `Command::ALL` lists commands in `--help` order instead of a separate
  canonical order. The per-command format enums implement the new
  `output::contract::FormatSubset` trait, which carries `FORMATS` in place of
  the inherent constant, and `Command::require_format` takes
  `F: FormatSubset`. Serialized command names and formats are unchanged. See
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
  `Tls::try_from`, `Hello::to_wire`, `HelloExtension::{server_name, alpn}`,
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
  `dhcp::Limits`, and `dns::DecodeLimits` gain `validate()`, and
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
- `packetcraftr_cli::output` types own every published field (ADR 0003).
  Output types embed only the versioned `packetcraftr.packet` document and its
  field values; every other field is a CLI-owned mirror with the same JSON
  shape (`envelope::Stats`, `diagnostic::Diagnostic`, `envelope::ErrorContext`,
  `network::InterfaceId`, `analysis::Scope`, `fuzz::Outcome`, and others).
  Conversions are `From`/`TryFrom` only: the `from_*`, `try_from_*`, and
  `complete_from_*` constructors, `Report::new`, `Detail::new`,
  `Worker::progress`/`native`, and `provenance::from_source_set` are removed,
  and a conversion that also yields diagnostics or stats returns
  `envelope::Published<T>`. `http::Issue` and `dns_read::Issue` are structs
  instead of newtypes, and `tls::SelectionCounts` is removed. output/v6 JSON is
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
  `reflect_*` helpers are documented API for custom layers. The
  `display_via_as_str!` macro is no longer exported, and the
  `frame::GlobalInterfaceId` alias is removed in favor of `u32`.
  `transform::Error::{Invalid, Unsupported, Limit}` carry the typed
  `transform::{InvalidInput, Unsupported, Limit}` reasons, and
  `fuzz::Error::{InvalidLimit, InvalidTarget, InvalidBasePacket}` carry
  `fuzz::{Constraint, TargetFault, BaseFault}`; messages and codes are
  unchanged. See `docs/migration-unreleased.md`.
- Route planning moved from `packetcraftr_netio::route` to
  `packetcraftr::route` (ADR 0001): `plan`, `Plan`, `Options`, `Error`,
  `materialize`, and `Materialized`. netio keeps the route contract
  (`Provider`, `Decision`, `Scope`, `SelectionReason`, `SystemProvider`,
  `SystemError`). `Client::plan` returns `packetcraftr::route::Plan`.
  Transmission frames take a borrowed `transmit::Route` view (decision, link
  mode, lookup destination) instead of `&route::Materialized`, and
  `Frame::route()` returns it; build one with `Materialized::transmit_route`.
  `Materialized::for_prepared_layer2_frame` is removed. See
  `docs/migration-unreleased.md`.
- Neighbor resolution moved from `packetcraftr_netio::neighbor` to
  `packetcraftr::neighbor` (ADR 0001): `Error`, `Request`, `Resolution`, and
  `Options`. The `Client` now resolves neighbors itself over its transmit and
  capture providers, so `Client<R, N, I>` is `Client<R, I>`, `Client::new`
  takes no resolver, and `probe::ExchangeExecutor<'a, R, N, I>` is
  `ExchangeExecutor<'a, R, I>`. `neighbor::Resolver`, `ActiveResolver`, and
  `SystemResolver` are removed; set the bounds with
  `Client::with_neighbor_options`, which validates them. `Client::send` and the
  send-set methods now require `I: capture::Provider` as well, since a Layer 2
  send may resolve a neighbor. `route::materialize` is no longer public: the
  client materializes admitted plans. `link::MAX_VLAN_TAGS` moved to
  `packetcraftr::route::MAX_VLAN_TAGS`. Error messages and codes are unchanged.
  See `docs/migration-unreleased.md`.

### Added

- `packetcraftr::fuzz::Totals` checks a live or offline campaign's case counts
  and cases for coherence (`TryFrom<&Report>`, `TryFrom<&Stats>`, and their
  offline counterparts), failing with `fuzz::IncoherentReport`. The CLI's
  `internal.fuzz_event_coherence` check now uses it.

- The versioned input documents and their rules are library API, so other
  consumers read them exactly as the CLI does. Core `transform::Rules` reads
  `packetcraftr.rewrite/v1` and `/v2` documents (`Rules::parse`, failing with
  `transform::RulesError`), builds one rule from direct edits
  (`Rules::single`), reports the VLAN growth a map needs
  (`maximum_growth`), and applies the rules in order to a frame with a
  caller-compiled filter (`try_map_filters`, `apply`).
  `packetcraftr::scan::profile::parse_document` reads
  `packetcraftr.udp-profiles/v1` into per-port profiles
  (`scan::profile::DocumentError`). Core `document::parse_recipe` reads recipe
  text as a JSON or YAML packet document or a layer expression
  (`document::Format::{from_path, sniff}`, `document::RecipeError`), and
  `document::PayloadTarget` fills an empty bytes field from outside the recipe
  (`document::PayloadError`). `transform::fragment_link_type` frames an
  Ethernet, IPv4, or IPv6 recipe for `transform::fragment`. Document formats,
  CLI flags, and error codes are unchanged.
- `protocol::network::ndp` types Neighbor Solicitation and Neighbor
  Advertisement bodies with their source and target link-layer address options
  (`NeighborSolicitation`, `NeighborAdvertisement`, `MessageOption`,
  `solicited_node_multicast`). Decoding keeps reserved bits and unknown
  options, and a decoded body re-encodes byte for byte. The models are not
  registered layers, so dissection output is unchanged.
- `packet::MacAddress::for_ip_multicast` maps an IPv4 or IPv6 multicast group
  to its Ethernet group address.

- `protocol::headers` is a public, bounded walker over raw link, VLAN, and IP
  header bytes (`LinkHeader`, `EthernetHeader`, `IpHeader`, `Ipv4Header`,
  `Ipv6Header` with its extension chain, and option iterators). Code that
  edits or inspects bytes a codec round trip would not reproduce uses it
  instead of parsing headers by hand (ADR 0004); `transform::rewrite` and
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
  ports, and `dns.id`. `--checksum-mode repair|preserve` selects recomputed or
  retained covering checksums, and `--dry-run` emits a bounded requested/derived
  change report without publishing the destination.
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
- Registered field projection from `read`/`dissect`, including CSV/TSV, missing
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
  Valid DNS, VXLAN, and Geneve payloads on their registered ports materialize
  as exact typed layers, including inner frames, while payloads that do not
  decode as their registered protocol still require strict construction.
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
  effective constraint set under `policy.destination_not_allowed`.
- `send` accepts the same `--axis` template expansion as `build`/`exchange`
  plus `--repeat N` (replays the whole expansion in order) and `--rate N`
  (paces transmission starts to `N` packets per second); the checked
  expansion-times-repetition total shares one packet/byte budget, pacing
  schedules past the operation ceiling fail before transmission, and text,
  hex, and raw formats emit each confirmed frame progressively so partial
  progress survives later failures.
- `dns` accepts multiple NAME positionals and repeatable `--reverse ADDRESS`,
  deriving PTR questions under `in-addr.arpa`/`ip6.arpa` via the new
  `dns::reverse_name`; `dns::run_batch`/`run_batch_with_events` execute a
  bounded batch (up to `dns::MAX_QUESTIONS`) under one shared deadline and
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

### Changed

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
- `read` without `--field` rejects JSON, CSV, and TSV output with the shared
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
  cancellation and `--max-duration`, surface a clock failure, account the
  delay, then add it to elapsed statistics. A wait that overruns
  `--max-duration` while the clock also fails now reports the duration limit
  instead of the clock failure, and a batch question stopped that way is
  unattempted rather than failed. `dns` elapsed statistics include a retry
  delay only once that delay has been accounted.
- Serial `scan` and `traceroute` pace and execute probe batches through one
  shared execution context with a fixed step order: the execution permit is
  checked before evidence validation, a batch's statistics are merged before
  an interruption observed after that batch surfaces, and time is accounted
  after validation. When a batch execution fails while the operation is
  cancelled or out of time, the run now reports the cancellation or
  `--max-duration` limit instead of the executor failure.
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

### Removed

- Rust: the equivalent public paths `packetcraftr_core::{Packet, PacketError}`
  (use `packet::`), `build::{Context, Mode, DEFAULT_MAX_LAYERS,
  DEFAULT_MAX_PACKET_SIZE}` (use `codec::` and `layout::`),
  `protocol::application::{Dns, Tls}` (use `dns::Dns` and `tls::Tls`),
  the `protocol::application::tls::{codec, fingerprint, model, names, parse}`
  submodule paths (use the flat `tls::` re-exports),
  `analysis::pcap::DEFAULT_SIZE_LIMIT` (use
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
  `packetcraftr::replay::{Authorizer, Operation, ReplayFrame, WireBudget}`
  re-exports; import them from `packetcraftr::policy`.
- **Breaking:** the `packetcraftr_netio::link::{MacAddress, VlanKind, VlanTag}`
  re-exports; import them from `packetcraftr_core::packet::link`.
- The `#[doc(hidden)]` `packetcraftr_core::layer::{malformed_layout,
  padding_layout}` exports. `raw_layout` remains available to codecs outside
  core that emit `Raw` layers.
- **Breaking:** `packetcraftr::dns::ResponseMetadata::response_code_name` and
  `ValidatedResponse::response_code_name`; use the canonical
  `packetcraftr::dns::response_code_name` function.

### Fixed

- `neighbor::Options::validate` keeps the capture-limit refusal as the
  `source` of `neighbor::Error::InvalidOptions` (a new field) instead of
  flattening it into the message, so it is reported once, as a cause. The
  message now reads "capture bounds are invalid"; the code stays
  `cli.neighbor_limit`.
- DHCP limits above 65535 message bytes, 4096 options, or nesting depth 8 are
  refused with `dhcp::Error::InvalidLimit` (`policy.dhcp_limit`) instead of
  being silently lowered to those ceilings, which are now public as
  `dhcp::{MAX_MESSAGE_BYTES, MAX_OPTIONS, MAX_NESTING}`.
- DNS decode limits above 65535 message or TXT bytes, 4096 records or TXT
  strings, or 128 name pointers are refused with `dns::Error::InvalidLimit`
  (`policy.dns_limit`) instead of being silently tightened, and the ceilings
  are public as `dns::{MAX_MESSAGE_BYTES, MAX_RECORDS, MAX_NAME_POINTERS}`.
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
- Capture-reader help now states that `--max-interfaces` bounds descriptions per
  input PCAPNG section, with a separate 65,536-description capture-wide ceiling.
  Normalization's selected-output interface ceiling is documented separately;
  input filtering and the existing limits keep their behavior.
- Release evidence requires versioned, complete named decoder/native results,
  pinned decoder identity, input/tool digests, exact corpus frame counts,
  matching TLS JA3 evidence, and successful native scenario/launcher exits.
  Missing parent namespace IDs and contradictory or duplicate results are
  rejected. Producers and release validation share the evidence contract.
- IPv6 destination classification includes the RFC 9637 `3fff::/20`
  documentation prefix under the same policy as `2001:db8::/32`, without
  accepting adjacent addresses or relaxing other destination checks.
- TLS limit documentation distinguishes logical handshake/alert buffering from
  retained hello summaries, allocation capacity, and total process memory.
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
