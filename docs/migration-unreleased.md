# Migrating from 0.5.0-beta.3

This guide describes the net upgrade from the released beta.3 to current `main`.
It does not preserve superseded intermediate APIs. See the [changelog](../CHANGELOG.md)
for additions and the [path tables](#renamed-and-removed-paths) for mechanical
Rust replacements. Callers already tracking `main` should also read
[the provider cleanup](#callers-tracking-main).

## Contract versions

| Contract | beta.3 | Current main |
| --- | --- | --- |
| Packet JSON/YAML | `packetcraftr.packet/v1` | `packetcraftr.packet/v2` |
| Command JSON/NDJSON | `packetcraftr.output/v2` | `packetcraftr.output/v14` |

Older packet documents are rejected. Explicitly update output consumers; keep
schemas, examples, and release assets from one revision. Output v6–v13 schemas
remain frozen for historical evidence; never relabel it. The
[consumer policy](consumer-compatibility.md) owns meanings and completion rules.

### OS identification

Output/v14 adds `identify-os` and its OS evidence/terminal records. Adopt
`output::contract::SCHEMA_V14`; v13 remains frozen. `packetcraftr::os::Request`
requires a numeric target, distinct open/closed TCP ports, and a validated
`os_fingerprints::Corpus`. `Client::identify_os` requires packet and target
providers; `os::Collector` rebuilds the aggregate. See
[OS identification](os-identification.md) and the
[v14 contract](consumer-compatibility.md#output-family-v14).

### TLS and identification corpus additions

Output/v13 adds SMTP/FTP fields, `tls_failed`, TLS evidence, `usage.tls`, and
source-backed candidate metadata. Set `identify::Request::tls: Option<TlsSettings>`
for explicit TCP wrapping; `--server-name` declares SNI without lookup.
`Usage`, `Evidence`, and `Outcome` gain TLS members; service-probe `Request`,
`Protocol`, and `Field` gain SMTP/FTP variants. Update literals/exhaustive matches.
`MatchRule` gains optional `hostname_field`, `device_type`, `cpe`; `Candidate`
gains supported values with sources. Documents may omit them. Corpus 1.1.0 adds
two greeting probes; supply your own bounded corpus if probe count matters.

## Service identification

`identify` / `Client::identify` is explicit, never an automatic scan stage.
Claims remain unauthenticated; candidates carry corpus and evidence provenance.
Unknown/ambiguous results assert no exact versions. See
[controls and limits](service-identification.md) and the
[v13 contract](consumer-compatibility.md#output-family-v13).

## Adaptive scheduling

Fixed scheduling remains default. `scan::Request::adaptive` is
`Option<scan::Adaptive>`; use `None` for fixed mode. Tuning flags require
`--adaptive`. Reports/aggregates gain `scheduling`, and `scan::discovery::Scan`
gains `Incomplete` when a host deadline prevents intended work. Never-sent
attempts imply no network evidence. Netio `tcp::ConnectBudget` leases survive
until worker/socket cleanup. See [scheduling](consumer-compatibility.md#output-family-v10).

## Forwarding verification

`verify-forwarding` is new. Missing values do not satisfy ordinary preservation;
use explicit presence/absence checks and read the terminal verdict.
[Verification semantics](verification-contract.md) owns the rules.
`Observation` is opaque: construct it through collectors, read getters, and use
the same compiled rules. `verify` returns `forwarding::Error`;
`verify_with_limits` accepts separate detail/scratch budgets and a shared deadline.
Detail omission never changes a verdict.

## Offline HTTP/2 analysis

`http2` / the core collector analyzes cleartext prior knowledge and h2c; `http`
remains HTTP/1-only. Handle `Command::Http2`; use `--http2-port`, not a stateless
codec/decode-as binding. TCP `stream` and `http2_stream_id` are distinct.
Read final connections/later issues, not just complete messages. TLS decryption
and HTTP/3 remain unsupported. See [capture recipes](tasks.md#2-investigate-a-capture-without-losing-evidence)
and [limits](analysis-resources.md#http2-limits).

## Error codes and messages

Errors retain typed sources. Read `Classified::causes()`, `error::source_chain`,
or `error::render` rather than searching `to_string()` for nested error text.
The CLI publishes that chain in `causes`; `message` describes only the current
failure. `error::Source` is the shared type-erased handle; replace string sources
or `SystemFault` with `Source::new(error)`. `document::Error::Parse.source` uses it.

`Kind::Cli` becomes `Kind::Usage` (serde/display `"usage"`, exit 2); existing
`cli.*` classification codes keep their spelling. `filter::Error` loses
`PartialEq`/`Eq`, and `policy::Error` loses `Clone`/`PartialEq`/`Eq`; use
`matches!` for variants. Scripts matching these cases need updating:

| Failure | Current classification / action |
| --- | --- |
| Analysis processing deadline | `policy.duration_limit`, not `policy.analysis_resource_limit` |
| Analysis dissection or live build failure | The original decode/build classification, not generic `packet.decode` / `packet.build` |
| Time filter on an untimestamped frame | `packet.timestamp_unavailable`, exit 3; remove time fields or provide timestamped records |
| Malformed/unresolved `fuzz --field` | `cli.selector`, exit 2 |
| Invalid `build --link-type` | Argument-parsing `cli.error`, exit 2, before output-format checks |
| Invalid normalization output | `cli.capture_normalize_format`; PCAP and PCAPNG are supported |
| Zero/above-ceiling HTTP/DNS application limits or export selection limit | `cli.analysis_limit`, exit 2, instead of a policy limit reached during processing |
| Invalid HTTP/DNS port or HTTP body limit | Argument-parsing `cli.error`, exit 2 |
| Text/hex/raw/JSON stdout write | `io.stdout`, exit 5, with the underlying I/O error in `causes` |
| UDP/ICMP requested with TCP-connect scan | `cli.scan_method`, exit 2 |

`application::Limits::validate` and HTTP/DNS collector constructors return
`application::Error::Analysis(analysis::Error::InvalidLimit { .. })` for invalid
configuration. Export planning/selection use the analogous `export::Error::Analysis`.
`policy.application_limit` / `policy.export_limit` still denote valid budgets
exhausted by input.

Byte/MAC filters reject ambiguous unquoted words such as `deadbeef`, `c0:0`,
or `aa:bb-cc` with `cli.filter` (`UnquotedByteWord`); use separated two-digit
bytes or explicit quoted text. Previous implicit ASCII comparisons must be made
explicit. Missing timestamp errors and source-only error messages are consistent
across command paths; do not depend on old message prefixes or OS-error duplication.

Workflow route errors `InvalidSourceRouting` / `InvalidSegmentRouting` retain
`source: Option<Box<dyn Error + Send + Sync>>`; use `None` for local refusals.
Native snapshot errors likewise retain their original typed route source.

## Named packet fields and DNS messages

Packet/v2 adds named object values (`{name=value}`) and nested paths such as
`questions[0].name` under finite item, payload, nesting, and node budgets.
Replace `Dns::{qnames,qtypes,qclasses}` with `questions: Vec<Question>`;
singular reflected views remain read-only. Counts are `WireValue<u16>` and
`Dns::edit` resets them to `Auto`. Untouched DNS preserves compression/wire bytes;
structured edits use uncompressed names and keep unknown RDATA opaque.

DNS `query_type` serializes as numeric `u16`, not an alias (`"aaaa"` → `28`).
Use `QueryType::new(code)`, `.code()`, uppercase constants, and an unknown-code
fallback; `Display` replaces `.as_str()`. CLI `--type` accepts names, decimal,
or `TYPE<n>`. Parsing returns `dns::wire::Error` with its original source.

## Packet templates and UDP scan payloads

`Template::axis` accumulates a Cartesian product; the last axis varies fastest.
Duplicate fields/aliases fail. Check `expansion_len()?` and bound `expand(maximum)`.
No axes means one packet; an empty axis means none (rejected by CLI). Packet sets
use text/hex/NDJSON/capture output, not JSON/raw.
Selectors accept `<protocol>[#occurrence].<field>` or a zero-based layer index via
`Target::select` / `payload::Target::resolve`. Add `expression::Limits::max_generated_bytes`
to literals for `repeat`, `zeros`, and `cyclic`. Re-record Boundary fuzz seeds/indexes:
values now use the target's accepted width. Identify new `fuzz.roundtrip_*`
diagnostics with `fuzz::is_roundtrip_diagnostic`.

Raw requests/probes gain `udp_payload: bytes::Bytes`; use empty bytes for old behavior.
Probes are `Clone`, not `Copy`. Above-`MAX_UDP_PAYLOAD_BYTES` or nonempty TCP/ICMP
payloads fail before work.

## Typed TCP options

`Tcp::options` is an ordered `Vec<TcpOption>`, not `Bytes`. EOL/NOP/MSS/window
scale/SACK/timestamps expose typed objects; unknown lengths/kinds and unparseable
tails remain exact `Raw`/`Trailing` values. Recipes accept
`options=[{kind=2,mss=1460}]` or verbatim `options=hex("0204 05b4")`.
Nested paths such as `tcp.options[0].mss` work throughout reflection. Replace
`options.as_ref()` with variant iteration.

## IPv6 reserved bits

IPv6 Fragment reserved byte/Res bits and SRH flags now decode faithfully with
`decode.ipv6_fragment_reserved` / `decode.srh_flags`, rather than making the
layer malformed. Reassembly accepts such fragments. Strict builds reject nonzero
bits; permissive builds retain them with corresponding `build.*` diagnostics.
Live policy and matching still reject nonzero SRH flags.

`Fragment` gains `reserved: u8` and `reserved_bits: u8` (`0..=3`); add zero values
or `..Fragment::default()` to literals and `..` to patterns. Above-3 Res bits fail
in either build mode. Reflection/layout gains these fields after `next_header`;
update exact field sets/positions and use `ipv6_fragment.reserved[_bits]` for
projection. The recursive packet/v2 and output/v14 shapes do not change.

## DNS transport selection

Replace `Request::tcp_fallback` with `transport: TransportMode`: `false` → `Udp`,
`true` → `UdpThenTcp` (default), or `Tcp` for direct TCP. Serialized values are
`udp`, `udp_then_tcp`, `tcp`; obsolete/unknown request fields are rejected.
`DEFAULT_TCP_FALLBACK` is removed; `source_port` is unused for TCP-only requests.
Direct TCP uses the client's provider without raw UDP cost; `dns --tcp` works
without packet-I/O features. Packet route overrides and scoped link-local TCP
remain unsupported. Inspect actual attempt transport: direct TCP reports
`fallback_attempted=false`, and fallback retains its truncated UDP phase.

## Explicit DNS TCP providers

Netio owns `tcp::{Provider, Stream}`; workflow `dns::tcp` owns framing/evidence.
The client uses its explicit `tcp` provider; the CLI uses `tcp::SystemProvider`.
Use a refusing provider to prohibit sockets. Kernel TCP rejects interface,
preferred-source, and link-mode overrides and rechecks endpoint/query bytes.

Replace `dns::tcp::exchange(request)` with `query(request, Arc::clone(&provider))`.
Provider/stream are `'static`; admitted work owns its `Arc` until cleanup. Set
`Request::cancellation: Some(&signal)` or `None`; client deadlines share its signal.
`Error::Cancelled { phase, transferred, .. }` / `Category::Cancelled` classify as
`io.cancelled`; `Phase::{Connect, Write, ReadPrefix, ReadMessage}` and transferred
bytes retain partial work. Write/read waits recheck cancellation every 25 ms.

## Opt-in EDNS requests

Add `Request::edns: Option<EdnsRequest>` (`None` preserves old queries) and pass
it as the fifth `dns::wire::encode_query` argument. `udp_payload_size` is
`512..=65535`; `dnssec_ok` requests data without validating signatures. Version 0,
root owner, and no options are fixed. The eleven extra bytes count in authorization
and TCP fallback repeats the same message. CLI `--dnssec-ok` requires
`--edns-udp-payload-size`; advertised size does not replace `--max-message-bytes`.
Existing output EDNS fields still describe responses; no output-family change.

## DNS question batches and reverse names

`dns` accepts several names and repeatable `--reverse ADDRESS`; `reverse_name`
builds PTR names. Batches are bounded by `dns::batch::MAX_QUESTIONS` and share the
minimum duration deadline. `--transaction-id` is invalid for multi-question runs.
Single-question envelopes remain unchanged; batch `questions` and stream terminals
report `completed`, `failed`, or `unattempted` in input order.

## Offline DNS records

Import `Name`, `Record`, `RecordValue`, `Edns`, `EdnsOption` from core
`protocol::application::dns`, not workflow DNS. `Name::from_labels` returns
`dns::Error` with offsets and distinct self-pointer/loop failures; live structural
failures wrap it in `dns::wire::Error::Decode`.
`Dns::try_from(bytes)` replaces `from_wire`; use `from_wire_with_limits` for explicit
bounds. Malformed/truncated records and trailing bytes fail, with original payload
retained by dissection. `wire()` keeps exact compression/unknown bytes.

Defaults: 65,535 message bytes, 512 records, 32 pointers/name, 256 TXT strings,
16,384 TXT bytes. Hard ceilings: 65,535 message/TXT bytes, 4,096 records/TXT strings,
128 pointers, 64 questions. Above-ceiling limits fail (`policy.dns_limit`); zero
allows none. See rustdoc for `dns::Limits`.
Reflection sections contain named `{owner, type, class, ttl, value}` objects.
`value.kind` selects address/name/MX/SOA/SRV/CAA/TXT/OPT members; unknown records
retain type and exact RDATA. Ordinary records are interpreted only for IN;
other classes keep opaque bytes. OPT stays in its original section and unknown
EDNS versions remain inspectable; live validation is unchanged.

## TLS hello construction

`Tls::try_from(Hello)` builds ClientHello/ServerHello fixtures. Recipes expose
versions, random/session ID, suites, compression, and ordered `{type, data}`
extensions; use `Extension::{server_name, alpn}` or shorthand recipe objects.
Bodies stay authoritative; edits rederive lengths/fingerprints and nested paths
work in templates/fuzzing. Replace `Extension::len` with `data.len()` and add
`data` to literals. ServerHello retains its echoed session ID.

## Live capture

Repeated interfaces share one budget. `frame.interface_id` is a zero-based
capture-selection ID, not OS index; completion sources map it to the native
interface. Cross-interface timestamps do not promise ordering.
Completion uses `output::capture::Summary`; errors can retain `error.capture`.
JSON requires `--write`, rotation uses PCAPNG, and settings distinguish requested,
applied, effective (unknown stays null). Unsupported settings fail.
Replace `Event::try_from_frame`/tuple conversion with `output::read::Frame::try_from`
on the same tuple; `frame` remains the event name. Text/NDJSON dissection and
projection are opt-in.

## Scan requests, round-trip statistics, and UDP profiles

`Request::targets: target::Selection` replaces `target`; requests gain
`max_in_flight`, UDP payload/profiles, route and collection; limits gain
`max_targets`/`max_prepared_bytes`. One in flight uses serial exchanges; larger
windows share a capture group and add `probe_sent` events plus partial
`error.scan` pending wire. Serial output keeps final probe events only.

Reports/connect stats gain `rtt` (confirmed sends, in-window replies,
`lost = sent - received`, optional min/avg/max). Use `Rtt::default()` in literals;
no sample means absent durations.
`udp_profiles` maps ports to validated `Arc<profile::UdpProfile>`; probe
`application` results are separate from reachability. Compile independent v1
[documents](../schemas/packetcraftr.udp-profiles.v1.schema.json) with
`scan::profile::compile(core::document::udp_profiles::parse(&bytes)?)?`.
Unknown response-check fields are rejected.

## TCP connect scanning

`client.scan_connect(request, sink)` uses its TCP provider, emits
`connect::Event::Probe`, returns `connect::Report`, and collects
`connect::Aggregate { report, endpoints }`. These are socket results, not wire
capture. Policy uses `Operation::Socket` with numeric endpoints and `SocketLimits`.
Report literals gain `diagnostics`, including duplicate-declaration warnings.
Invalid target-plan durations are reported in milliseconds, saturating at `u64::MAX`.

`tcp::start_connect` returns `PendingConnect`. Dropping/cancelling stops unstarted
work; admitted calls retain leases through cleanup. `MAX_PENDING_CONNECTIONS`
is 16, shared with capture/route workers. Workflow `max_in_flight` remains finite
and UDP/ICMP are rejected; adaptive windows may queue under that process ceiling.

## Offline analysis options and results

Update `Options` literals for `plan`, `deadline`, `stream`, `time_bounds`,
`track_sources`; limits gain provenance and nested TCP/IP ceilings. Source-aware
collectors enable `tcp_events`/`track_sources`. Summary/stats gain interfaces;
stats adds optional duration/size/rates without inventing empty/zero-span values.
TCP retransmission events gain `ranges: Vec<Range<u32>>`.
HTTP/DNS RST-cut messages end once as `reset`, without reset-payload provenance.
DNS message/transaction retention shares a cumulative ceiling and may stop earlier.
Expert code changes: `tcp.connection_refused`, `tcp.fast_retransmission`,
`tcp.out_of_order`, and Info `tcp.not_closed_at_end`. Exact finding totals change;
only four gaps/direction are watched, and filtering/expiry can hide lifecycle evidence.

## Display filter language

`topics filters` owns syntax: escaped text/bytes, masks, ranges, text operators,
list selectors, last/relative occurrences, `len()`/`count()`, and frame facts.
Function `(` must directly follow the name. Text operations on number/address
lists compile but do not match; object lists reject them. `frame.reassembled`
is not a field. Decoded layer/protocol facts are unevaluable for incomplete
forwarding evidence; frame time/direction/truncation cannot be rule fields.
`--expect` uses the same literals/ranges. Ambiguous unquoted bytes must be replaced
with explicit byte or quoted-text literals (see [errors](#error-codes-and-messages)).

## Offline epoch bounds

Offline capture commands accept inclusive `--start-epoch`/`--stop-epoch`: nonnegative
Unix seconds with up to nine fractional digits. Reversed/unsupported precision
fails rather than rounding. Bounds exclude untimestamped frames, compose with
filters, preserve full timestamp precision, and do not assume order. Skipped input
still counts toward frame/byte limits.
Use `frame::TimeBounds::new(start, end)` in `Options`. Timestamped physical frames
advance IP reconstruction/indexing before selection; untimestamped bounded-out
frames skip stateful processing. `bytes_read` still counts all captured bytes.

## Capture files

Normalization/rewrite/merge refuse unrepresentable declared FCS metadata
(`packet.capture_transform_metadata` / `packet.capture_merge_metadata`, exit 3);
library transforms call `Reader::refuse_declared_fcs`. Malformed option structure
is checked before option values. [Capture fidelity](tasks.md#selecting-and-saving-evidence)
owns the constraints.
`read --normalize` supports PCAP with a nonempty, timestamp-exact single-interface
selection without direction metadata. Selection keeps source numbering/budgets.
`merge` rejects chronological regressions unless bounded `--max-reorder-frames`
or explicit `--order append` is chosen (mutually exclusive). Add `order` and
`max_reorder_frames` to `MergeLimits` or use defaults.

## Header rewriting, DHCP, and protocol discovery

`rewrite` applies bounded header/address/fixed-width edits with explicit checksum
policy and staged publication. Hand-built `transform::rules::Rule` gains `map: None`;
loaders/`Rules::single` already set it. DHCP supports bounded typed fixtures.
Protocol discovery can emit `children_reference`: resolve the JSON Pointer against
the containing top-level field description before traversing.

## Protocol coverage and bindings

STP, LLDP, EAPOL, VRRP, EtherIP, GTP-U, TFTP, syslog and corresponding
`BuiltinProtocol` variants are new. UDP 5353/5355 bind DNS; ephemeral TFTP DATA/ACK
needs explicit decode-as. Replace assumptions that these payloads are `raw`.
mDNS class bits remain exact; non-exhaustive NDP `MessageOption` gains typed
variants and `.value()` returns owned `Bytes`. MLD/IGMPv3 helpers are not registered
layers. GTP-U TEIDs/EtherIP tunnels do not separately scope otherwise identical tuples.

## Destination allowlists

Add `Policy::allowed_destinations: Vec<DestinationConstraint>` to literals.
Exact addresses/canonical CIDRs are bounded by `MAX_DESTINATION_CONSTRAINTS`.
A nonempty list must admit target, declared, visited-route, and final-wire
addresses; empty adds no constraint. It never replaces other opt-ins.
Denials: `policy.destination_not_allowed`; malformed/oversized lists: `cli.live_target`.
Every destination-bearing live command accepts repeated `--allow-destination`;
`fuzz` rejects it without `--live` instead of ignoring it.

## Target planning and scoped IPv6

Manifests/list mode share admission; listing sends no target/neighbor packets,
but explicitly authorized hostname resolution is reported. v7 fields persist in v14.
`Request::target_sources` is empty or one bounded nonempty label/declaration.
`Client::plan_targets` requires only `TargetProviders`.
Handle `Target::ScopedAddress`; use `Authorized::selected()` for scope and owned
`addresses()` otherwise. Identity includes resolved interface. Unsupported workflows
fail rather than stripping scope. Retained-byte reports are wire charges for
raw/trace, structure/error-string charges for connect, never RSS.

## Port planning and inference

Ports accept catalog names/presets and transport-qualified terms; exclusions
precede budgets. No default set; mixed TCP/UDP shares a budget, ICMP is portless.
Names are hints. `--method raw|tcp-connect|auto` defaults raw; `--connect` is an
alias, explicit methods never fall back, automatic choice records its reason.
Use inference, not attempt classification, with supporting/conflicting/unanswered/
failed sequences ([rules](scanner-evidence.md#port-inference), introduced v8).

Replace request transport/port fields with `endpoints: Vec<probe::ProbeEndpoint>`;
`planned_endpoints()` replaces `selected_ports()`. Use `select_endpoints` for
catalog selections. Endpoint literals gain hints/inference; `ProbeEvidence`
gains `reply`; aggregate/event gain unattributed evidence.
CLI `Report::publish` replaces plan-less raw/connect conversions; supply stage
and reverse-DNS data. List reports accept optional expanded ports.

## Host discovery

Discovery is opt-in (`before|only|skip`); silence remains uncertain. v9 hosts/stages
persist in v14 and share authorization/budgets.
Add `Request::discovery: discovery::Options`; default omits discovery and only
`Mode::Only` permits no endpoints. Probes/evidence gain `stage`, reports gain
`hosts`, aggregates keep discovery probes separately. Handle `InvalidDiscovery`/
`Neighbor`; `MethodProbe { method, probe }` replaces `MethodTransport` and
`method::select` takes `&Request`. See [host evidence](scanner-evidence.md#host-observations).

## Scan traceroute

Raw-only `scan --traceroute` runs before reverse DNS under remaining policy/time
budgets. Connect/list reject it before work. Select a responsive TCP/ICMP observation
or explicit fallback; reused hops are sourced claims. v11 fields persist in v14.
`traceroute::hosts` / `Client::trace_hosts` add multi-host plans; standalone shapes
stay unchanged. Handle `TargetSelection`, `InvalidObservation`, `Collection` sources.
Resolved targets/sequence numbering can be reused after reauthorization.
`with_remaining_budget`/`with_parent_deadline` only narrow allowances. CLI publication
requires optional trace data; trace work contributes to scan totals.

## Scan follow-ups

Use workflow-owned `scan::followup`: `Client::scan_with_followups` runs raw scan,
optional trace, then PTR lookups; `scan_connect_with_followups` supports connect
plus reverse DNS. One duration/policy allowance governs all stages. Events, report,
and collector keep stage evidence and aggregate totals/inferences/enrichment.
`Trace::validate`/`ReverseDns::validate` reject invalid stages before probes.
The CLI composes requests and renders results, not a separate pipeline.

## Send packet sets

`send` expands `--axis`, repeats with `--repeat`, and paces with `--rate` under
one budget. Results replace single `frame`/`route` with `frames` and
`passes_completed`; per-frame pass is one-based and expansion index is retained.
Invalid repeat/rate: `cli.send_limit`; maximum pacing wait: netio `deadline::MAX_WAIT`.
Use `client.send(send::Request, sink)`.

## Replay

Use `client.replay(Request::new(Source::stream(reader), routing, options), sink)`
and optional `.with_filter`. Replace `Options::interface` with `Routing::from`
on `route::Interface::Id`; add `repeat: 1`, `inter_pass_delay: Duration::ZERO`,
`allow_permissive_live`, and `max_gap: None` for prior behavior.
`Routing::new(rules, fallback)` bounds source/filter mappings. Conflicting or
unmapped interfaces fail (`Error::{ConflictingInterfaces, Unmapped}`); selection
failures retain `filter::Error`. Parse `SOURCE_ID=INTERFACE` / `EXPR=>INTERFACE`
with `Rule::parse_source` / `parse_filter`.

Repeat needs `Source::seekable(Read + Seek)`; CLI validates/snapshots full input
before live work, including compression. All passes share budgets.
`FrameEvidence::pass` is one-based; source index stays input-relative.
Replace `source_interface_id` with `frame.interface`. Reports gain
`passes_completed`/`interfaces_used`; per-frame routes remain exact.
`Timing::BitRate` publishes `bit_rate`; positive `max_gap` clamps original/scaled
inter-frame delays and is not separately reflected in published timing.
Sink errors are `BoundaryError`, retained as `Output { source_index, source }`;
interruption sources become cancellation/duration failures. Collector coherence
is checked. Replay admission is internal; remove public Replay/ReplayFrame/shape
and unsupported-operation matches (see path table).

## Resource and output hardening

Native capture/route/TCP shares one worker pool. Callback admission is separate
and can be shared through `with_runtime`. Timed-out/cancelled work retains permits
until cleanup. Output timeouts bound writes, not whole operations; invocation
limits prevail. TCP page slack/transient work and cumulative DNS evidence may
reject previously near-limit inputs. See [resources](analysis-resources.md).
Staged writers bind the selected directory and never overwrite. Linux/procfs uses
its handle; other platforms recheck identity, with a remaining pathname race and
best-effort cleanup after moves.

## Core API conventions

- Use module-owned errors with typed sources; match variants rather than messages.
- Registry APIs use `LinkType` and `impl Into<Discriminator>`, not peeled integers.
  Frame constructors take `frame::Lengths { captured, original }`; `Malformed::new`
  takes `Option<String>`; non-exhaustive `budget::Interrupted` needs a wildcard.
- `LayerCodec::decode` takes refcounted `Bytes`; slice to retain ranges.
  `LayerDecodeContext` gains `parent`/`hop_limit` and loses `allow_trailing_padding`.
  The registry owns padding policy; supply actual IP TTL/hop limit or `None`.
- Remove `Layer::as_any[_mut]`; use inherent `downcast_ref`, `downcast_mut`, `is`.
  Custom layers retain `clone_box`. Public `reflective_layer!` and reflection helpers
  build static schemas; `protocol:` must be constant, not arbitrary runtime code.
- Built-in semantics/matching identify concrete layer types, not spoofable schema
  names. Register custom layers under their own names. New `BuiltinProtocol` variants
  need exhaustive arms. Removed semantics field-name constants require typed downcasts;
  removed unreachable error variants require deleting their arms.
- DNS conversions return `dns::Error` (encoding wraps codec errors); TLS malformed
  outcomes carry `tls::Error`. Update old codec-error matches.
- Replace `DecodedPacket::original` with `decoded.frame.bytes()`; delete redundant
  literal/pattern members.

## Live-policy vocabulary out of core

`BuiltPacket` records build `mode` and exposes `contains_malformed()` /
`contains_network_trailer()`; workflow `policy::requires_live_opt_in(&built)` owns
live interpretation. The serialized opt-in field stays unchanged.
`Deadline` exposes `limit`, `cancellation`, `live_remaining`, `detach`;
remaining checks cancellation first. Replace `Cancelled::into_boundary_error`
with `BoundaryError::with_source(c.to_string(), c.classification(), Vec::new(), c)`.
Other moved names appear in the [path tables](#renamed-and-removed-paths).

## Limits and budgets

Validated `Limits` declare ceilings; running `Budget` charges work. Replace
`capture_file::Limits::advance` with `Budget::new(limits)?`, `.charge(len)?`
(or `.after` to check), `.frames()`, `.captured_bytes()`.

| Before | After |
| --- | --- |
| Flat TCP/IP fields in `analysis::Limits` | `tcp: reassembly::tcp::Limits`, `ip: reassembly::ip::Limits` |
| `decode::Options { max_layers, max_packet_size }` | `Options { limits: packet::Limits { .. } }` |
| `build::Options { mode, max_layers, max_packet_size }` | `Options { mode, limits: packet::Limits { .. } }` |
| `Interner::with_limits(count, bytes)` | `Interner::with_limits(scope::Limits { max_scopes, max_bytes })?` |
| Workflow `max_evidence_frames`, `max_evidence_bytes`, `max_undecoded` | `evidence: evidence::Limits { max_frames, max_bytes, max_undecoded }` |

TCP/IP reassembler and scope constructors return `Result`; invalid limits fail
(`cli.analysis_limit`). TCP concurrent-direction `tcp.max_flows` is independent
of cumulative `max_flows` (default twice it); adjust both deliberately.
Capture writers/transforms refuse zero frames/bytes before publication.
DHCP/DNS above-hard-ceiling limits fail, never clamp; pass `MAX_*` explicitly.
Policy `WireLimits`/`SocketLimits` replace budget-named ceilings; `CaptureBudget`
remains a running allowance. Evidence nesting preserves JSON and binary Serde shape.
`Runtime::new(capacity)` returns `Result`: above-8 fails (`cli.worker_capacity`),
zero refuses every publication, default selects the maximum. Public limit types
provide `validate()`; use defaults/struct update syntax when appropriate.

## Core error convention

Every core module owns one classified `Error`; messages do not repeat sources.
Typed reasons include `analysis::Constraint`, `semantics::Constraint`, and fuzz
`Constraint`/`TargetFault`/`BaseFault`. `codec::Error::Rejected { protocol, source }`
retains/downcasts model errors; construct with `codec::Error::rejected`.
Fuzz nesting/item failures now use `ValueNesting`/`ValueItems`, not only
`ValueTooLarge`; all classify as `policy.fuzz_resource_limit`.

## Provider contracts

Capabilities expose `Provider` (`Send + Sync`) and `SystemProvider`.
Transmit uses `send(Outbound::{Layer2, Layer3})`; unavailable layers fail typed
`Unsupported`. Route associated errors must implement `Classified`; remove
`classify_error`. `Infallible` already works; wrap `std::io::Error` in a local type.

Blocking calls take `&budget::Deadline`, not separate timeout/cancellation.
Check cancellation before expiry and never wait beyond remaining time. Use
`Deadline::new(timeout).with_cancellation(...)`; passive lookups may use workflow
`deadline::PASSIVE_LOOKUP_TIMEOUT`. Native deadline/cancellation failures retain
`io.deadline_exceeded`/`io.cancelled`.
Capture fakes inherit single-source defaults; `Captured::source` defaults zero.
Spent `next_captured_frame` deadlines only drain queued input. Validate capture
limits/settings and the 64 KiB filter bound before native work.

Errors wrap `Unsupported { capability, message, source }`: route uses
`capability.route`, other native capabilities `capability.unsupported`.
`interface::Provider` returns `interface::Error` with required original `Source`
for `Discovery`; `From<interface::Error>` converts to shared netio error.
Replace `SystemFault` / `Arc` source handles with core `Source::new(error)`.
Native diagnostics/status remain in `causes`, not repeated messages.

## Route planning and neighbor resolution

Netio retains route provider/native decision/scope/error contracts; workflow
`route` owns plans/materialization and active neighbors. `Options::interface`
accepts `Id`/`Name`/`Index`; client resolves selectors only after admission.
Free `route::plan` accepts resolved `Id` only. Unknown/enumeration failures stay typed.
Transmit constructors take `materialized.transmit_route()`, not `&Materialized`;
`frame.route()` exposes decision/mode/destination directly. Replace removed
`for_prepared_layer2_frame` with a decision and borrowed transmit view.
Preferred-source family checking precedes backend calls.

Remove `Resolver`/`ActiveResolver`/`SystemResolver` and free `materialize`.
The client resolves over its own transmit/capture providers after authorization.
`with_neighbor_options(options)?` validates and starts a shared fresh client cache;
`neighbor::Request` no longer stores a deadline. Even send requires capture for
possible Layer 2 resolution. Move `MAX_VLAN_TAGS` (8) to workflow neighbor;
only resolving plans apply it. Unreadable VLAN fields fail before route lookup;
explicit/broadcast/multicast MAC paths do not need neighbor replay.

## Client model

Replace free runners, executor seams, and authorizers with
`Client<P, K = SystemClock>::new(registry, policy, providers)`.
`ProviderSet` fields are `route`, `interface`, `capture`, `transmit`, `tcp`,
`resolver`, `udp`; unused types default to `()`. Use `SystemProviders` or partial
`ProviderSet::{capture, packet, tcp}` constructors and `.with_udp`.
Bind custom bundles by `CaptureProviders`, `PacketProviders`, `TargetProviders`,
`TcpProviders`, `UdpProviders`, not a broad `Providers` marker.
Policy admission is `Policy::authorize` / `resolve_target` outside a client.

Every method takes a request and sink and returns a terminal `Report`;
`Collector` rebuilds `Aggregate`:

```rust
let collector = scan::Collector::default();
let report = client.scan(request, collector.clone())?;
let aggregate = collector.finish(report)?;
```

`Sink<E>` has `Ack` and returns `Result<Ack, BoundaryError>`; `FnMut(E)` closures
must be `Send + 'static` and may need an explicit event type. Runtime workers
publish sequentially and retain permits until cleanup, possibly after the method
returns. `runtime::Worker<T, A>` replaces progress sinks; fuzz's collector finish
returns its aggregate directly. Configure clock/runtime/cancellation/neighbors
with `with_*` methods.
`Clock` is shared/cloneable; `now(&self)`, `sleep(&self, delay, deadline)` use one
monotonic base. Remove clock cancellation adapters; use `Client::with_cancellation`.

- **Send:** `Request::packet` for one frame or bounded template/repeat/rate;
  events/aggregate retain pass, index, packet. Preparation/output/clock/coherence
  failures are typed.
- **Exchange:** split old options into request and reusable `Collection`.
  Clone a collector as sink, not `observe`. `StopCondition::Window` is default;
  `AllAnswered` stops only after every request was answered and every send completed.
  Report diagnostics move to events/aggregate.
- **Scan/trace:** requests own route/collection; no longer Serde types. Errors are
  workflow enums, not `probe::ErrorKind`. Validate collection against evidence
  before I/O; failures retain pipeline evidence/sources. Trace literals add
  `payload_size: 0`, `dont_fragment: false`, `dscp: 0`; limits are 9000/63,
  TCP carries no payload, IPv6 rejects DF, real wire size governs admission.
- **Capture:** `Request::new(group_request, window)` with optional selector.
  Sink answers convert to `Control` (`()` continues); `StopBefore`/`StopAfter`
  preserve successful partial evidence. Selector runs before worker publication.
- **DNS:** client/batch reports and collectors replace runners; aggregate
  `report()` replaces `summary()`. Batch questions share server/route/collection.
  Request live route/collection skip Serde. Construct authorization errors explicitly;
  evidence/query failures retain typed sources.
- **Fuzz:** core owns campaign/cases/offline outcomes; live `Request` and
  `Trial { case, evidence }` replace executor inputs. Rejected cases carry no live
  evidence; transmitted cases describe exact sent packets. Campaign preparation
  and traffic statistics remain separate. Offline runs use core `run_observed`.

Collector/report incoherence is an internal error, never synthesized success.

## CLI library API

`packetcraftr_cli::main()` owns parsing/execution and returns `ExitCode`; the binary
calls it. Output `Format`/stats `Table` no longer implement `clap::ValueEnum`;
define your own and convert. Command variants/formats derive from the command
catalog; `Command::ALL` uses help order, so sort by `as_str()` if needed.
`require_format` returns validated `Format`, not `()`; impossible rendering paths
fail typed rather than panic. This refactor alone changes no machine contract.

## Output field types

Output uses library types directly where their Serde shapes agree; CLI-owned
representations remain where fields/variants differ. Removed `output::diagnostic`
and `output::probe` paths become owner types; frame/network/analysis conversions
remain under their output modules.
Use `From`/`TryFrom` instead of `from_*`/`try_from_*`/`complete_from_*`.
Conversions carrying diagnostics/stats yield `envelope::Published<T>`; publish
with `Envelope::published` or stream `emit_published`/`complete_published`.
Scan additionally requires plan/stage data through `publish` / `Summary::new`.
Unpublishable future variants fail `contract::Error::Unpublished`, except optional
error coordinates, which are omitted. Protocol `Detail` embeds flattened
`summary`; access Rust fields as `detail.summary.<field>` (JSON unchanged).
Use `FilterField::try_from((path, binding))`, not removed helper constructors.

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
| `scan::ProbeEndpoint`, `traceroute::ProbeTarget` | `probe::ProbeEndpoint` |
| `scan::ProbeStatus`, `traceroute::ProbeStatus` | `probe::ProbeStatus` |
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
| `output::contract::SCHEMA_V2` | `output::contract::SCHEMA_V14` |
| `Command::require_format(format) -> Result<(), Error>` | `require_format(format) -> Result<Format, Error>` |
| `impl clap::ValueEnum` for `output::contract::Format` and `output::stats::Table` | removed; declare your own value enum and convert with `From` |
| `try_from_*`, `from_*`, and `complete_from_*` constructors on output types | `From`/`TryFrom`, yielding `output::envelope::Published<T>` where diagnostics or stats travel with the result (see [Output field types](#output-field-types)) |

## Callers tracking main

Items introduced and removed entirely after beta.3 have no released migration.
Pin a reviewed revision rather than depending on intermediate names. This cleanup
changes provider composition only; CLI behavior and output/v14 remain unchanged:

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
These semantics are retained in current output/v14; historical native evidence
keeps its original schema identity. See [scanner timing](scanner-evidence.md).
