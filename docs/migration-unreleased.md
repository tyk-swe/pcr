# Migrating from 0.5.0-beta.3

These notes describe the pending changes in `[Unreleased]`.

All structured command envelopes now identify `packetcraftr.output/v6` and
validate against `schemas/packetcraftr.output.v6.schema.json`. Packet documents
now use `packetcraftr.packet/v2` and the corresponding v2 schema. Earlier
packet-document versions are rejected with a schema error.

## Forwarding semantics and output/v6

Ordinary preservation no longer treats two missing fields as a satisfied check.
Use explicit `--preserve-presence` / `--expect-absent` for decoder-view absence.
Checks expose evidence states; an unrelated incomplete field cannot erase a
readable-field violation. Rules now label correspondence-only comparisons and
warn about identity/preservation overlap.

Rust `Observation` fields are private and observations bind to the exact
compiled rules and side. Use collectors and read-only getters, not literals.
`verify` returns `forwarding::Error`; `verify_with_limits` accepts independent
detail/scratch budgets and a shared deadline. `analysis::Options` gains `plan`
and `deadline`; exhaustive struct initializers must add them or use defaults.
The default analysis plan preserves previous reconstruction/index semantics.
Analysis processing deadlines now classify as `policy.duration_limit`, matching
capture-reader and invocation deadlines, instead of `policy.analysis_resource_limit`.
Analysis dissection failures keep the decode error's own code instead of
`packet.decode`: a layer-limit refusal reports `policy.analysis_resource_limit`,
like a byte-limit refusal, and codec-contract failures report
`internal.codec_contract`. Live workflow build failures likewise report the
build error's own code (such as `policy.build_resource_limit`) instead of
`packet.build`.

Forwarding defaults now retain at most 4 MiB of detail charges across categories,
in addition to the per-category entry ceiling. Omission counts remain explicit
and do not change verdicts. Consumed input SHA-256/byte counts and decode context
are published by the CLI. Evidence charges account for typed JSON serialization.

See [verification semantics](verification-contract.md), [consumer compatibility](consumer-compatibility.md),
and [resource presets](resource-presets.md). Consumers of earlier output
contracts must reject or explicitly migrate v6 rather than infer semantics.

## Named packet fields and output/v6

Field values now include `{ "type": "object", "value": { "name": TAGGED_VALUE } }`.
Object members share the list-item, nesting, node, and payload budgets; key bytes
also consume payload budget. Expressions use `{name=value}` objects. Nested paths
such as `questions[0].name` use zero-based list indices in reflection, templates,
filters, and fuzz targets. Protocol field descriptions publish nested members.

DNS is constructible. `Dns::questions` contains lossless `Question` values;
`qnames`, `qtypes`, and `qclasses` are replaced by this single question model.
The read-only reflected `qname`, `qtype`, and `qclass` views remain available.
Section counts now use `WireValue<u16>`. Fresh messages derive counts; `Dns::edit`
resets them to `Auto` for explicit structured edits. Exact/raw overrides follow
the existing strict/permissive rules. DNS records reflect as named objects.
Untouched decoded messages retain compression and unknown bytes exactly; edited
messages encode names uncompressed, leaving unknown RDATA opaque. Opaque RDATA
is not interpreted or relocated if it contains application-specific pointers.
The reflected `wire` field preserves the original message through document
round trips; explicit structured edits invalidate that retained image.

Output/v6 includes streamed `build` packet/completion events and replay
`{"bit_rate": BITS_PER_SECOND}` timing. Successful TCP DNS can have
`fallback_attempted=false`: this represents a direct TCP query. Consumers
must inspect the actual attempt transport rather than infer it from fallback.
Fallback attempts retain a preceding truncated UDP phase with the same attempt
number. These changes supersede the earlier unreleased output/v3, output/v4, and
output/v5 contracts.

DNS `query_type` is an integer in `0..=65535` wherever it appears in aggregate
summaries and NDJSON DNS events. For example, `"query_type": "aaaa"` becomes
`"query_type": 28`; `"any"` becomes `255`. Update consumers that compare strings
or require the output/v2 envelope. Named and unknown record data retain their
existing representations and exact bytes.

`--type` accepts existing aliases, 1–5 ASCII decimal digits, or `TYPE` followed
by 1–5 digits. Aliases and `TYPE` are case-insensitive; codes must fit `u16`.
Signs, whitespace, Unicode digits, and out-of-range values are rejected before
I/O. Text displays known aliases and `TYPE<n>` for other codes.

The Rust `dns::QueryType` enum becomes a numeric value storing a private `u16`,
with `QueryType::new(code)` and `.code()`. Constants are `A`, `AAAA`, `CAA`, `CNAME`,
`MX`, `NS`, `PTR`, `SOA`, `SRV`, `TXT`, and `ANY`; update names such as `Aaaa` to
`AAAA`. Match constants or numeric codes with a fallback for other values.
Use `Display` for presentation and integer serde values for data. The CLI
contract constant is now `SCHEMA_V6`.
The `.as_str()` method is removed; use `Display` or `.to_string()` instead.
Text parsing returns `QueryTypeParseError`, preserving the original integer
parse error for out-of-range values.
CLI DNS output structs store `query_type` as `u16`; use `.code()` when
constructing their summaries or events from a `QueryType`.

## Packet templates and UDP scan payloads

`Template::axis` now adds an axis to a Cartesian product instead of replacing
the previous axis. The last axis varies fastest. Repeating a field or one of
its aliases is an error. `expansion_len()` returns `Result<usize, template::Error>`;
use `expansion_len()?` and handle expansion overflow. `expand(maximum)` validates
axis fields and values before returning its lazy iterator. An axisless template
has one packet, and any empty axis produces an empty library set.

CLI `build` and `exchange` use `--axis '0.ttl=[1,64]'` and the finite
`--max-template-packets` ceiling. Empty CLI sets are rejected. Multi-packet builds
support text, hex, and NDJSON; JSON/raw remain single-packet outputs. Streamed
build records carry `packet_index` and the existing built-packet fields;
completion carries `packets_built` and `bytes_built`. `expression::parse_value`
exposes the existing bounded value grammar for callers authoring axes.

`--axis` additionally accepts inclusive unsigned ranges `START..END[:STEP]`
with decimal or `0x` endpoints, such as `0.ttl=1..64` or `0.ttl=1..64:8`.
Ranges are checked against the packet ceiling before any packet materializes;
reversed ranges, zero steps, and malformed spans are typed errors.

Rust `scan::Request` and `scan::Probe` gain `udp_payload: bytes::Bytes`; add
`udp_payload: bytes::Bytes::new()` to request/probe literals to retain empty
datagrams. Request deserialization defaults missing payloads to empty.
`scan::Probe` is now `Clone` rather than `Copy`, with shared payload storage.
Payloads are bounded to `scan::MAX_UDP_PAYLOAD_BYTES` (65,507), included in the
operation budget, and rejected when non-empty for TCP or ICMP.

## Typed TCP options

The `Tcp` layer's `options` field is now an ordered list of typed option
objects (`packetcraftr_core::protocol::transport::TcpOption`) instead of
`bytes::Bytes`. Standard options — EOL, NOP, MSS, window scale,
SACK-permitted, SACK blocks, and timestamps — reflect as
`{kind: N, member: …}` objects; unknown kinds, nonstandard lengths, and
unparseable tails stay byte-exact as `Raw`/`Trailing` entries. Construction
accepts typed objects (`options=[{kind=2,mss=1460}]`) or verbatim bytes
(`options=hex("0204 05b4")`), which parse into the same typed form. Nested
paths such as `tcp.options[0].mss` work in filters, projection, templates,
and fuzz targets. Code that read `options.as_ref()` now iterates `options`
variants instead.

## DNS transport selection

Replace `dns::Request::tcp_fallback` with `transport: dns::TransportMode`:
`false` becomes `TransportMode::Udp`, `true` becomes `TransportMode::UdpThenTcp`,
and `TransportMode::Tcp` selects direct TCP. The enum defaults to `UdpThenTcp`;
the `DEFAULT_TCP_FALLBACK` constant is removed. Serialized requests use
`"transport": "udp"`, `"udp_then_tcp"`, or `"tcp"`. Unknown request fields,
including the obsolete `tcp_fallback`, are rejected so an old UDP-only setting
cannot silently enable TCP. `source_port` is unused in TCP-only requests.

Direct TCP uses the explicitly composed TCP provider without executing a UDP
exchange. Its budget contains connections, framed messages, and application
bytes, with zero raw UDP cost. Completion reports `fallback_attempted=false`;
successful aggregate TCP reports require a retained successful TCP attempt.
Packet-oriented route overrides and scoped IPv6 link-local TCP remain unsupported.

## Opt-in EDNS requests

`dns::Request` gains `edns: Option<EdnsRequest>`. Add `edns: None` to existing
Rust request literals. Deserializing a request without this field defaults to
`None`. `encode_query(name, query_type, id, recursion_desired, edns)` now takes
the option as its fifth argument; `None` preserves the original query bytes.

`EdnsRequest` contains `udp_payload_size: u16` in `512..=65535` and
`dnssec_ok: bool`. Version 0 is fixed. The encoder adds exactly one OPT record
with the root DNS name and no options, and validates settings before I/O. All eleven
added bytes count toward UDP and framed TCP authorization budgets. Each TCP
continuation sends the same DNS message as its triggering UDP attempt.

The CLI enables EDNS with `--edns-udp-payload-size SIZE`; `--dnssec-ok` requires
that flag. DO requests DNSSEC data and performs no signature validation. The
advertised receive size is independent of `--max-message-bytes`, which bounds
response decoding. Existing output `edns` fields still describe the response;
these request settings add no fields to the output/v6 or packet/v2 contracts.

## Offline DNS records

Import DNS `Name`, `Record`, `RecordValue`, `Edns`, and `EdnsOption` from
`packetcraftr_core::protocol::application::dns`. The workflow crate consumes
these core types. `Name::from_labels` now returns core `DecodeError`.
Name failures use `DecodeError::Name(name::Error)`, retaining their original
offsets and typed source, including the distinction between self-pointers and
pointer loops.
Structural live-decoder failures are wrapped in `WireError::Decode(DecodeError)`;
match the core error inside that variant. Query correlation, TCP framing, and
live EDNS policy errors remain workflow-owned.

`Dns::from_wire` decodes all declared records. Malformed or truncated records
and trailing bytes now fail decoding; offline dissection retains the original
payload with malformed-packet diagnostics. `Dns::from_wire_with_limits` returns
typed `DecodeError` and accepts `DecodeLimits`. The retained `wire()` remains
the original message, including compression and unknown bytes.

Default bounds are 65,535 message bytes, 512 records, 32 compression pointers
per name, and 256 strings / 16,384 bytes per TXT record. Absolute ceilings are
65,535 message or TXT bytes, 4,096 records or TXT strings, 128 pointers per name,
and 64 questions. Supplied limits above these ceilings are tightened; zero
permits none of that resource.

DNS reflection exposes `answers`, `authorities`, and `additionals` as lists of
named `{owner, type, class, ttl, value}` objects. Replace positional record lists
with these objects. The nested `value` object selects its shape with `kind`:

| `kind` | Named value members |
| --- | --- |
| `a`, `aaaa` | `address` (IPv4) or `address6` (IPv6) |
| `cname`, `ns`, `ptr` | `name` |
| `mx` | `preference`, `exchange` |
| `soa` | `primary_name_server`, `responsible_mailbox`, `serial`, `refresh`, `retry`, `expire`, `minimum` |
| `srv` | `priority`, `weight`, `port`, `target` |
| `caa` | `flags`, `tag` bytes, `data` bytes |
| `txt` | `strings`, a list of byte values |
| `unknown` | `type`, exact `rdata` bytes |
| `opt` | `udp_payload_size`, `extended_response_code`, `version`, `dnssec_ok`, `flags`, `options` as `{code, data}` objects |

Ordinary typed records are decoded for the Internet (`IN`) class. Other
classes retain exact RDATA as `unknown`; their class-specific formats are not
interpreted as Internet addresses or records.

OPT records remain in their original section. Offline inspection retains
unknown EDNS versions; live queries still enforce their existing OPT version,
owner, section, and uniqueness rules. These fields fit the existing recursive
packet/v2 field contract.

## Typed netio validation errors

`packetcraftr_netio::route::Error::InvalidSourceRouting` and
`InvalidSegmentRouting` now carry
`source: Option<Box<dyn std::error::Error + Send + Sync>>`.
When constructing a local route failure, provide `source: None`. Conversions
from packet-semantics validation retain the original error as `Some`, so
`source().downcast_ref::<packetcraftr_core::packet::semantics::Error>()`
recovers the typed cause.

Wrapped errors display route context; inspect `std::error::Error::source()` or
`Classified::causes()` for the validation detail. Native interface-snapshot
validation similarly retains its original `SystemError` in the existing
`SystemFault` shared-source representation. Classification codes are unchanged.

## Explicit DNS TCP providers

A bare `packetcraftr::probe::ExchangeExecutor` reports unsupported TCP
execution. Opt in with `.with_dns_tcp(provider)`; the CLI selects
`packetcraftr_netio::tcp::SystemProvider` explicitly. Injected UDP providers
therefore cannot silently open a system TCP socket after a truncated response.

Low-level callers pass a provider to `dns::tcp::exchange(request, &provider)`.
`packetcraftr_netio::tcp::{Provider, Stream}` owns the narrow connection and
stream capability; `dns::tcp` retains framing, finite deadlines, and evidence.
The standard-library provider works independently of native packet and route
feature flags. Interface, preferred-source, and link-mode overrides remain
unsupported for kernel TCP, and every TCP query retains endpoint reauthorization
and final query-byte checks.

## Resource and output hardening

Existing client constructors remain available; the feature additions in this
release add fields to public limits and migrate output to v6. Share callback admission with
`client.with_progress_runtime(runtime.clone())`; inspect it with
`client.progress_runtime().snapshot()`. Native admission remains process-wide.

`--resource-diagnostics` opts into an optional `resources` envelope member.
Output/v6 schemas include this member. Resource diagnostics add no NDJSON events
or sequence positions.
`--output-timeout-ms` affects NDJSON writes only; the default and terminal-error
cleanup allowance remain one second, and operation deadlines take precedence.

TCP memory charges now include payload-page slack and transient allocations.
A previously accepted capture near an aggregate limit can be rejected earlier;
raise an explicit budget only after considering the hosting process limit.
Packet-document key reordering no longer changes semantic acceptance. Existing
input/depth and duplicate-field checks still apply. See
[resource contracts](analysis-resources.md).

## TLS hello construction

`Tls::from_hello(Hello)` builds complete ClientHello/ServerHello fixture records.
The `hello` object in recipes exposes record/legacy versions, random, session ID,
cipher suites, compression methods, and ordered `{type, data}` extensions.
`HelloExtension::server_name` and `HelloExtension::alpn` construct common bodies;
recipes also accept `{server_name="example.test"}` and `{alpn=["h2"]}`.
Extension bodies remain authoritative, including unrecognized extensions.
Nested template and fuzz paths can address `hello.cipher_suites[0]` or
`hello.extensions[0].data`. Edits rederive lengths and fingerprints.

Expressions accept `hex("00ff")` and `bytes("text")` for exact byte values,
including inside objects and lists. Decoded TLS extension models now retain
`data`; ServerHello models retain their echoed `session_id`.

Offline DNS analysis is available through `analysis::dns::Collector` and the
`dns-read` CLI command. Collector callers enable both `Options::tcp_events` and
`Options::track_sources`, feed complete conversations, then call `finish` with
the run summary. `FrameRecord` exposes source sets for physical and reassembled
transport views; source sets share a bounded provenance allocator and reject
unions from different capture runs. `Limits::max_provenance_bytes` bounds these
allocations. `LayerDecodeContext::parent` identifies the enclosing protocol so
DNS can distinguish UDP messages from TCP length-prefixed messages.

Capture header rewrites use `transform::HeaderRewrite` and the `rewrite` CLI.
Conditional rule documents have independent version `packetcraftr.rewrite/v1` and
schema `schemas/packetcraftr.rewrite.v1.schema.json`. Rules evaluate original frames
and apply matching edits in order. `pcap::map_frames` normalizes mapped frames into
one PCAPNG section and checks capture identity, metadata, and declared growth.
`export` instead uses a stable snapshot and preserves selected source records.

Fixed-width field assignments extend the same `rewrite` workflow through
`transform::FieldEdits` (`FieldAssignment`, `ChecksumMode`, `FieldEditOutcome`,
`FieldChange`). `--set <protocol>[#occurrence].<field>=<value>` and
`packetcraftr.rewrite/v2` documents (`assign` entries as `"field=value"` strings
or `{"field","value"}` objects) write `ipv4.ttl`, `ipv6.hop_limit`,
`tcp.sequence`, `tcp.acknowledgment`, TCP/UDP ports, and `dns.id` in place over
original bytes; compressed names, opaque payload, and unrelated checksums are
retained. `--checksum-mode repair` (default) recomputes only covering IPv4
header and TCP/UDP pseudo-header checksums, refusing fragmented,
AH/ESP-protected, quoted, or uncomputable coverage; `preserve` keeps checksum
bytes exactly. `--dry-run` reports per-frame `changes` (field, `range`,
`old`/`new`, `origin`) bounded at `MAX_REPORTED_CHANGES` with a
`changes_omitted` count, and never creates the destination. `--set` conflicts
with `--rules-file`; when combined with header flags the header rewrite applies
first. Rules evaluate the original frame and apply in order, atomically per
frame.

DHCP codecs live at `protocol::application::dhcp` and bind standard UDP ports.
`Dhcpv4`, `Dhcpv6`, `Option4`, and `Option6` construct fixtures with named option
values. `Limits` bounds complete message bytes, aggregate option nodes, and nesting.
Per-message wire retention preserves exact unedited captures. Protocol discovery
may replace repeated `children` arrays with `children_reference`: resolve that JSON
Pointer against the containing top-level field description before traversing its
children. This only compacts discovery output; reflective paths keep their bounds.

Live capture orchestration now lives in `packetcraftr::capture`, over
`packetcraftr_netio::capture::group`. `capture::run` owns activation through cleanup,
charges the shared `CaptureBudget` before selection, and reports per-source evidence.
The CLI accepts repeated `--interface` flags. Live `frame.interface_id` and emitted
frame interface values are capture IDs (0-based selected-interface order); completion
sources map these to native interface names/indexes. Update filters that used native
OS indexes in this field. Cross-interface delivery keeps exact timestamps without
promising timestamp ordering.

Capture completion is an enriched `output::capture::Summary`, replacing the empty
completion payload. JSON capture requires `--write`. Capture failures may include
`error.capture`, containing source/file evidence and processed statistics. Rotated
files are PCAPNG, use uncompressed byte thresholds, and finalize compression per
file. Explicit ring retention reuses operation-owned handles and reports retired
files; neither source count nor rotation increases the configured operation budget.

`capture` accepts `--capture-buffer-bytes`, `--timestamp-source`, and
`--timestamp-precision` for native driver settings applied per interface before
activation; the kernel capture buffer is independent of the PacketcraftR queue
budgets (`--max-queue-frames`/`--max-captured-bytes`). Explicit settings the
backend cannot honor fail with a typed error rather than silently falling back.
Each capture source can report `capture_settings`, a requested/applied/effective
triple per setting where `effective` is `null` when the backend cannot confirm
the realized value — the pcap-family API offers no post-activation query for the
allocated buffer or the active timestamp type. `interfaces --timestamp-types`
adds a `timestamp_types` list to each interface; entries with `source: null`
describe clock domains capture cannot select. Only timestamp sources
synchronized with the system clock are selectable.

`capture --dissect` adds an optional `decoded` object to NDJSON `frame` records —
the same `decodedStack` (`packet`, `layout`, `diagnostics`) `read --dissect`
publishes — beside the preserved `frame` bytes and metadata. `capture --field`
streams `fields` rows on the capture stream under `--max-projection-bytes`, so
the `capture` command joins `read`/`dissect` in the shared projection contract.
Both are additive: consumers that ignore optional members and the `fields`
event need no change. Decoded output requires text or NDJSON (`--write` to
PCAPNG stays raw-only) and `--field` conflicts with `--dissect`.

Scan requests use bounded `target::Selection` sets (hosts/CIDRs/exclusions), with
`Limits::max_targets`, `max_in_flight`, and `Limits::max_prepared_bytes`. Raw scan
executors expose `pipeline_capacity` and may implement `execute_pipeline`; the
base executor refuses unsupported windows instead of serializing them silently.
`probe::PipelineEvent` carries confirmed sends, completions and bounded evidence.
CLI executor delegation preserves this capability. Raw scan NDJSON adds
`probe_sent`; failures may carry `error.scan` with confirmed pending wire.

`scan::Summary`, `scan::Report`, and `connect::Statistics` gain `rtt`:
confirmed sends, verdicts received inside their round, `lost = sent - received`,
and min/avg/max over one sample per received probe. Rust literal constructors
must supply `scan::Rtt::default()` or an accumulated value. The output/v6
schema adds the corresponding `rtt` objects on scan summaries and
`socket_stats`; absent duration fields mean no response produced a sample.

`analysis::Summary` and `stats::Report` gain `interfaces`: the capture
source's interface descriptions in global-ID order (empty for a PCAPNG
source with none). `stats::Report` also gains `duration()`,
`average_packet_size()`, `packet_rate()`, and `byte_rate()` derived
accessors — `None` on empty match sets or zero spans — and the stats
aggregate publishes them as `duration`, `average_packet_size`,
`packets_per_second`, `bytes_per_second`, plus a required `interfaces`
array on `statsResult`.

`Request::udp_profiles` maps ports to validated `Arc<profile::UdpProfile>` values.
`Probe` retains its selected profile, and `ProbeEvidence::application` reports
application validation independently of reachability. Configuration serializes
through `profile::Config`; private compiled state is revalidated on deserialization.
`Registry::to_builder` derives isolated bindings for explicit byte/DNS profiles,
without changing the caller's registry. UDP profile documents use independent
`packetcraftr.udp-profiles/v1` and ship with a schema and example.

## Replay mapping and repetition

Wrap the old `replay::Options::interface` value in `Some` for a fixed fallback,
and add `repeat: 1` and `inter_pass_delay: Duration::ZERO` for one pass.
`Selector::interface` may return an output interface for each selected frame;
its default uses the fallback. Replay readers now require `Read + Seek` so the
engine can rewind between passes. The CLI snapshots and validates the complete
capture before live work, including compressed inputs.

Repetition shares source-frame, transmitted-byte, time, and policy budgets.
`FrameEvidence::pass` is one-based; `source_index` remains relative to the input.
`Summary` adds `passes_completed` and `interfaces_used`. The aggregate requested
interface is optional, and each sent frame retains its actual output route.

## TCP connect scanning

Use `scan::connect::{run, run_with_events}` with an explicit TCP provider for
kernel connections. Reports use socket outcomes and endpoint evidence, with no
raw packet receipt or capture statistics. `policy::Operation::Socket` carries
`SocketOperation` with the authorized numeric endpoints and a finite `SocketBudget`.
Custom authorizers must handle this operation before a connection is admitted.

Netio's `tcp::start_connect` returns a pollable `PendingConnect`. Cancellation or
drop cancels unstarted calls; admitted calls retain their process-wide resource
lease until worker and socket cleanup finish. Successful `Connection` values
retain that lease until dropped. At most 16 calls/connections can retain admission.
The workflow caps `Request::max_in_flight` accordingly and rejects UDP/ICMP use.

## Offline epoch bounds

`read`, `stats`, `expert`, `follow`, `tls`, `dns-read`, `http`, and `export`
accept `--start-epoch EPOCH`/`--stop-epoch EPOCH` keeping only frames inside
the inclusive window. Values are non-negative Unix seconds with an optional
fraction of at most nine digits, compared at full `SystemTime` precision —
`1.5000005` still selects correctly against a microsecond-resolution capture.
Reversed bounds fail with `cli.reversed_time_bounds`; unsupported precision,
including fractions finer than the host's `SystemTime` representation, is
rejected rather than rounded. Frames whose records carry no timestamp are never
kept while bounds are set, and frames skipped by bounds count toward
`--max-frames`/`--max-bytes`. Bounds compose with `--filter` and do not assume
capture timestamps are ordered.

The Rust `analysis::Options` gains `time_bounds: Option<frame::TimeBounds>`;
construct bounds with `TimeBounds::new(start, end)`, which rejects a start
after the stop. Bounds apply at the same pipeline stage as the display filter:
timestamped physical frames still advance IP reconstruction and stream indexing
whether or not they are kept. Timestamp-less frames are skipped before that
stateful processing when bounds are set. All frames consume read budgets;
`analysis::Summary::bytes_read` reports the complete captured-byte input count.

## Followed-direction files

`follow --write DIR` writes each selected direction's payload to
`DIR/TRANSPORT-INDEX-client.bin` and `DIR/TRANSPORT-INDEX-server.bin`,
filtered by `--direction` and empty-filed when a direction carried no payload.
Both files share `--max-application-output-bytes`. Destinations are never
overwritten; publish failures attempt to roll back files the invocation already
created, and report any cleanup failures and their paths.
JSON and NDJSON reports carry `written: [{direction, path, bytes}]`.

## Destination allowlists

`policy::Policy` gains `allowed_destinations: Vec<DestinationConstraint>`,
bounded by `MAX_DESTINATION_CONSTRAINTS`. Each entry is an exact IP address or
a canonical CIDR network parsed by `DestinationConstraint::from_str`; network
input must spell the masked network address. A non-empty list must contain
every authorized destination at the target, packet-declared, route-visited,
and final-wire stages; an empty list adds no constraint, and matching entries
never substitute for the public-destination or other opt-ins. Denials surface
as `policy::Error::DestinationNotAllowed` (`policy.destination_not_allowed`)
carrying the refused destination and the rendered constraint set; malformed
entries and an oversized list classify as `cli.live_target`. The CLI exposes
the list as repeatable `--allow-destination ADDRESS[/PREFIX]` on every
destination-bearing live command.

## Send packet sets

`send` expands `--axis` templates and repeats the set with `--repeat`/`--rate`
instead of sending exactly one packet. `Client::send` is unchanged; new
`send_set`, `send_set_with_events`, and `send_set_driven` entry points take
`send::SetOptions` (`repeat`, `rate`, `max_template_packets`) and return
`send::SetReport` — `sent: Vec<SentFrame>` records each carry one-based `pass`
and expansion `index`, and `passes_completed` counts finished passes. The
output/v6 `sendResult` replaces `frame`/`route` with a `frames` list plus
`passes_completed`. Invalid repeat/rate values classify as `cli.send_limit`;
the pacing ceiling is `send::MAX_SEND_DURATION`.

## DNS question batches and reverse names

`dns` accepts several `NAME` positionals plus repeatable `--reverse ADDRESS`
(PTR questions derived by `dns::reverse_name` under `in-addr.arpa`/`ip6.arpa`)
as one batch bounded by `dns::MAX_QUESTIONS`. `dns::run_batch` and
`run_batch_with_events` take `&[Request]`, share the minimum
`limits.max_duration` as a single `Deadline` across questions, and return
`dns::BatchReport` whose `questions` carry `QuestionStatus` —
`completed`/`failed`/`unattempted` — in input order. Single-question
invocations keep the previous envelope and error semantics; batch aggregates
add a `questions` array to `dnsResult`, and streamed batches end with a
`complete` record carrying per-question statuses. `--transaction-id` is
rejected for multi-question batches because identifiers are per question.

## Generated documentation

`packetcraftr documentation --directory DIR` writes `DIR/completions/` (Bash,
Elvish, Fish, PowerShell, Zsh) and `DIR/man/` (one page per command), both
generated from the finalized command definitions of the binary that runs it.
The command produces files rather than a contract document: it ignores
`--output` and reports failures on stderr with the `io.documentation`
classification. Release archives now carry both trees, and the archive
verifier requires a man page for every shipped subcommand.

## Standard traits and narrower APIs

Wire constructors moved to `TryFrom`: `Dns`, `Dhcpv4`, and `Dhcpv6` implement
`TryFrom<Bytes>`/`TryFrom<Vec<u8>>`/`TryFrom<&[u8]>`, `Http` and `Tls` implement
`TryFrom<&[u8]>`, and `Tls` implements `TryFrom<Hello>`. Replace `X::from_wire(b)`
with `X::try_from(b)` (or `b.as_ref()` for `&Bytes`); the bounded
`*_with_limits` constructors stay inherent. `field::Path::parse` is removed —
use `FromStr` (`"a.b".parse::<Path>()`); `BuiltinProtocol` also implements
`FromStr` over canonical names and aliases, while `from_name` remains
canonical-only.

`Packet` supports `for layer in &packet` and `packet.extend(layers)`;
`SourceSet` dereferences to `[SourceFrame]`. The `as_str`-backed enums
(`error::Kind`, `FieldKind`, `BuiltinProtocol`, `scan::Classification`,
traceroute `ResponseKind`/`Completion`, `fuzz::CaseOutcome`, `ProbeStatus`,
`dns::Outcome`, `QuestionStatus`, and netio `Capability`/`Mode`/
`OverflowPolicy`) implement `Display`.

Registry APIs take the `LinkType` newtype (`RegistryBuilder::bind_link_type`,
`Registry::root_for_link_type`, `registry::Error::DuplicateLinkType`) and
`impl Into<Discriminator>` (`From<u64>`) instead of bare integers — drop `.0`
peels at call sites. `Frame::try_with_lengths`/`try_with_optional_timestamp`
take `frame::Lengths { captured, original }`, and
`Interner::with_limits` takes `analysis::scope::Limits { limit, max_bytes }`,
removing adjacent-scalar swaps. `Malformed::new` takes `Option<String>`;
analysis HTTP/DNS collectors take `impl IntoIterator<Item = u16>` for ports.

`transform::VlanTag` is renamed `VlanRewrite` (`From<link::VlanTag>` provided);
`analysis::follow::Direction` is renamed `PeerDirection`, distinct from
`frame::Direction`. `budget::Interrupted` and netio capture `Failure`/`Error`
are `#[non_exhaustive]` — add a wildcard arm to exhaustive matches.

## Layer codec input

`LayerCodec::decode` takes the layer input as a refcounted `Bytes` view instead
of `&[u8]`, and `dns::name::decompress` takes `&Bytes`. Custom codecs can
retain ranges with `input.slice(..)` instead of copying them; callers holding
borrowed bytes wrap them once with `Bytes::copy_from_slice` or `Bytes::from`.

## TCP retransmission spans

`analysis::reassembly::tcp::Event::Retransmission` gains a `ranges:
Vec<Range<u32>>` field listing the arriving segment's retransmitted sequence
spans in stream order; the spans need not form a contiguous prefix. `Event` is
not `#[non_exhaustive]`, so struct patterns need `..` or a `ranges` binding and
constructors must supply the field.

## Typed error sources

Errors keep typed sources instead of display strings.
`document::Error::Parse.source` is now
`Box<dyn std::error::Error + Send + Sync>` (was `String`); construct it with
the parser's error or a message-boxing helper rather than `.to_string()`.
probe `ErrorKind` implements `std::error::Error` and `Error::source()`
delegates to it, so `source().downcast_ref::<SelectionError>()` (and similar)
recovers the original cause through worker-reaper, route materialization,
authorization, send-execution, DNS-classification, and capture-output
failures. `fuzz::CaseFailure` implements `Error`. `CliError` implements
`std::error::Error`; `rules::vlan`/`mac` return it directly.

## Neutral classification kinds

`packetcraftr_core::error::Kind::Cli` is renamed `Kind::Usage`; replace every
`Kind::Cli` match arm and constructor. `Kind::Usage.as_str()` and its serde
name are `"usage"`. Classification codes keep their frozen strings (for example
`cli.capture_filter`), and machine output still publishes a usage failure as
`"kind": "cli"` with exit code 2. In the CLI crate,
`output::envelope::Error.kind` is now the CLI-owned `envelope::ErrorKind`;
convert with `ErrorKind::from(kind)`.

## Filter timestamp failures

A display filter that reads `frame.time_epoch` on a frame without a timestamp
now reports `packet.timestamp_unavailable` (exit 3) from every command,
including `read --field`, `capture`, `replay`, and `rewrite`. It previously
reported `packet.error` (exit 3) or `cli.filter` (exit 2) depending on the
command; update scripts that match either code for this case.

## Format proof enums

`output::contract::Command::require_format` is generic:
`require_format::<F>(format) -> Result<F, contract::Error>` narrows `Format`
to one of the per-command proof enums (`AggregateFormat`, `ToolFormat`,
`BuildFormat`, `CaptureFormat`, `DissectFormat`, `SendFormat`,
`ExchangeFormat`, `ReadFormat`, `FollowFormat`). Each exposes `FORMATS`,
`as_format()`, `From` into `Format`, `TryFrom<Format, Error = Format>`, and
`Display`. Shared helpers accept `impl Into<Format>`, and dead rendering arms
surface typed `internal` errors instead of panicking.

## Canonical probe APIs

Shared probe types now live only at `packetcraftr::probe`. There are no
compatibility aliases; update imports directly:

| Existing paths | Canonical path |
|---|---|
| `scan::Executor`, `traceroute::Executor`, `dns::Executor`, `fuzz::Executor` | `probe::Executor` |
| `scan::Execution`, `traceroute::Execution` | `probe::Execution` |
| `scan::Error`, `traceroute::Error` | `probe::Error` |
| `scan::ProbeEndpoint`, `traceroute::ProbeTarget` | `probe::ProbeEndpoint` |
| `scan::ProbeStatus`, `traceroute::ProbeStatus` | `probe::ProbeStatus` |
| `scan::Transport`, `traceroute::Strategy` | `probe::Transport` |

Workflow-specific types keep their module homes: `dns::Error`,
`dns::Execution`, `dns::Transport`, DNS execution receipts, `fuzz::Error`,
`fuzz::Execution`, and the specialized `traceroute::Batch` alias are
unchanged.

`scan::Batch` is now the specialized `probe::Batch<scan::Probe>` alias, like
`traceroute::Batch`. A scan batch still carries exactly one probe, so an
executor implementation reads `batch.probes[0]` (or iterates `batch.probes`)
where it read `batch.probe`. Probe order, timeouts, and upfront budgets are
unchanged.

## Removed equivalent paths

Items that were reachable at more than one public path keep only their
canonical path:

| Removed path | Import instead |
|---|---|
| `packetcraftr_core::{Packet, PacketError}` | `packetcraftr_core::packet::{Packet, PacketError}` |
| `build::{Context, Mode}` | `codec::{Context, Mode}` |
| `build::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE}` | `layout::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE}` |
| `protocol::application::{Dns, Tls}` | `protocol::application::dns::Dns`, `protocol::application::tls::codec::Tls` |
| `protocol::application::tls` facade re-exports | `tls::fingerprint::`, `tls::model::`, `tls::parse::` |
| `analysis::pcap::DEFAULT_SIZE_LIMIT` | `frame::DEFAULT_SIZE_LIMIT` |
| `packetcraftr::dns::tcp::SocketFault` | `packetcraftr_netio::SystemFault` |
| `packetcraftr::fuzz::PolicyAuthorizer` | `packetcraftr::policy::PolicyAuthorizer` |
| `packetcraftr::replay::{Authorizer, Operation, ReplayFrame, WireBudget}` | `packetcraftr::policy::{Authorizer, Operation, ReplayFrame, WireBudget}` |
| `packetcraftr_netio::link::{MacAddress, VlanKind, VlanTag}` | `packetcraftr_core::packet::link::{MacAddress, VlanKind, VlanTag}` |
| `dns::ResponseMetadata::response_code_name`, `dns::ValidatedResponse::response_code_name` | `packetcraftr::dns::response_code_name(code)` |

The undocumented `packetcraftr_core::layer::{malformed_layout, padding_layout}`
exports are removed; `raw_layout` remains for codecs that emit `Raw` layers.
