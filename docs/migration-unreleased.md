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
these core types. `Name::from_labels` now returns core `dns::Error`.
Name failures use `dns::Error::Name(name::Error)`, retaining their original
offsets and typed source, including the distinction between self-pointers and
pointer loops.
Structural live-decoder failures are wrapped in `WireError::Decode(dns::Error)`;
match the core error inside that variant. Query correlation, TCP framing, and
live EDNS policy errors remain workflow-owned.

`Dns::from_wire` decodes all declared records. Malformed or truncated records
and trailing bytes now fail decoding; offline dissection retains the original
payload with malformed-packet diagnostics. `Dns::from_wire_with_limits` returns
typed `dns::Error` and accepts `DecodeLimits`. The retained `wire()` remains
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

`packetcraftr::route::Error::InvalidSourceRouting` (formerly in netio) and
`InvalidSegmentRouting` now carry
`source: Option<Box<dyn std::error::Error + Send + Sync>>`.
When constructing a local route failure, provide `source: None`. Conversions
from packet-semantics validation retain the original error as `Some`, so
`source().downcast_ref::<packetcraftr_core::protocol::semantics::Error>()`
recovers the typed cause.

Wrapped errors display route context; inspect `std::error::Error::source()` or
`Classified::causes()` for the validation detail. Native interface-snapshot
validation similarly retains its original `SystemError` as a shared
`packetcraftr_core::error::Source`. Classification codes are unchanged.

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
`client.progress_runtime().snapshot()`. Native admission remains process-wide:
one worker pool of `resources::WORKER_CAPACITY` slots admits capture reads,
route queries, and TCP connects. `native_snapshot()` (the `native_process`
row) covers all of them and is supported in every build profile;
`tcp_connect_snapshot()` (`tcp_connect_process`) reports the TCP sub-limit.

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
`packetcraftr_netio::capture::Group`. `capture::run` owns activation through cleanup,
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

`scan::Summary`, `scan::Report`, and `connect::Stats` gain `rtt`:
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
`SocketOperation` with the authorized numeric endpoints and finite `SocketLimits`.
Custom authorizers must handle this operation before a connection is admitted.

Netio's `tcp::start_connect` returns a pollable `PendingConnect`. Cancellation or
drop cancels unstarted calls; admitted calls retain their process-wide resource
lease until worker and socket cleanup finish. Successful `Connection` values
retain that lease until dropped. At most `tcp::MAX_PENDING_CONNECTIONS` (16)
calls/connections can retain admission, and they share the native worker pool
with capture and route work, so fewer are admitted while that work holds slots.
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
the pacing ceiling is `packetcraftr_netio::capture::MAX_TIMEOUT`.

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
`Interner::with_limits` takes `analysis::scope::Limits { max_scopes, max_bytes }`,
removing adjacent-scalar swaps. `Malformed::new` takes `Option<String>`;
analysis HTTP/DNS collectors take `impl IntoIterator<Item = u16>` for ports.

`transform::VlanTag` is renamed `VlanRewrite` (`From<link::VlanTag>` provided);
`analysis::follow::Direction` is renamed `PeerDirection`, distinct from
`frame::Direction`. `budget::Interrupted` and netio capture `Failure`/`Error`
are `#[non_exhaustive]` — add a wildcard arm to exhaustive matches.

## Layer codec input

`LayerCodec::decode` takes the layer input as a refcounted `Bytes` view instead
of `&[u8]`, and `dns::decode_name` takes `&Bytes`. Custom codecs can
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
`document::Error::Parse.source` is now an `error::Source` (was `String`);
construct it with `Source::new(error)` rather than `.to_string()`.
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

## Live-policy vocabulary out of core

Core keeps packet facts; `packetcraftr` owns what they mean for live traffic.

| Before | After |
| --- | --- |
| `build::BuiltPacket.requires_live_opt_in` | `packetcraftr::policy::requires_live_opt_in(&built)` |
| `packetcraftr_core::budget::remaining_before` | `packetcraftr_netio::deadline::remaining_before` |
| `budget::Cancellation::POLL_INTERVAL` | `packetcraftr_netio::deadline::POLL_INTERVAL` |
| `Deadline::bounded_timeout`, `Deadline::for_wait` | `packetcraftr::deadline::DeadlineExt` methods (import the trait) |
| `Cancelled::into_boundary_error` | removed; build `BoundaryError::with_source(c.to_string(), c.classification(), Vec::new(), c)` |
| `packetcraftr_core::deadline_error_conversions!` | removed; implement `From<DeadlineExceeded>` and `From<Interrupted>` (via `Interrupted::into_error`) |

`BuiltPacket` now records the codec `mode` it was built with and exposes
`contains_malformed()` and `contains_network_trailer()`; the published
`requires_live_opt_in` output field is unchanged. `Deadline` gains `limit()`
and `cancellation()` getters. `protocol::semantics::Error` messages now read
"destination cannot be determined because …"; match on the variant, not the
text.

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
`ExchangeFormat`, `ReadFormat`, `FollowFormat`). Each exposes
`FormatSubset::FORMATS`, `as_format()`, `From` into `Format`,
`TryFrom<Format, Error = Format>`, and `Display`. Shared helpers accept `impl Into<Format>`, and dead rendering arms
surface typed `internal` errors instead of panicking.

## Canonical probe APIs

Shared probe types now live only at `packetcraftr::probe`. There are no
compatibility aliases; update imports directly:

| Existing paths | Canonical path |
|---|---|
| `scan::Executor`, `traceroute::Executor`, `dns::Executor`, `fuzz::Executor` | `probe::Executor` |
| `scan::Execution`, `traceroute::Execution` | `probe::Execution` |
| `scan::ProbeEndpoint`, `traceroute::ProbeTarget` | `probe::ProbeEndpoint` |
| `scan::ProbeStatus`, `traceroute::ProbeStatus` | `probe::ProbeStatus` |
| `scan::Transport`, `traceroute::Strategy` | `probe::Transport` |

Workflow-specific types keep their module homes: `scan::Error`,
`traceroute::Error`, `dns::Error`, `dns::Execution`, `dns::Transport`, DNS execution receipts, `fuzz::Error`,
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
| `protocol::application::{Dns, Tls}` | `protocol::application::dns::Dns`, `protocol::application::tls::Tls` |
| `protocol::application::tls::{codec, fingerprint, model, names, parse}` submodule paths | the same items re-exported flat from `protocol::application::tls` |
| `analysis::pcap::DEFAULT_SIZE_LIMIT` | `frame::DEFAULT_SIZE_LIMIT` |
| `packetcraftr::dns::tcp::SocketFault` | `packetcraftr_core::error::Source` |
| `packetcraftr::fuzz::PolicyAuthorizer` | `packetcraftr::policy::PolicyAuthorizer` |
| `packetcraftr::replay::{Authorizer, Operation, ReplayFrame, WireBudget}` | `packetcraftr::policy::{Authorizer, Operation, ReplayFrame, WireLimits}` |
| `packetcraftr_netio::link::{MacAddress, VlanKind, VlanTag}` | `packetcraftr_core::packet::{MacAddress, VlanKind, VlanTag}` |
| `dns::ResponseMetadata::response_code_name`, `dns::ValidatedResponse::response_code_name` | `packetcraftr::dns::response_code_name(code)` |

The undocumented `packetcraftr_core::layer::{malformed_layout, padding_layout}`
exports are removed; codecs that emit `Raw` layers use `layer::Raw::layout`.

## Layer downcasting

`Layer::as_any` and `Layer::as_any_mut` are removed. `dyn Layer` upcasts to
`dyn Any`, and its inherent `is`, `downcast_ref`, and `downcast_mut` replace
the two-step call: `layer.as_any().downcast_ref::<Udp>()` becomes
`layer.downcast_ref::<Udp>()`. Hand-written `Layer` implementations delete
both methods; `clone_box` stays because `Clone` is not object safe.

## Capture file module

Capture-file formats are a top-level core module. Only the path changes; the
items and their behavior do not.

| Removed path | Import instead |
|---|---|
| `packetcraftr_core::analysis::pcap` | `packetcraftr_core::capture_file` |
| `analysis::pcap::compression` | `capture_file::compression` |
| `protocol::capture::{CaptureRoot, BUILTIN_CAPTURE_ROOTS}` | `frame::LinkType::BUILTIN_ROOTS`, a `(LinkType, BuiltinProtocol)` slice |

`frame::LinkType` keeps its path, fields, and constants. The link-type ↔
root-protocol mapping now exists once: use `LinkType::root_protocol`,
`LinkType::for_root_protocol` (raw IP is written as `LinkType::RAW`), and
`LinkType::is_raw_ip` instead of matching link-type constants by hand.
`fuzz::packet_link_type` returns the same link types through that mapping.

## CLI library entry point

The `packetcraftr_cli` library now holds the whole command-line application.
`packetcraftr_cli::main()` parses the process arguments, runs the command, and
returns its `ExitCode`; the `packetcraftr` binary only calls it. Command-line
behavior, flags, exit codes, and output documents are unchanged.

`output::contract::Format`, `output::stats::Table`, and
`output::capture::Retention` are plain output types and no longer implement
`clap::ValueEnum`. Code that parsed them with clap declares its own value enum
and converts it with `From`, as the CLI does.

## Acyclic core layers

Core modules now depend only on their own layer or a lower one (see the
`packetcraftr_core` crate docs). Only paths change; items and behavior do not.

| Removed path | Import instead |
|---|---|
| `packetcraftr_core::packet::semantics` | `packetcraftr_core::protocol::semantics` |
| `packetcraftr_core::protocol::raw::parse_hex` | `packetcraftr_core::layer::parse_hex` |

`protocol::raw` exported only `parse_hex`; the `Raw`, `Padding`, and
`Malformed` layers stay at `packetcraftr_core::layer`. A custom link protocol
whose frames may end in padding after the network payload (as Ethernet frames
do) calls `Builder::allow_trailing_padding(protocol)` when it registers its
codec, so decoding reports those bytes as padding and strict builds accept
link padding inside it.

## One command declaration

`output::contract::Command` is generated from the same declaration as the
CLI's command line, so its variants, serialized names, and `formats()` cannot
drift from the commands the binary accepts. Serialized names and each
command's formats are unchanged. `Command::ALL` now lists commands in `--help`
order; code that relied on the previous canonical order sorts by
`Command::as_str()` instead.

The per-command format enums (`AggregateFormat`, `ToolFormat`, and the others)
implement `output::contract::FormatSubset`. Their `FORMATS` constant moved from
an inherent item to that trait, so import the trait to read it:

```rust
use packetcraftr_cli::output::contract::{FormatSubset as _, ToolFormat};

let formats = ToolFormat::FORMATS;
```

`Command::require_format::<F>` requires `F: FormatSubset` instead of
`F: TryFrom<Format, Error = Format>`.

## Protocol grouping and wire errors

Built-in protocols live in their layer group, and each protocol's wire API
returns that protocol's error. Items and wire behavior are unchanged.

| Removed path | Import instead |
|---|---|
| `protocol::gre::Gre` | `protocol::tunnel::Gre` |
| `protocol::icmp::{Icmpv4, Icmpv6}` | `protocol::network::{Icmpv4, Icmpv6}` |
| `protocol::ipv6::{Fragment, HopByHop, DestinationOptions, SegmentRoutingHeader}` | `protocol::network::{Fragment, HopByHop, DestinationOptions, SegmentRoutingHeader}` |
| `application::dns::DecodeError` | `application::dns::Error` |

TLS items are imported from `application::tls` itself (for example
`tls::Tls`, `tls::parse_record`, `tls::ja4`, `tls::version_name`, and the
`tls::extension` constants); see "Removed equivalent paths".

Error types of the wire APIs:

- `Dns::to_wire` and `Dns::try_from` (from `Bytes`, `Vec<u8>`, and `&[u8]`)
  return `dns::Error`. Decoding failures are the former `DecodeError`
  variants; an encoding failure is `dns::Error::Encode`, whose source is the
  codec error. Code that matched `codec::Error::Truncated` on a DNS
  conversion matches `dns::Error::MessageTooShort`, `TruncatedField`, or
  `TruncatedLabelLength`/`TruncatedPointer`/`TruncatedLabel` instead.
- `Http::try_from(&[u8])` returns `http::Error`; an incomplete or trailing
  header block is `http::Error::Invalid`.
- `Tls::try_from` (from `&[u8]` and `Hello`), `Hello::to_wire`,
  `HelloExtension::server_name`, `HelloExtension::alpn`, and
  `tls::Outcome::Malformed` carry the new `tls::Error`. Its `Invalid`
  message displays exactly as the former `codec::Error::Invalid` did, and a
  hello that exceeds an encoder bound is `tls::Error::Encode` with the codec
  error as source.

## Parsed field paths

`Layer::field_path` and `Layer::set_field_path` take a `&field::Path`. Parse
the caller's spelling once and reuse it:

```rust
let path: packetcraftr_core::field::Path = "questions[0].name".parse()?;
let name = layer.field_path(&path);
layer.set_field_path(&path, value)?;
```

A string that is not a path fails with `field::Error::InvalidPath` at the
parse, where it used to read as an absent field or fail with
`layer::FieldError::UnknownField`. `Display` writes a path back in the same
syntax. Hand-written `Layer` implementations are unaffected unless they
overrode either method.

## Built-in identity

`BuiltinProtocol::of(layer)` and `BuiltinProtocol::identifies(layer)` decide
by the layer's concrete type, not by the protocol name in its schema. A custom
`Layer` whose schema says `ipv4` is not IPv4 to core: `of` returns `None`,
route semantics refuse it as an unknown protocol carrying a route field, and
it gets no built-in matcher or validation behavior. Give a custom layer its
own protocol name and register it through `registry::Builder`.
`BuiltinProtocol::from_id` and `from_name` still map registry identifiers and
names.

`protocol::semantics` no longer exports its field-name constants (`SOURCE`,
`DESTINATION`, `SOURCE_PORT`, `DESTINATION_PORT`, `SEGMENTS`,
`SEGMENTS_LEFT`, `LAST_ENTRY`, `TARGET_PROTOCOL`, `IPV4_OPTIONS`). Downcast
to the built-in layer and read its field: `layer.field(semantics::DESTINATION)`
on an Ethernet layer becomes
`layer.downcast_ref::<Ethernet>().map(|ethernet| ethernet.destination)`.

## Core error convention

Each core module has one `Error`, used module-qualified. Errors keep typed
sources, their messages no longer repeat the source's text, and every public
error implements `Classified`. Classification codes are unchanged.

| Removed | Use instead |
|---|---|
| `packet::PacketError` | `packet::Error` |
| `layer::FieldError` | `field::Error` |
| `field::PathError` | `field::Error::InvalidPath` |
| `layer::ReflectiveFieldError` | `layer::Refusal` (a reason, not an error) |
| `capture_file::SelectionError::Predicate` | `capture_file::Error::Predicate` |
| `capture_file::MapError::{Transform, Metadata, Identity}` | `capture_file::Error::{Transform, TransformMetadata, TransformIdentity}` |
| `capture_file::MergeError::{Sources, Source, ClockRegression, Metadata}` | `capture_file::Error::{MergeSources, MergeSource, MergeClockRegression, MergeMetadata}` |
| `analysis::SessionError::{Run, Collector}` | `analysis::Error` itself, and `analysis::Error::Collector` |
| `filter::ProjectionError::{Field, Limit}` | `filter::Error::{ProjectionField, ProjectionLimit}` |
| `fuzz::TargetParseError::{MissingSeparator, InvalidLayer, InvalidField}` | `fuzz::Error::{TargetSeparator, TargetLayer, TargetField}` |
| `dns::name::Error::*` and `dns::Error::Name(..)` | the same variants directly on `dns::Error` |
| `reassembly::{ip, tcp}::{ResourceError, MalformedError}` | `reassembly::{ip, tcp}::{Resource, Malformed}` |

The former `…::Capture(error)` wrapper variants are gone: `select`,
`map_frames`, and `merge` return `capture_file::Error`, `Session` returns
`analysis::Error`, and `Projection::compile`/`values` return `filter::Error`.
A merge input failure is `MergeSource { source: Box<Error>, .. }`.

Typed sources and reasons:

- `codec::Error::Rejected { protocol, source }` reports a protocol model's
  typed refusal (for example a `dns::Error` or `dhcp::Error` from a codec) and
  displays as "invalid <protocol> layer"; `source()` downcasts to the original
  error. Build one with `codec::Error::rejected(protocol, error)`.
  `codec::Error`, `dns::Error`, and `tls::Error` keep `PartialEq` but drop
  `Eq`; a `Rejected` source compares by its rendered chain.
- `error::Source` is core's one type-erased source handle (it is `Clone`, and a
  `#[source]` field of this type exposes the wrapped error). `BoundaryError`,
  `document::Error::Parse`, and `fuzz::CaseFailure::with_source` use it.
- `dhcp::Error::Limit` holds `dhcp::Limit` and `http::Error::Limit` holds
  `http::Limit` instead of a string; their messages are unchanged.
  `analysis::Error::InvalidLimit.reason` is an `analysis::Constraint`.
  `protocol::semantics::Error::Field.reason` is a `semantics::Constraint`
  instead of a string; its message is unchanged.
  `forwarding::Error::ExpectationSyntax` splits into `ExpectationSeparator`
  and `ExpectationEmptySide`.
- `error::render(&error)` joins an error and its sources into one line for text
  records such as diagnostics and malformed-layer reasons.

Messages that ended in `: {source}` now end before it, and the source
appears in `Classified::causes()` (and the published `causes`). Code that
searched `to_string()` for a source's text reads `causes()` or
`error::source_chain`, or `error::render` for one line.

## CLI output modules named after commands

Each `packetcraftr_cli::output` module is named after the command whose
output it describes. Update imports; the types, their fields, and their JSON
are unchanged:

| Before | After |
| --- | --- |
| `output::dns_analysis` | `output::dns_read` |
| `output::forwarding` | `output::verify_forwarding` |
| `output::scan_connect` | `output::scan::connect` |

## Limits and budgets

A configured ceiling is a `…Limits` type, validated where it is accepted and
never lowered silently. The running allowance charged against it is a
`…Budget`.

| Removed | Use instead |
|---|---|
| `capture_file::ReaderOptions` | `capture_file::ReaderLimits` |
| `capture_file::Reader::with_options` | `capture_file::Reader::with_limits` |
| `capture_file::Limits::advance(frames, bytes, len)` | `capture_file::Budget::new(limits)?`, then `budget.charge(len)?` (or `budget.after(len)?` to check without charging) and `budget.frames()` / `budget.captured_bytes()` |
| `analysis::Limits { max_tcp_bytes_per_flow, max_tcp_reassembly_bytes, max_tcp_segments_per_flow, tcp_idle_expiry, .. }` | `analysis::Limits { tcp: reassembly::tcp::Limits { max_bytes_per_flow, max_aggregate_bytes, max_segments_per_flow, idle_expiry, max_flows }, .. }` |
| `analysis::Limits { max_ip_datagrams, max_ip_fragments_per_datagram, max_ip_bytes_per_datagram, max_ip_reassembly_bytes, max_ip_outcomes, ip_idle_expiry, .. }` | `analysis::Limits { ip: reassembly::ip::Limits { max_datagrams, max_fragments_per_datagram, max_bytes_per_datagram, max_aggregate_bytes, max_retained_outcomes, idle_expiry }, .. }` |
| `scope::Limits { limit, .. }` | `scope::Limits { max_scopes, .. }`, at most `scope::MAX_SCOPES` |
| `decode::Options { max_layers, max_packet_size }` | `decode::Options { limits: packet::Limits { max_layers, max_packet_size } }` |
| `build::Options { mode, max_layers, max_packet_size }` | `build::Options { mode, limits: packet::Limits { .. } }` |
| `reassembly::tcp::Resource::InvalidWindowLimit` | `analysis::Error::InvalidLimit` from `tcp::Reassembler::new` |

Constructors that accept limits now validate them and return a `Result`:
`reassembly::ip::Reassembler::new` and `reassembly::tcp::Reassembler::new`
return `analysis::Error::InvalidLimit` (`cli.analysis_limit`), and
`scope::Interner::with_limits` returns `scope::Error::InvalidLimit`
(`cli.analysis_limit`). Each of these types, plus `capture_file::Limits`,
`MergeLimits`, `compression::Limits`, `dhcp::Limits`, `dns::DecodeLimits`, and
`application::Limits`, has a public `validate()`.

Behavior changes:

- `analysis::Limits.tcp.max_flows` bounds concurrent directional TCP flows by
  itself. It was derived as twice `max_flows`, which is still its default; set
  both if you raise `max_flows` past half of `tcp.max_flows`.
- Capture writers, `rewrite`, `select`, `map_frames`, and `merge` refuse a zero
  `max_frames` or `max_bytes` with `capture_file::Error::InvalidLimit`
  (`cli.capture_limit`) before writing anything.
- `dhcp::Limits` above `dhcp::{MAX_MESSAGE_BYTES, MAX_OPTIONS, MAX_NESTING}`
  and `dns::DecodeLimits` above `dns::{MAX_MESSAGE_BYTES, MAX_RECORDS,
  MAX_NAME_POINTERS}` fail with `InvalidLimit` (`policy.dhcp_limit` /
  `policy.dns_limit`) instead of being lowered to the ceiling. Pass the
  constant itself to ask for the widest limit.

## CLI-owned output types

`packetcraftr_cli::output` types no longer embed library types, except the
versioned `packetcraftr.packet` document (`document::Packet`) and its
`FieldValue`s. Each other field is a CLI-owned type with the same JSON shape,
so the published JSON is unchanged. Common replacements:

| Library type | Output type |
| --- | --- |
| `packetcraftr::Stats` | `output::envelope::Stats` |
| `core::diagnostic::{Diagnostic, Severity}` | `output::diagnostic::{Diagnostic, Severity}` |
| `core::error::Coordinate` (in `envelope::Error.context`) | `output::envelope::ErrorContext` |
| `core::layout::PacketLayout`, `core::frame::Direction` | `output::frame::{Layout, Direction}` |
| `netio::interface::Id`, `link::Mode`, `route::{Scope, SelectionReason}` | `output::network::{InterfaceId, LinkMode, Scope, SelectionReason}` |
| `netio::capture::{Statistics, RealizedSettings}` | `output::capture::{Stats, RealizedSettings}` |
| `core::analysis::{scope::Definition, ClockReport, StreamTransport, Endpoint, StreamRef}` | `output::analysis::{Scope, Clock, StreamTransport, Endpoint, StreamRef}` |
| `packetcraftr::probe::{Transport, ProbeStatus}` | `output::probe::{Transport, ProbeStatus}` |
| `packetcraftr::fuzz::CaseOutcome`, `core::fuzz::Strategy` | `output::fuzz::{Outcome, Strategy}` |

Every conversion is a `From` or `TryFrom` impl. A conversion whose source also
carries diagnostics or totals yields `output::envelope::Published<T>`
(`result`, `diagnostics`, `stats`), which `Envelope::published` and
`StreamEncoder::{emit_published, complete_published}` publish:

| Before | After |
| --- | --- |
| `send::Report::try_from_report(r)` → `(report, diagnostics, stats)` | `Published::<send::Report>::try_from(r)` |
| `scan::Event::try_from_scan(e)` → `(event, diagnostics)` | `Published::<scan::Event>::try_from(e)` |
| `scan::Event::complete_from_scan(s)` | `Published::<scan::Event>::from(s)` |
| `fuzz::Report::try_from_offline(r)` / `try_from_live(r)` | `Published::<fuzz::Report>::try_from(r)` |
| `build::Report::from_built(b)` | `Published::<build::Report>::from(b)` |
| `dissect::Report::from_decoded(d)` + `AggregateResult::new` | `Published::<dissect::AggregateResult>::from((matched, d))` |
| `frame::Captured::try_from_frame(f)`, `Wire::new(b)` | `Captured::try_from(f)`, `Wire::from(b)` |
| `read::Frame::try_from_frame(n, f)` / `try_from_decoded(n, f, &d)` | `read::Frame::try_from((n, f))` / `try_from((n, f, &d))` |
| `stats::Report::try_from_report(t, r, n)` | `stats::Report::try_from((t, r, n))` |
| `follow::Report::from_summary(transport, index, s, chunks, &ip, written)` | `follow::Report::try_from((stream_ref, s, chunks, &ip, written))` |
| `replay::Report::from_summary(s, interface, mode, frames)` | `replay::Report::try_from((s, Option<interface>, mode, frames))` |
| `verify_forwarding::Report::from_report(&r, paths)` | `Report::try_from((&r, Sided<(path, source, filter)>, decode))` |
| `interfaces::Report::new(infos)`, `merge::Report::new(path, r)` | `Report::from(infos)`, `Report::from((path, r))` |

The other command outputs follow the same pattern (exchange, traceroute, dns,
tls, expert, http, dns-read, export, rewrite, fragment, projection,
protocols, routes, plan, and resource workers). The fuzz campaign coherence
check moved to `packetcraftr::fuzz::Totals`; `contract::Error::IncoherentFuzzEvents`
wraps its `fuzz::IncoherentReport` source. A library value the published
contract has no spelling for (a future variant of a `non_exhaustive` enum)
fails with `contract::Error::Unpublished` (`internal.error`), except an error
coordinate, which is omitted like other optional error metadata.

## Flat core facade

Every core item has one documented public path, and no other crate uses a
hidden core item. Nested public modules remain only for sub-domains with
their own vocabulary (`analysis::{dns, http, tls, stats, ...}`,
`analysis::reassembly::{ip, tcp}`, `capture_file::compression`, the
`protocol` groups and `protocol::{builtin, headers, semantics}`) and for the
constant namespaces `network::ip_protocol` and `tls::extension`.

| Removed | Use instead |
|---|---|
| `packet::link::{MacAddress, VlanKind, VlanTag}` | `packet::{MacAddress, VlanKind, VlanTag}` |
| `dns::name::decompress(message, offset, max_pointers)` | `dns::decode_name(message, offset, DecodeLimits { max_name_pointers, .. })`, which returns `(Name, resume)`; `Name::labels()` gives the label octets |
| `dns::name::{MAX_LABEL_LEN, MAX_NAME_LEN}` | `dns::{MAX_LABEL_LEN, MAX_NAME_LEN}` |
| `dns::read_u16` | read the two bytes yourself; `dns::Error::TruncatedField` stays public |
| `layer::raw_layout(len)` | `layer::Raw::layout(len)` |
| `protocol::QuotedIcmpError` | `protocol::IcmpErrorKind` (same variants) |
| `protocol::QuotedProbeTransport` | `protocol::QuotedTransport` (same variants) |
| `protocol::quoted_icmp_error_kind` | `protocol::quoted_icmp_error` |
| `packetcraftr_core::display_via_as_str!(T)` | `impl Display for T` writing `self.as_str()` |
| `frame::GlobalInterfaceId` | `u32` |
| `transform::Error::Invalid(&str)` | `transform::Error::Invalid(transform::InvalidInput)` |
| `transform::Error::Unsupported(&str)` | `transform::Error::Unsupported(transform::Unsupported)` |
| `transform::Error::Limit { field: &str, limit }` | `transform::Error::Limit { field: transform::Limit, limit }` |
| `fuzz::Error::InvalidLimit { reason: String, .. }` | `fuzz::Error::InvalidLimit { reason: fuzz::Constraint, .. }` |
| `fuzz::Error::InvalidTarget { message: String, .. }` | `fuzz::Error::InvalidTarget { reason: fuzz::TargetFault, .. }` |
| `fuzz::Error::InvalidBasePacket { message: String }` | `fuzz::Error::InvalidBasePacket { reason: fuzz::BaseFault }` |

`reflective_layer!` (exported at the crate root), `layer::ReflectiveField`,
`layer::Refusal`, and `layer::{reflect_get, reflect_set, reflect_set_bounded}`
are now documented API for declaring custom layers; their signatures are
unchanged. `protocol::transport_tuple_reversed` is documented as well.

Every typed reason renders the text the message carried before, so error
messages, classification codes, and published output are unchanged.

## Route planning in packetcraftr

Route planning interprets packets, so it moved out of netio (ADR 0001). netio
keeps the route contract a provider implements; `packetcraftr::route` plans
and materializes routes over it.

| Removed | Use instead |
|---|---|
| `packetcraftr_netio::route::plan` | `packetcraftr::route::plan` |
| `packetcraftr_netio::route::{Plan, Options, Error}` | `packetcraftr::route::{Plan, Options, Error}` |
| `packetcraftr_netio::route::{materialize, Materialized}` | `packetcraftr::route::Materialized`; the `Client` materializes admitted plans (see below) |
| `Materialized::for_prepared_layer2_frame(..)` | build a `route::Decision` and a `transmit::Route` view directly |
| `transmit::{Frame, Layer2Frame, Layer3Frame}::try_new(bytes, &materialized)` | `try_new(bytes, materialized.transmit_route())` |
| `frame.route().plan.decision`, `.plan.mode`, `.plan.lookup_destination` | `frame.route().decision`, `.mode`, `.lookup_destination` |

`packetcraftr_netio::route::{Provider, Decision, Scope, SelectionReason,
SystemProvider, SystemError}` are unchanged, and so are variant names,
messages, and classification codes. `Client::plan` and `send::Options::plan`
use the `packetcraftr::route` types.

`SystemProvider` checks a preferred source's address family once, before any
native backend runs, and still reports `SystemError::SourceFamilyMismatch`
(`io.route_selection`).

## Neighbor resolution in packetcraftr

Neighbor resolution is active discovery composed from transmission and
capture, so it moved out of netio (ADR 0001). The `Client` resolves neighbors
itself, over the transmit and capture providers it already holds, and only
while materializing a route that policy has admitted. The CLI no longer
composes a second I/O stack for it.

| Removed | Use instead |
|---|---|
| `packetcraftr_netio::neighbor::{Error, Request, Resolution, Options}` | `packetcraftr::neighbor::{Error, Request, Resolution, Options}` |
| `packetcraftr_netio::neighbor::{Resolver, ActiveResolver, SystemResolver}` | nothing: the `Client` resolves over its own I/O |
| `Client<R, N, I>`, `Client::new(registry, routes, neighbors, io, policy)` | `Client<P>`, `Client::new(registry, policy, providers)`; see [Client model](#client-model) |
| `ActiveResolver::try_new(layer2, capture, options)` | `client.with_neighbor_options(options)?` |
| `probe::ExchangeExecutor<'a, R, N, I>` | `probe::ExchangeExecutor<'a, P>` |
| `packetcraftr::route::materialize(plan, &resolver, deadline)` | none; `Client` send and exchange methods materialize admitted plans |
| `packetcraftr_netio::link::MAX_VLAN_TAGS` | `packetcraftr::route::MAX_VLAN_TAGS` |

The client resolves over its transmit and capture providers, for
`Client::send` too, since a Layer 2 send may resolve a neighbor. A capture
fake for Layer 3 sends only can implement `arm_capture` as unreachable; a fake
that scripts resolution answers the ARP or NDP request it is sent through the
capture session armed for it.

`with_neighbor_options` validates the options (`cli.neighbor_limit` on
failure) and starts a fresh cache. Every operation of one client shares that
cache. Variant names, messages, and classification codes are unchanged.

## Interface enumeration errors

`interface::Provider::interfaces` returns `packetcraftr_netio::interface::Error`
instead of `packetcraftr_netio::Error`, so enumeration no longer shares an
error type with other live I/O.

| Before | After |
|---|---|
| `Err(Error::Unsupported { message, source: None })` | `Err(interface::Error::Unsupported(Unsupported::new(NativeCapability::InterfaceEnumeration, message)))`; see [netio error convention](#netio-error-convention) |
| `Err(Error::InterfaceDiscovery { message, source })` | `Err(interface::Error::Discovery { message, source })`; `source` is a required `packetcraftr_core::error::Source` |

Messages and classification codes are unchanged. `packetcraftr_netio::Error`
implements `From<interface::Error>`, so `?` still converts an enumeration
failure into a live I/O failure. A test fake that returned
`InterfaceDiscovery { source: None }` supplies a source, for example
`Source::new(std::io::Error::other("fixture"))`.

## One provider contract shape

Every netio capability is `<capability>::Provider` with a
`<capability>::SystemProvider`, and every provider trait has `Send + Sync`
supertraits.

| Before | After |
|---|---|
| `transmit::Sender` | `transmit::Provider` (same `send` method) |
| `transmit::Frame` | `transmit::Outbound` (same variants and methods) |
| `transmit::{Layer2Sender, Layer3Sender}` | `transmit::Provider`; match `Outbound::Layer2`/`Outbound::Layer3` inside `send` |
| `ModeSender::new(SystemLayer2, SystemLayer3)` | `transmit::SystemProvider` |
| `SystemLayer2.send_layer2(frame)` | `transmit::SystemProvider.send(Outbound::Layer2(frame))` |
| `route::Provider::classify_error(&error)` | `error.classification()`; `type Error` must implement `Classified` |
| `tcp::Provider` (no bounds), `tcp::Stream: Read + Write` | `tcp::Provider: Send + Sync`, `tcp::Stream: Read + Write + Send` |

`transmit::SystemProvider` sends through the backend built for the frame's
layer. A layer this build does not include fails with
`Error::Unsupported` (`capability.unsupported`), as `SystemLayer2` and
`SystemLayer3` did.

A route provider that cannot fail keeps `type Error = Infallible`, since core
implements `Classified` for it. A provider with its own error type implements
`Classified` for it and chooses the code that `classify_error` returned
before; the old default was `io.route` (`Kind::Io`). A fake whose error was
`std::io::Error` needs a local error type, because `Classified` is a core
trait. A TCP fake that counted calls in a `Cell` uses an atomic instead.

## Capture groups as sessions

`capture::Group` is a composite `capture::Session`, so single and grouped
capture share one contract. The `capture::group` module is private.

| Before | After |
|---|---|
| `capture::group::{Request, Source, Phase, MAX_SOURCES}` | `capture::{GroupRequest, Source, Phase, MAX_SOURCES}` |
| `Group::arm(&provider, &request, cancellation)?` | `let mut group = Group::new(&request)?; group.arm(&provider, &deadline)?;` |
| `group.wait_ready(timeout)` | `group.wait_ready(&deadline)` (`capture::Session`) |
| `group.next_record(timeout)` returning `Record { source, captured }` | `group.next_captured_frame(&deadline)` (`capture::Session`); the record's `source` field is the source index |
| `group.shutdown()` returning `Vec<Source>` | `group.shutdown()` returning `()`, then `group.snapshot()` |
| `group.shutdown_attempted()` | none; `shutdown` is safe to call after a failure and repeats its outcome |
| `group::Error { sources, .. }` | `group.snapshot()`, readable after any failure, including an arming failure |
| `group::Error { cleanup, .. }` | the `Err` of the following `group.shutdown()` |
| `group::Cause::Invalid(reason)` | `Error::InvalidCaptureGroup { reason }` (`cli.capture_group`) |
| `group::Cause::Configuration(error)` | `error` itself |
| `group::Cause::Provider(Failure { index, interface, phase, source })` | `Error::CaptureSource { index, interface, phase, source }` |
| `group::Cause::Contract { index, message }` | `Error::CaptureSourceContract { index, reason }` (`internal.capture_group`) |
| `group::Cause::State` | `Error::CaptureGroupState` (`internal.capture_group`) |

`Error` is `packetcraftr_netio::Error`. When stopping fails for more than one
source, `shutdown` returns `Error::CaptureCleanup { first, remaining }`,
classified as `first`, whose `causes()` list every failure. A group source
failure's message names the source and phase; the source's own failure is its
`#[source]` and decides the classification.

`capture::Session` gains `source_count` (default 1) and `source_metadata`
(default: `metadata()` for source 0), and `Captured` gains a public `source`
field, set to 0 by its constructors. Existing single-source session fakes need
no change. A group reports its first source through `metadata()`.

`capture::Request::validate` checks limits, native settings, and the
`capture::MAX_FILTER_BYTES` (64 KiB) filter limit. `capture::SystemProvider`
runs it before opening an interface, and groups apply the same limit, so an
oversized filter fails with `Error::CaptureFilterTooLong`
(`cli.capture_filter`) either way.

In `packetcraftr`, `capture::Cause::Native` holds `packetcraftr_netio::Error`
(was `Box<group::Error>`), `capture::Error::cleanup` is
`Vec<packetcraftr_netio::Error>` (was `Vec<group::Failure>`), and
`scan::PipelineError::cleanup` is `Option<Box<packetcraftr_netio::Error>>`.

## One deadline convention for providers

Every provider call that can block takes the caller's core
`packetcraftr_core::budget::Deadline` by reference. The deadline carries the
caller's cancellation, so there is no separate cancellation argument. A
provider checks cancellation first, treats a zero remainder as expired, and
never waits past the remainder.

| Before | After |
|---|---|
| `route::Provider::lookup_with_preferences(destination, hint, source)` | `lookup_with_preferences(destination, hint, source, &deadline)` |
| `route::Provider::lookup_interface(&interface)` | `lookup_interface(&interface, &deadline)` |
| `interface::Provider::interfaces()` | `interfaces(&deadline)` |
| `capture::Provider::arm_capture(&request)` | `arm_capture(&request, &deadline)` |
| `capture::Provider::timestamp_types(&interface)` | `timestamp_types(&interface, &deadline)` |
| `Session::wait_ready(timeout)` | `wait_ready(&deadline)` |
| `Session::next_captured_frame(timeout)` | `next_captured_frame(&deadline)`; a spent deadline takes only what is queued |
| `capture::Cancellable::new(session, cancellation)` | the session itself; pass `Deadline::new(timeout).with_cancellation(cancellation)` to each wait |
| `Group::arm(&provider, &request, cancellation)`, `Group::wait_ready(timeout)`, `Group::next_record(timeout)` | `Group::new(&request)?`, then `arm(&provider, &deadline)`, `wait_ready(&deadline)`, and `next_captured_frame(&deadline)`; see [Capture groups as sessions](#capture-groups-as-sessions) |
| `tcp::Provider::connect(endpoint, timeout)` | `connect(endpoint, &deadline)` |
| `tcp::start_connect(provider, endpoint, timeout, cancellation)` | `start_connect(provider, endpoint, &deadline)` |
| `packetcraftr::route::plan(packet, destination, &options, &provider)` | `plan(packet, destination, &options, &provider, &deadline)` |
| `Client::plan(packet, destination, &options)` | `Client::plan(packet, destination, &options, &deadline)` |
| `replay::Transmitter::plan_frame(interface, mode, frame)` | `plan_frame(interface, mode, frame, &deadline)` |
| `neighbor::Request { deadline, .. }` | no `deadline` field; the client passes the operation deadline to resolution |

A caller that had a timeout builds the deadline from it:
`Deadline::new(timeout)`, with `.with_cancellation(Some(signal))` to share a
stop signal. A passive lookup whose operation has no deadline can use
`packetcraftr::deadline::PASSIVE_LOOKUP_TIMEOUT`, the allowance the backends
used to apply themselves.

A fake provider that ignores time takes `_deadline: &Deadline`. A fake that
recorded or slept for its timeout reads `deadline.remaining()` instead, and
one that stalls until expiry can loop on
`packetcraftr_netio::deadline::remaining(deadline)`. A system backend stopped
by the deadline reports `route::SystemError::DeadlineExceeded`,
`interface::Error::DeadlineExceeded`, or `Error::DeadlineExceeded`, all
classified `io.deadline_exceeded`; a cancelled one reports the `Cancelled`
variant (`io.cancelled`). `tcp::start_connect` refuses a spent deadline with
`tcp::Error::DeadlineExceeded` (then `ConnectError`) rather than `Timeout`, which
now means only a remainder above one hour.

## netio error convention

Every public netio error implements `Classified` and keeps its source.

**One unsupported representation.** `packetcraftr_netio::Error`,
`route::SystemError`, and `interface::Error` carry the same
`packetcraftr_netio::Unsupported`, and its capability decides the class.

| Before | After |
|---|---|
| `Error::Unsupported { message, source }` | `Error::Unsupported(Unsupported { capability, message, source })` |
| `route::SystemError::Unsupported { message }` | `SystemError::Unsupported(Unsupported::new(NativeCapability::Route, message))` |
| `interface::Error::Unsupported { message }` | `interface::Error::Unsupported(Unsupported::new(NativeCapability::InterfaceEnumeration, message))` |
| `matches!(error, Error::Unsupported { .. })` | `matches!(error, Error::Unsupported(_))` |

`NativeCapability::Route` classifies as `capability.route`, and
`InterfaceEnumeration`, `Capture`, and `Transmission(mode)` classify as
`capability.unsupported`. Messages are unchanged: a route capability reads
"native route selection is unavailable: ...", and every other capability
reads "live packet I/O is unavailable: ...". All three error types implement
`From<Unsupported>`, so `Unsupported::new(capability, message).into()` builds
any of them.

**Type-erased sources.** `packetcraftr_netio::SystemFault` is removed. Use
`packetcraftr_core::error::Source`: `Some(Source::new(error))` in place of
`Some(Arc::new(error))`. A `Source` field exposes the wrapped error itself, so
`error.source().and_then(|source| source.downcast_ref::<std::io::Error>())`
reaches it without first unwrapping an `Arc`. `packetcraftr::dns::tcp::Error`
source fields use the same type.

**`tcp::Error`.** `tcp::ConnectError` is renamed `tcp::Error`, and it also
replaces the `io::Result` the TCP contract returned.

| Before | After |
|---|---|
| `fn connect(&self, endpoint, &deadline) -> io::Result<Self::Stream>` | `-> Result<Self::Stream, tcp::Error>`; `?` converts an `io::Error` into `tcp::Error::Socket` |
| `ConnectOutcome::result: io::Result<Connection<S>>` | `Result<Connection<S>, tcp::Error>` |
| `tcp::ConnectError::Capacity { .. }` and the other variants | `tcp::Error::Capacity { .. }`, same variants and codes |
| a socket failure's `io::Error` | `tcp::Error::Socket(io_error)`, classified `io.tcp_connect` |
| a connect the worker stopped before its provider ran: `io::ErrorKind::TimedOut` or `Interrupted` | `tcp::Error::DeadlineExceeded` or `tcp::Error::Cancelled` |

A fake provider that returned `Err(io::Error::from(kind))` returns
`Err(io::Error::from(kind).into())`. The connect scan still publishes the
socket error's kind and OS code: it reads them from `tcp::Error::Socket`, and
it reports a deadline that stopped the connection as `TimedOut` and a
cancellation as `Interrupted`.

**Messages.** Native libpcap and Npcap failures keep the status and
diagnostic text as their source, so that text appears in `causes` rather than
in the message. `tcp::Error::{Evidence, Spawn}`, `Error::InvalidSendEvidence`,
and `SendEvidenceFault::UnrepresentableFrame` also no longer repeat their
source in their message. `SendEvidenceFault` implements `Classified`
(`internal.live_io_invariant`).

## Policy error and workflow names

**One policy error.** `Policy::authorize` returns `policy::Error` instead of
`packetcraftr::Error`, and `policy` no longer uses the crate error at all.
`packetcraftr::Error::Policy(policy::Error)` still wraps it for preparation
failures. `policy::Error` no longer implements `Clone`, `PartialEq`, or `Eq`;
compare with `matches!`.

| Before | After |
|---|---|
| `packetcraftr::Error::UnsupportedOperation { authorizer, operation }` | `policy::Error::UnsupportedOperation { authorizer, operation }` |
| `packetcraftr::Error::Wire(decode_error)` | `policy::Error::UndecodableWire { source: decode_error }` |
| `packetcraftr::Error::PermissiveLiveOptInRequired` | `policy::Error::PermissiveLiveOptIn` |
| `matches!(policy.authorize(op), Err(packetcraftr::Error::Policy(policy::Error::PacketLimit { .. })))` | `matches!(policy.authorize(op), Err(policy::Error::PacketLimit { .. }))` |

A preparation failure from these reports `packetcraftr::Error::Policy(..)`
with the same code as before (`internal.unsupported_operation`,
`policy.invalid_packet_semantics`, `policy.permissive_live_opt_in`).

**Limits and budgets.** The ceilings an operation declares for policy to
authorize are limits; the running allowances charged against them keep
`Budget` (`policy::CaptureBudget`).

| Before | After |
|---|---|
| `policy::WireBudget` | `policy::WireLimits` |
| `policy::SocketBudget` | `policy::SocketLimits` |
| `policy::BudgetOverflow` | `policy::LimitOverflow` (code still `policy.budget_overflow`) |
| `dns::Error::BudgetOverflow` | `dns::Error::LimitOverflow` |
| `policy::Operation::Budgeted(limits)` | `policy::Operation::Wire(limits)`; `Operation::shape()` reports `"wire"` |
| `Operation::budget()`, `DnsOperation::budget()`, `SocketOperation::budget()`, `DeclaredPackets::budget()`, `ReplayFrame::budget()` | `limits()` on each |

**Stats.** Counter types are named `Stats`. Serialized field names are
unchanged.

| Before | After |
|---|---|
| `packetcraftr_netio::capture::Statistics` | `packetcraftr_netio::capture::Stats` |
| `capture::Session::statistics()` (and every implementation) | `capture::Session::stats()` |
| `packetcraftr::scan::connect::Statistics` | `packetcraftr::scan::connect::Stats` |

**One duration ceiling.** Each workflow's duration and timeout ceiling
restated `packetcraftr_netio::capture::MAX_TIMEOUT` (one hour). The aliases
are removed; use that constant.

| Removed | Use instead |
|---|---|
| `scan::MAX_DURATION`, `traceroute::MAX_DURATION`, `dns::MAX_DURATION`, `fuzz::MAX_DURATION` | `packetcraftr_netio::capture::MAX_TIMEOUT` |
| `replay::MAX_REPLAY_DURATION`, `send::MAX_SEND_DURATION`, `exchange::MAX_EXCHANGE_TIMEOUT` | `packetcraftr_netio::capture::MAX_TIMEOUT` |

`packetcraftr_core::fuzz::MAX_DURATION`, the offline campaign ceiling, is
unchanged.

## Execution seams and probe errors

**Scan and traceroute errors.** `probe::Error { workflow, kind }` and
`probe::ErrorKind` are gone; each workflow reports its own enum whose variants
are the former kinds. `probe::Workflow` is no longer public.

| Before | After |
|---|---|
| `probe::Error::new(Workflow::Scan, ErrorKind::Clock { sequence, source })` | `scan::Error::Clock { sequence, source }` |
| `matches!(error.kind, ErrorKind::InvalidLimit { .. })` on a scan error | `matches!(error, scan::Error::InvalidLimit { .. })` |
| the same for a traceroute error | `traceroute::Error::…` |
| `scan::connect::run` returning `probe::Error` | `scan::Error` |

Scan-only kinds (`TargetSelection`, `PipelineExecution`) exist only on
`scan::Error`, and `InvalidSourcePort` only on `traceroute::Error`. Codes,
messages, remediations, probe-sequence coordinates, and causes are unchanged.

**One event sink.** `packetcraftr::Sink<E>` is the contract for receiving a
workflow's events: `type Ack` (what the sink answers per event) and
`fn publish(&mut self, event: E) -> Result<Self::Ack, BoundaryError>`. Every
`FnMut(E) -> Result<A, BoundaryError> + Send + 'static` closure is a sink, so
existing closures and boxed callbacks still work. Because the entry points now
bound `S: Sink<Event, Ack = ()>` rather than a closure signature, a closure
that relied on that signature for its argument type names it:

```rust
// Before
scan::run_with_events(&request, &mut authorizer, &registry, &mut executor, &mut clock, &runtime, |event| { /* ... */ Ok(()) })?;
// After
scan::run_with_events(&request, &mut authorizer, &registry, &mut executor, &mut clock, &runtime, |event: scan::Event| { /* ... */ Ok(()) })?;
```

The same applies to `scan::connect::run_with_events` (`scan::connect::Probe`),
`traceroute::run_with_events`, `dns::run_with_events`,
`dns::run_batch_with_events`, `fuzz::run_with_events` (`fuzz::Case`), and
`fuzz::run_offline_with_events` (`packetcraftr_core::fuzz::Case`).

`progress::Sink<T>` is renamed `progress::Worker<T, A = ()>`: the worker thread
a runtime admits. Its callback returns `Result<A, BoundaryError>`, and
`emit` returns that `A`. Name the answer type when the callback never returns
`Ok` (for example `Worker::<()>::new_in(&runtime, |_| Err(error))`).

**Evidence errors.** `packetcraftr::ExchangeEvidenceError` is public. It names
why an executor's evidence disagrees with its step, including the new
`PermitMismatch`, and its `Display` is workflow-neutral.

**Port helpers.** `probe::EPHEMERAL_SOURCE_PORT_BASE` and
`probe::ephemeral_source_port` are no longer public. The dynamic range starts at
49152 (IANA); choose source ports in your own code.

## Client model

The `Client` owns every provider a workflow reaches the network through, and
workflows run as client methods that take a request and a sink.

**Composition.** `Client<P, K = SystemClock>` holds a `Providers` bundle.
`ProviderSet { route, interface, capture, transmit, tcp, resolver }` composes
six providers, and `ProviderSet::system()` (the `SystemProviders` alias)
selects the native ones. `packetcraftr_netio::PacketIo` is removed: transmit
and capture are separate fields.

| Before | After |
|---|---|
| `Client::new(registry, routes, PacketIo::new(sender, capture), policy)` | `Client::new(registry, policy, ProviderSet { route: routes, interface, capture, transmit: sender, tcp, resolver })` |
| `Client<R, I>` | `Client<P>` or `Client<P, K>` with `P: Providers`, `K: Clock` |
| `client.with_progress_runtime(runtime)`, `client.progress_runtime()` | `client.with_runtime(runtime)`, `client.runtime()` |
| a clock passed per call (`send_set_driven(.., clock, ..)`) | `client.with_clock(clock)` |
| `probe::ExchangeExecutor::new(&client, exchange_options)` | `probe::ExchangeExecutor::new(&client, send_options, collection)` |
| `ExchangeExecutor::with_dns_tcp` on `ExchangeExecutor<'a, R, I>` | the same on `ExchangeExecutor<'a, P, K>` |

A provider the workflow does not use is never called, so a composition may
fill it with the system provider. Fakes shared between transmit and capture
implement `Clone` and fill both fields.

**Send.** One entry point replaces `send`, `send_set`, `send_set_with_events`,
and `send_set_driven`:

```rust
// Before
let report = client.send_set_with_events(&template, set_options, |frame| { /* ... */ Ok(()) })?;
// After
let collector = send::Collector::default();
let report = client.send(
    send::Request { repeat, rate, ..send::Request::new(template, send_options) },
    collector.clone(),
)?;
let aggregate = collector.finish(report)?; // every SentFrame, as SetReport held them
```

`send::Request::packet(packet, options)` sends one packet once;
`Request::validate` and `Request::packet_count` replace `SetOptions::validate`
and `validate_for`. Events are `send::Event::Sent(SentFrame)`, published on a
runtime worker; the send waits for each answer before the next transmission.
`send::Report` is the terminal `{ passes_completed, stats }`, and
`send::Aggregate` has the former `SetReport` fields. A single send's
`SentPacket` is `aggregate.sent[0].packet`.

**Exchange.** `exchange::Options` splits: the per-run fields move to
`exchange::Request { template, send, timeout, max_template_packets,
collection }`, and the capture, decode, and retention bounds form
`exchange::Collection { capture, decode, max_responses, max_unmatched_frames }`,
which workflow executors reuse for every step.

| Before | After |
|---|---|
| `client.exchange(&template, options)` | `let collector = exchange::Collector::default(); let report = client.exchange(request, collector.clone())?; collector.finish(report)?` |
| `client.exchange_with_events(&template, options, sink)` | `client.exchange(request, sink)` |
| `exchange::Summary` | `exchange::Report` |
| `exchange::Report` (every event joined) | `exchange::Aggregate` |
| `Collector::observe(event)` | `Collector` is a `Sink<Event>`; clone it and pass one clone |
| `options.validate()` | `request.validate()`, `collection.validate()` |

**Errors.** `packetcraftr::Error` is the preparation error both workflows
wrap as `send::Error::Preparation` and `exchange::Error::Preparation`. Codes
are unchanged.

| Before | After |
|---|---|
| `Error::SendOutput { source }` | `send::Error::Output { source }` (unboxed) |
| `Error::InvalidSendOption { field, message }` | `send::Error::InvalidRequest { field, message }` |
| `Error::ExchangeOutput { source }` | `exchange::Error::Output { source }` |
| `Error::ExchangeOutputAndCaptureShutdown { output, shutdown }` | `exchange::Error::OutputAndCaptureShutdown { output, shutdown }` (both boxed) |
| `Error::OperationAndCaptureShutdown { .. }` | `exchange::Error::OperationAndCaptureShutdown { .. }` |
| `Error::InvalidExchangeEvents { message }` | `exchange::Error::IncoherentEvents { message }` |
| `Error::HeterogeneousExchangeRoute` | `exchange::Error::HeterogeneousRoute` |
| `Error::InvalidExchangeOption { field, message }` | `exchange::Error::InvalidRequest { field, message }` |
| `Error::Policy(..)` from a send | `send::Error::Preparation(Error::Policy(..))` |

`send::Error` adds `IncoherentEvents` (`internal.send_event_coherence`) for a
collector finished with another run's report, and `Clock`
(`io.send_clock`) for a pacing clock that fails.

**Clock.** `Clock` is `Clone + Send + Sync + 'static`. `now` takes `&self`, and
`sleep` takes `&self` and the operation `Deadline`, returning early once the
deadline's cancellation is signaled. A fake clock shares its state behind an
`Arc` and starts from `Instant::now()`, so its deadlines and capture
timestamps share one monotonic base:

```rust
// Before
fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error>
// After
fn sleep(&self, delay: Duration, deadline: &Deadline) -> Result<(), Self::Error>
```

`Clock::cancellation` and `CancellableClock` remain for the free workflow
entry points.

**Interface selectors.** `route::Options.interface` is an
`Option<route::Interface>`: `Interface::Id(id)` for an identity a provider
confirmed, or `Interface::Name`/`Interface::Index` for a selector the client
resolves through its interface provider after admission, so a refused
operation never enumerates interfaces. An unmatched selector fails with
`route::Error::UnknownInterface` (`io.device`) and an enumeration failure with
`route::Error::InterfaceDiscovery`. The free `route::plan` takes only
`Interface::Id` and reports `route::Error::UnresolvedInterface` otherwise.

**Target resolution.** `Authorizer::resolve_and_authorize` moves to its own
trait, `target::ResolveTarget`. An authorizer that resolved targets implements
both; one that relied on the failing default drops it. DNS, scan, connect
scan, and traceroute entry points require `A: Authorizer + ResolveTarget`.

```rust
// Before
impl Authorizer for Gate {
    fn authorize_operation(&mut self, op: Operation<'_>) -> Result<(), BoundaryError> { /* ... */ }
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> { /* ... */ }
}
// After
impl Authorizer for Gate {
    fn authorize_operation(&mut self, op: Operation<'_>) -> Result<(), BoundaryError> { /* ... */ }
}
impl ResolveTarget for Gate {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> { /* ... */ }
}
```

## Scan and traceroute on the client

Scan and traceroute are client methods that take a request and a sink, like
send and exchange. The request carries the route and collection bounds the
`ExchangeExecutor` held before, and the client supplies the policy, registry,
clock, runtime, and cancellation.

| Before | After |
|---|---|
| `scan::run(&request, &mut authorizer, &registry, &mut ExchangeExecutor::new(&client, send, collection), &mut clock)` | `let collector = scan::Collector::default(); let report = client.scan(request, collector.clone())?; collector.finish(report)?` |
| `scan::run_with_events(&request, .., &runtime, sink)` | `client.scan(request, sink)` (the client's runtime publishes) |
| `traceroute::run(..)`, `traceroute::run_with_events(..)` | `client.traceroute(request, collector.clone())`, `client.traceroute(request, sink)` |
| `scan::Summary`, `traceroute::Summary` | `scan::Report`, `traceroute::Report` |
| `scan::Report`, `traceroute::Report` (every event joined) | `scan::Aggregate`, `traceroute::Aggregate` |
| `send.plan` of the executor's `send::Options` | `request.route` |
| the executor's `exchange::Collection` | `request.collection` |
| `scan::PipelineError` | `scan::PipelineFailure` |
| `scan::ResponseClassification`, `traceroute::ResponseClassification` | `scan::CorrelatedResponse`, `traceroute::CorrelatedResponse` |
| `traceroute::Completion`, `report.completion` | `traceroute::Termination`, `report.termination` |
| `scan::Batch`, `traceroute::Batch` | removed; executors are internal |

```rust
// Before
let mut send = send::Options::default();
send.plan.link_mode = Mode::Layer3;
let report = scan::run(
    &request,
    &mut PolicyAuthorizer::for_packets(&policy),
    &registry,
    &mut ExchangeExecutor::new(&client, send, collection),
    &mut SystemClock,
)?;
// After
let request = scan::Request {
    route: route::Options { link_mode: Mode::Layer3, ..Default::default() },
    collection,
    ..request
};
let collector = scan::Collector::default();
let report = client.scan(request, collector.clone())?;
let aggregate = collector.finish(report)?;
```

The duration limit and every pacing delay are anchored on the client's clock,
and its cancellation stops the run; a `CancellableClock` is no longer needed.
`Request` values are no longer serde types, because the route and collection
bounds are not.

**Pipelining.** `max_in_flight` alone selects how a scan runs: one runs each
probe as its own exchange, and up to `scan::MAX_IN_FLIGHT` overlap their
response windows over one capture group. `probe::Executor` no longer has
`pipeline_capacity` or `execute_pipeline`, and `probe::{PipelineOptions,
PipelineEvent}` are gone. An `Executor` implementation that only forwarded
them deletes those methods.

**Errors.** `scan::Error` and `traceroute::Error` add `IncoherentEvents`
(`internal.scan_event_coherence`, `internal.traceroute_event_coherence`) for a
collector finished with another run's report. Other codes are unchanged; a
pipeline failure still reaches the caller as
`scan::Error::PipelineExecution`, whose source chain holds the
`scan::PipelineFailure` with the pending evidence.
