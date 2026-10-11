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
| Command JSON/NDJSON | `packetcraftr.output/v2` | `packetcraftr.output/v12` |

Update consumers explicitly; older packet documents are rejected. Output v6–v11
schemas remain frozen for previously emitted evidence, not as current producer
versions. Never relabel old evidence as v12. The [consumer policy](consumer-compatibility.md)
defines strict envelopes/enums, extensible result records, sequence/terminal rules,
and each retained output family's additions. Keep schemas, examples, and release
assets from the same revision.

## Service identification

`identify` is an explicit operation; scans do not invoke it. Consumers gain the
`identify` command and endpoint records in output/v12. Observed claims are
unauthenticated, candidates cite matching evidence and corpus provenance, and
unknown or ambiguous results never assert exact versions. See
[identification controls](service-identification.md) and the
[v12 contract](consumer-compatibility.md#output-family-v12).

## Adaptive scheduling

Fixed scheduling remains the default; adaptive tuning flags require
`scan --adaptive`. Rust `scan::Request` gains `adaptive: Option<scan::Adaptive>`;
use `None` to retain fixed scheduling. Raw/connect reports and aggregates gain
`scheduling`, and `scan::discovery::Scan` gains `Incomplete`. Handle that state
when a host deadline prevents intended work; never-sent attempts carry no probe
evidence. Netio `tcp::ConnectBudget` leases remain held until worker/socket cleanup.
See the [scheduling contract](consumer-compatibility.md#output-family-v10),
introduced in v10 and retained in current v12.

## Forwarding verification

`verify-forwarding` is new since beta.3. Missing fields do not satisfy ordinary
preservation: use explicit presence/absence checks. Read evidence states and the
terminal verdict, not just retained details. [Verification semantics](verification-contract.md)
is the authoritative reference.

Rust `Observation` fields are private; construct observations through collectors
and read them through getters. `verify` returns `forwarding::Error`;
`verify_with_limits` accepts independent detail/scratch budgets and a shared
deadline. Omission counts do not change verdicts.

## Offline HTTP/2 analysis

The new `http2` command and core collector inspect cleartext prior-knowledge
and h2c upgrades; `http` remains HTTP/1-only. Handle `Command::Http2` in exhaustive
CLI contract matches. HTTP/2 is not a stateless recipe or decode-as codec;
select services with `--http2-port`. TCP conversation `stream` and
`http2_stream_id` are distinct. Read final connection assessments and later
issues as well as messages; TLS decryption and HTTP/3 remain unsupported.
See [capture investigation](tasks.md#2-investigate-a-capture-without-losing-evidence)
and [HTTP/2 limits](analysis-resources.md#http2-limits).

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

Packet/v2 adds named object values (`{name=value}` in expressions). Nested paths
such as `questions[0].name` work in reflection, templates, filters, and fuzzing;
object keys/members share finite payload, item, nesting, and node budgets.

Replace `Dns::{qnames,qtypes,qclasses}` with `questions: Vec<Question>`; reflected
read-only singular views remain. Section counts are `WireValue<u16>` and
`Dns::edit` resets them to `Auto`. Untouched decoded DNS preserves its exact wire
image, including compression; structured edits re-encode names uncompressed and
leave unknown RDATA opaque rather than relocating embedded pointers.

DNS `query_type` serializes as an integer `0..=65535`, not an alias string
(`"aaaa"` becomes `28`). Rust `dns::QueryType` stores a numeric code: use
`new(code)`, `.code()`, uppercase constants (`AAAA`, `ANY`), and a fallback for
unknown codes. `.as_str()` is removed; use `Display`. CLI `--type` accepts names,
decimal numbers, or `TYPE<n>`. Parsing returns `dns::wire::Error` with the
original integer error where applicable.

## Packet templates and UDP scan payloads

`Template::axis` adds to a Cartesian product instead of replacing the prior axis;
the last varies fastest and duplicate fields/aliases fail. Use
`expansion_len()?`, handle overflow, and pass a finite bound to `expand(maximum)`.
An axisless template contains one packet; an empty axis produces none (the CLI
rejects empty sets). Multi-packet builds use text, hex, NDJSON, or capture output;
JSON and raw remain single-packet formats.

Selectors accept `<protocol>[#occurrence].<field>` or a zero-based layer index.
`Target::select` / `payload::Target::resolve` accept named selectors; numeric
`FromStr` paths remain. `expression::Limits` gains `max_generated_bytes` for
`repeat`, `zeros`, and `cyclic`; add it to literals or use defaults.

Boundary fuzz values now derive from the target field's accepted width; re-record
stored Boundary seeds/indexes. Other strategies retain their reproduction rules.
The round-trip oracle adds `fuzz.roundtrip_*` diagnostics, distinguished by
`fuzz::is_roundtrip_diagnostic`.

Raw scan request/probe literals gain `udp_payload: bytes::Bytes` (empty for the
previous behavior), and probes are `Clone`, not `Copy`. Payloads above
`scan::MAX_UDP_PAYLOAD_BYTES` or nonempty TCP/ICMP payloads fail before work.

## Typed TCP options

The `Tcp` layer's `options` field is an ordered list of typed option objects
(`packetcraftr_core::protocol::transport::TcpOption`) instead of `bytes::Bytes`.
Standard options (EOL, NOP, MSS, window scale, SACK-permitted, SACK blocks, and
timestamps) reflect as `{kind: N, member: ...}` objects; unknown kinds,
nonstandard lengths, and unparseable tails stay byte-exact as `Raw`/`Trailing`
entries. Construction accepts typed objects (`options=[{kind=2,mss=1460}]`) or
verbatim bytes (`options=hex("0204 05b4")`), which parse into the same typed
form. Nested paths such as `tcp.options[0].mss` work in filters, projection,
templates, and fuzz targets. Code that read `options.as_ref()` iterates the
option variants instead.

## IPv6 reserved bits

RFC 8200 and RFC 8754 have receivers ignore an IPv6 Fragment header's reserved
byte and 2-bit Res field and a Segment Routing header's flags byte, so those
bits no longer make the layer `Malformed`. Decoding keeps them and reports
`decode.ipv6_fragment_reserved` or `decode.srh_flags`, and such fragments are
counted and reassembled. Strict builds refuse non-zero bits; permissive builds
write them and report `build.ipv6_fragment_reserved` or `build.srh_flags`. Live
authorization and response matching still refuse a Segment Routing header with
non-zero flags.

Every IPv6 Fragment layer, including one whose reserved fields are zero, now
publishes `reserved` and `reserved_bits` beside its other fields, so decoded
packets and their layouts grow two entries per fragment: `dissect`,
`read --dissect`, and `capture --dissect` output, and the field list of
`protocols ipv6_fragment` (`next_header`, `reserved`, `fragment_offset`,
`reserved_bits`, `more_fragments`, `identification`). Layout entries follow the
same order, so those after `next_header` change position. `read --field`
selects the new fields as `ipv6_fragment.reserved` and
`ipv6_fragment.reserved_bits`, where they failed with `cli.projection_field`.
Consumers that pin the exact field set of an `ipv6_fragment` layer must accept
the two additions; the `packetcraftr.packet/v2` and output/v12 shapes are
unchanged.

`packetcraftr_core::protocol::network::Fragment` gains `pub reserved: u8` (the
byte after Next Header) and `pub reserved_bits: u8` (the 2-bit Res field,
`0..=3`). Struct literals that name every field add `..Fragment::default()` (or
`reserved: 0, reserved_bits: 0`), and exhaustive destructuring patterns add
`..`; code that starts from `Fragment::default()` or uses struct update syntax is
unaffected. A `reserved_bits` above 3 fails to build in both modes.
`SegmentRoutingHeader.flags` keeps its shape: non-zero flags now decode with
`decode.srh_flags` and build permissively with `build.srh_flags`, and strict
builds still refuse them.

## DNS transport selection

Replace `dns::Request::tcp_fallback` with `transport: dns::TransportMode`:
`false` becomes `TransportMode::Udp`, `true` becomes `TransportMode::UdpThenTcp`,
and `TransportMode::Tcp` selects direct TCP. The enum defaults to `UdpThenTcp`,
and the `DEFAULT_TCP_FALLBACK` constant is removed. Serialized requests use
`"transport": "udp"`, `"udp_then_tcp"`, or `"tcp"`. Unknown request fields,
including the obsolete `tcp_fallback`, are rejected so an old UDP-only setting
cannot silently enable TCP. `source_port` is unused in TCP-only requests.

Direct TCP runs over the client's TCP provider without executing a UDP
exchange. Its budget contains connections, framed messages, and application
bytes, with zero raw UDP cost. CLI `dns --tcp` works without native packet-I/O
features. Packet-oriented route overrides and scoped IPv6 link-local TCP remain
unsupported.

In current output, a successful TCP query reports `fallback_attempted=false`, and
successful aggregate TCP reports require a retained successful TCP attempt.
Consumers must inspect the actual attempt transport rather than infer it from
fallback. A fallback attempt keeps its preceding truncated UDP phase under the
same attempt number.

## Explicit DNS TCP providers

Native TCP sockets belong to netio (`packetcraftr_netio::tcp::{Provider,
Stream}`); `dns::tcp` keeps framing, finite deadlines, and evidence. The
`Client` queries over its own `tcp` provider (the `tcp` field of its
`ProviderSet`), and the CLI composes `packetcraftr_netio::tcp::SystemProvider`.
A composition that must never open a TCP socket fills that field with a
provider that refuses connections. The standard-library provider works
independently of native packet and route feature flags. Interface,
preferred-source, and link-mode overrides remain unsupported for kernel TCP, and
every TCP query keeps endpoint reauthorization and the final query-byte check.

Low-level callers replace `dns::tcp::exchange(request)` with
`dns::tcp::query(request, Arc::clone(&provider))`. The provider and its stream
must be `'static`, because the admitted native worker owns its `Arc<P>` until
the connect call and cleanup finish. Set `dns::tcp::Request::cancellation` to
`Some(&signal)` to interrupt the connect, write, and read waits (the write and
read waits re-check it every 25 ms), or `None` when there is no signal (the
client passes its own). `dns::tcp::Error::Cancelled { phase, transferred,
cancelled }` and `dns::tcp::Category::Cancelled` identify cancellation
(`io.cancelled`); match `Error::Cancelled { .. }`. `phase` names the interrupted
wait (`Phase::Connect`, `Write`, `ReadPrefix`, or `ReadMessage`) and
`transferred` the bytes already moved in it, so a query cancelled after it was
sent reports the query bytes it wrote in its statistics.

## Opt-in EDNS requests

`dns::Request` gains `edns: Option<EdnsRequest>`. Add `edns: None` to Rust
request literals; deserializing a request without the field defaults to `None`.
`dns::wire::encode_query(name, query_type, id, recursion_desired, edns)` takes
the option as its fifth argument, and `None` preserves the original query
bytes.

`EdnsRequest` holds `udp_payload_size: u16` in `512..=65535` and
`dnssec_ok: bool`. Version 0 is fixed. The encoder adds exactly one OPT record
with the root DNS name and no options, validating settings before I/O. All
eleven added bytes count toward UDP and framed-TCP authorization budgets, and
each TCP continuation sends the same DNS message as the UDP attempt that
triggered it.

The CLI enables EDNS with `--edns-udp-payload-size SIZE`; `--dnssec-ok` requires
that flag. DO requests DNSSEC data and performs no signature validation. The
advertised receive size is independent of `--max-message-bytes`, which bounds
response decoding. Existing output `edns` fields still describe the response;
these request settings add no fields to the output/v12 or packet/v2 contracts.

## DNS question batches and reverse names

`dns` accepts several `NAME` positionals plus repeatable `--reverse ADDRESS`
(PTR questions derived by `dns::reverse_name` under `in-addr.arpa`/`ip6.arpa`)
as one batch bounded by `dns::batch::MAX_QUESTIONS`. Questions share one
`Deadline` (the minimum `limits.max_duration`), and `--transaction-id` is
rejected for multi-question batches because identifiers are per question.
Single-question invocations keep the previous envelope and error semantics.
Batch aggregates add a `questions` array to `dnsResult` whose entries report
`completed`, `failed`, or `unattempted` in input order, and streamed batches
end with a `complete` record carrying the per-question statuses.

## Offline DNS records

Import DNS `Name`, `Record`, `RecordValue`, `Edns`, and `EdnsOption` from
`packetcraftr_core::protocol::application::dns`; `packetcraftr::dns` no longer
exports them. `Name::from_labels` returns core `dns::Error`. Name failures are
variants of `dns::Error` itself (`InvalidName`, `SelfPointer`, `PointerLoop`,
and the truncation and pointer-limit variants), keeping their offsets and the
distinction between self-pointers and pointer loops. Structural live-decoder
failures are wrapped in `dns::wire::Error::Decode(dns::Error)`; match the core
error inside that variant. Query correlation, TCP framing, and live EDNS policy
errors remain workflow-owned.

`Dns::try_from(bytes)` replaces `Dns::from_wire` and decodes all declared
records. Malformed or truncated records and trailing bytes now fail decoding
with `dns::Error`, and offline dissection retains the original payload with
malformed-packet diagnostics. `Dns::from_wire_with_limits(bytes, dns::Limits)`
is the bounded constructor, and the retained `wire()` remains the original
message, including compression and unknown bytes.

Default bounds are 65,535 message bytes, 512 records, 32 compression pointers
per name, and 256 strings / 16,384 bytes per TXT record. Absolute ceilings are
65,535 message or TXT bytes, 4,096 records or TXT strings, 128 pointers per
name, and 64 questions. Limits above a ceiling fail with `InvalidLimit`
(`policy.dns_limit`) instead of being lowered; pass the constant itself to ask
for the widest limit. Zero permits none of that resource.

DNS reflection exposes `answers`, `authorities`, and `additionals` as lists of
named `{owner, type, class, ttl, value}` objects. Replace positional record
lists with these objects. The nested `value` object selects its shape with
`kind`:

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

Ordinary typed records are decoded for the Internet (`IN`) class. Other classes
retain exact RDATA as `unknown`; their class-specific formats are not
interpreted as Internet addresses or records.

OPT records remain in their original section. Offline inspection retains
unknown EDNS versions; live queries still enforce their existing OPT version,
owner, section, and uniqueness rules. These fields fit the existing recursive
packet/v2 field contract.

## TLS hello construction

`Tls::try_from(Hello)` builds complete ClientHello and ServerHello fixture
records. The `hello` object in recipes exposes record and legacy versions,
random, session ID, cipher suites, compression methods, and ordered
`{type, data}` extensions. `Extension::server_name` and
`Extension::alpn` build the common bodies, and recipes also accept
`{server_name="example.test"}` and `{alpn=["h2"]}`. Extension bodies stay
authoritative, including unrecognized extensions; edits rederive lengths and
fingerprints, and paths such as `hello.cipher_suites[0]` or
`hello.extensions[0].data` work in templates and fuzz targets. Decoded TLS
extension models now retain `data` in place of `len`, so `Extension` literals
have only `kind` and `data` and `extension.len` becomes `extension.data.len()`.
ServerHello models retain their echoed `session_id`.

## Live capture

Repeated `--interface` selections share one capture operation and budget.
`frame.interface_id` is now the zero-based capture selection ID, not the OS
index; completion sources map back to native interfaces. Cross-interface delivery
preserves timestamps without promising order.

Completion is `output::capture::Summary`, not an empty payload; failures may carry
`error.capture` partial source/file evidence. JSON requires `--write`; rotated
files are PCAPNG and share the operation's bounds. Native settings are reported as
requested/applied/effective, with unknown effective values left null, not guessed.

Replace `output::capture::Event::try_from_frame` or its tuple conversion with
`output::read::Frame::try_from` using the same tuple. The event name remains
`frame`. Dissection/projection are opt-in text/NDJSON paths; native capture
settings unsupported by a backend fail rather than silently falling back.

## Scan requests, round-trip statistics, and UDP profiles

`scan::Request` selects targets with a bounded `target::Selection` (hosts,
CIDRs, and exclusions) in `targets`, replacing the single `target`, and gains
`max_in_flight`, `udp_payload`, `udp_profiles`, `route`, and `collection`.
`scan::Limits` gains `max_targets` and `max_prepared_bytes`. `max_in_flight`
alone selects how a scan runs: one runs each probe as its own exchange, and up
to `scan::MAX_IN_FLIGHT` overlap their response windows over one capture group.
Raw scan NDJSON adds `probe_sent` when `max_in_flight` exceeds one, and
failures then may carry `error.scan` with the confirmed pending wire; a serial
scan publishes no `probe_sent` events, only final `probe` events beside its
`undecoded`, `diagnostic`, and `complete` records.

`scan::Report` (the former `Summary`) and `scan::connect::Stats` gain `rtt`:
confirmed sends, verdicts received inside their round, `lost = sent - received`,
and min/avg/max over one sample per received probe. Rust literal constructors
supply `scan::Rtt::default()` or an accumulated value. The current output schema includes
matching `rtt` objects on scan summaries and `socket_stats`; absent duration
fields mean no response produced a sample.

`Request::udp_profiles` maps ports to validated `Arc<profile::UdpProfile>`
values (`Probe` keeps its selected profile), and `ProbeEvidence::application`
reports application validation independently of reachability. UDP profile
documents use the independent version `packetcraftr.udp-profiles/v1`, ship with
a schema and example, and load through
`scan::profile::compile(packetcraftr_core::document::udp_profiles::parse(&bytes)?)?`.
A profiles document whose `any` or `dns` response carries an unknown field, such
as `checks` or `min_length`, is refused as `invalid UDP profiles`, as the
published schema requires.

## TCP connect scanning

`client.scan_connect(scan::Request, sink)` runs kernel TCP connections through
the client's TCP provider. Events are `connect::Event::Probe(ProbeEvidence)`,
the terminal result is `connect::Report`, and `connect::Collector` rebuilds
`connect::Aggregate { report, endpoints }`. Reports use socket outcomes and
endpoint evidence, with no raw packet receipt or capture statistics, and
`policy::Operation::Socket` carries `SocketOperation` with the authorized
numeric endpoints and finite `SocketLimits`.

`connect::Report` gains `diagnostics`, including `scan.duplicate_declaration`
warnings for coalesced target declarations. CLI text, JSON, and NDJSON
completion output publish these warnings through their existing diagnostic
channels. Exhaustive report initializers must supply the new field.

`target::plan::Error::InvalidLimit` reports invalid `max_duration` values in
milliseconds, saturating at `u64::MAX` for larger durations.

Netio's `tcp::start_connect` returns a pollable `PendingConnect`: cancellation
or drop cancels unstarted calls, while admitted calls keep their process-wide
resource lease until worker and socket cleanup finish. At most
`tcp::MAX_PENDING_CONNECTIONS` (16, equal to `resources::WORKER_CAPACITY`) calls
or connections retain admission, and they share the native worker pool with
capture and route work, so fewer are admitted while that work holds slots. The
workflow caps `Request::max_in_flight` accordingly and rejects UDP and ICMP.

## Offline analysis options and results

Update exhaustive `analysis::Options` literals for `plan`, `deadline`, `stream`,
`time_bounds`, and `track_sources`; use defaults to retain ordinary reconstruction.
`analysis::Limits` gains `max_provenance_bytes` and nested TCP/IP limits.
Collectors requiring source evidence enable `tcp_events` and `track_sources`.
See [resource accounting](analysis-resources.md) for exact charges and hard stops.

`analysis::Summary` and `stats::Report` gain capture `interfaces`; stats adds
optional duration, mean packet size, packet rate, and byte rate. Empty/zero-span
results do not invent a rate. `reassembly::tcp::Event::Retransmission` gains
`ranges: Vec<Range<u32>>`; add it to constructors and use `..` in patterns.

HTTP/DNS partial messages cut off by RST now end as `reset`, with one reset issue,
not duplicate `evicted` issues. Reset payload contributes no provenance span.
DNS emitted messages and transaction tracking now share one cumulative retained
ceiling, so near-limit captures can stop earlier with `policy.application_limit`.

Update consumers of TCP expert codes: resets answering a handshake become
`tcp.connection_refused`; qualifying retransmissions become
`tcp.fast_retransmission`; filling a reported gap becomes `tcp.out_of_order`.
Established connections without a close gain `tcp.not_closed_at_end` (Info),
changing exact finding totals. Only four sequence gaps per direction are watched;
idle expiry and one-direction filters can leave handshake/close evidence incomplete.

## Display filter language

Filters gain escapes and `b"..."` byte-string literals, `field & MASK`, `A..B`
ranges, the `startswith`, `endswith`, `icontains`, and `iequals` operators,
`[*]` and `[-1]` list selectors, `#last` and `#-1` occurrences, `len()` and
`count()`, and the frame facts `frame.time_nsec`, `frame.direction`,
`frame.truncated`, `frame.layer_count`, and `frame.protocols`; `packetcraftr
topics filters` is the reference. `len` and `count` are functions only when `(`
follows the word directly, so `len (raw.bytes)` is an unknown field. Known
limits: the text operators and `contains` compile on a list of numbers or
addresses (`dns.qtype`, `tls.cipher_suites`) but never match, because the field
schema records no element kind, and they are compile errors on a list of objects
(`tcp.options`, `dns.questions`). `frame.reassembled` is not a field.
`frame.layer_count` and `frame.protocols` are decoded facts, so forwarding
verification treats them as unevaluable on a truncated or incompletely decoded
capture, and `frame.time_nsec`, `frame.direction`, and `frame.truncated` cannot
name forwarding identity or preservation fields. `verify-forwarding --expect`
values take the same literals and ranges.

## Offline epoch bounds

`read`, `stats`, `expert`, `follow`, `tls`, `dns-read`, `http`, `export`, and
`verify-forwarding` accept `--start-epoch EPOCH` and `--stop-epoch EPOCH`,
keeping only frames inside the inclusive window. Values are non-negative Unix
seconds with an optional fraction of at most nine digits, compared at full
`SystemTime` precision (`1.5000005` still selects correctly against a
microsecond-resolution capture). Reversed bounds fail with
`cli.reversed_time_bounds`; unsupported precision, including fractions finer
than the host's `SystemTime` representation, is rejected rather than rounded.
Frames without a timestamp are never kept while bounds are set, and frames
skipped by bounds count toward `--max-frames`/`--max-bytes`. Bounds compose with
`--filter` and do not assume capture timestamps are ordered.

In Rust, construct `analysis::Options::time_bounds` with
`frame::TimeBounds::new(start, end)`, which rejects a start after the stop.
Bounds apply at the same pipeline stage as the display filter: timestamped
physical frames still advance IP reconstruction and stream indexing whether or
not they are kept, and timestamp-less frames are skipped before that stateful
processing. All frames consume read budgets, and `analysis::Summary::bytes_read`
reports the complete captured-byte input count.

## Capture files

Normalization, rewriting, and merging now refuse a declared FCS they cannot
represent (`packet.capture_transform_metadata` or `packet.capture_merge_metadata`,
exit 3). Use `capture_file::Reader::refuse_declared_fcs` in library transforms.
Malformed PCAPNG option structure is reported before option-value errors; accepted
inputs are unchanged. See [capture fidelity](tasks.md#selecting-and-saving-evidence).

`read --normalize --output pcap` now writes classic PCAP rather than failing;
selection must be nonempty, timestamp-exact, single-interface, and carry no packet
direction. `--frames` / `--every` preserve source numbering and input-budget charges.
`merge` defaults to chronological input and fails on clock regression; use bounded
`--max-reorder-frames` or explicit `--order append`, not both. Callers tracking
`main` add `order` and `max_reorder_frames` to `MergeLimits`, preferably through
`..Default::default()`.

## Header rewriting, DHCP, and protocol discovery

`rewrite` and its versioned rules are new since beta.3; command help is the option
reference. It applies header changes, address maps, and fixed-width assignments
with explicit checksum policy, bounded changes, and staged publication.
Callers tracking `main` add `map: None` to hand-built `transform::rules::Rule`
values; document loaders and `Rules::single` already initialize it.

DHCP codecs construct bounded typed fixtures. Protocol field discovery can emit
`children_reference` instead of repeating children: resolve that JSON Pointer
against the containing top-level field description before traversal.

## Protocol coverage and bindings

New registered codecs include STP, LLDP, EAPOL, VRRP, EtherIP, GTP-U, TFTP,
and syslog; UDP 5353/5355 now bind DNS. Consumers that previously read those
payloads as `raw` should select their typed fields. TFTP DATA/ACK on ephemeral
ports needs explicit decode-as selection. `BuiltinProtocol` gains matching
variants; update exhaustive matches.

mDNS cache-flush class bits remain exact. NDP options gain typed variants and
`MessageOption` is non-exhaustive; use a wildcard and `.value()` as owned `Bytes`,
not a borrowed value. MLD/IGMPv3 helpers are not registered layers.

Analysis still does not distinguish GTP-U TEIDs or EtherIP tunnels within an
otherwise identical outer/inner tuple; such flows share scope and stream identity.

## Destination allowlists

`policy::Policy` gains `allowed_destinations: Vec<DestinationConstraint>`,
bounded by `MAX_DESTINATION_CONSTRAINTS`; add it to exhaustive literals. Each
entry is an exact IP address or a canonical CIDR network parsed by
`DestinationConstraint::from_str` (network input must spell the masked
network address). A non-empty list must contain every authorized destination at
the target, packet-declared, route-visited, and final-wire stages; an empty list
adds no constraint, and a match never substitutes for the public-destination or
other opt-ins. Denials surface as `policy::Error::DestinationNotAllowed`
(`policy.destination_not_allowed`), and malformed entries or an oversized list
classify as `cli.live_target`. The CLI exposes the list as repeatable
`--allow-destination ADDRESS[/PREFIX]` on every destination-bearing live
command; `fuzz` takes it only with `--live`, and an offline run rejects it with
a usage error naming `--live` where it used to accept and ignore it.

## Target planning and scoped IPv6

Manifests and `scan --list` use the same bounded admission as live scans. List
mode sends no target/neighbor packets; hostname resolution remains an explicit,
reported opt-in. Scope and target-list output were introduced in v7 and remain
in v12; see [consumer compatibility](consumer-compatibility.md#output-family-v7).

`scan::Request` gains `target_sources: Vec<String>`: empty for ordinal diagnostics,
or one bounded nonempty source label per included declaration. Invalid labels
fail before provider work. `Client::plan_targets` needs only `TargetProviders`.

Handle `Target::ScopedAddress` and use `Authorized::selected()` when scope matters.
`addresses()` now returns an owned `Vec<IpAddr>`, not a slice. Selection identity
is `(address, resolved interface)`; the authorized serialized shape changes.
Raw/connect scan evidence and socket/route identities retain that scope. Workflows
that cannot carry it fail before work, never silently strip it.

Raw scan/traceroute `retained_evidence_bytes` counts retained wire bytes; connect
reports charge retained probe structures/error text, not a wire transcript. Neither
is process memory. [Scanner evidence](scanner-evidence.md) defines the charges.

## Port planning and inference

`scan --ports` accepts catalog names/presets and transport-qualified selections;
exclusions apply before planning and budgets. No implicit port set is selected.
Mixed TCP/UDP plans share one operation budget; ICMP remains portless. Catalog
names are hints, not service identification.

`--method raw|tcp-connect|auto` defaults to raw; `--connect` remains an alias.
An explicitly chosen method never silently falls back. Automatic selection records
its reason. Inferred port state is distinct from attempt classification and must
retain supporting, conflicting, unanswered, and failed sequences. See the
[v8 additions retained in v12](consumer-compatibility.md#output-family-v8).

In Rust, replace separate request transport/port fields with
`endpoints: Vec<probe::ProbeEndpoint>`; each entry carries its own transport and
optional port. Replace `Request::selected_ports()` with `planned_endpoints()`;
use `scan::select_endpoints` for catalog selections (`select_ports` still handles
numeric lists). Endpoint literals gain `port_hint` and `inference`.
`ProbeEvidence` gains `reply`, raw `Aggregate` gains `unattributed`, and `Event`
gains `Unattributed`.
Port/catalog/profile documents remain independently versioned.

CLI scan serializers require the published plan rather than inferring it:
`output::scan::Report::publish` and `output::scan::connect::Report::publish` replace
plan-less conversions. Supply reverse-DNS results and optional trace data where
required; list reports take the optional expanded port selection.

## Host discovery

Discovery is opt-in (`before`, `only`, or `skip`); silence is `no_response`, not
proof of absence. Discovery and scan stages share authorization and finite budgets.
Host records and stage discriminators were introduced in v9 and remain in v12;
see [host output](consumer-compatibility.md#output-family-v9) and
[host evidence](scanner-evidence.md#host-observations).

`scan::Request` gains `discovery: scan::discovery::Options`; `Default` omits it.
An empty endpoint list is valid only for `Mode::Only`. Probes and raw/connect
`ProbeEvidence` gain `stage`; reports/aggregates gain `hosts`, and aggregates retain
discovery probes separately. `scan::Error` gains `InvalidDiscovery` and `Neighbor`;
`MethodTransport` becomes `MethodProbe { method, probe }`. `scan::method::select`
takes `&Request` so discovery participates in method choice.

## Scan traceroute

`scan --traceroute` is an opt-in raw-scan stage before reverse DNS, sharing the
remaining policy/time budgets. It selects observed responsive TCP/ICMP probes or
an explicit fallback. Reused hops retain source/age separately from this host's
observations. Connect/list modes reject the stage before work. See the
[v11 additions retained in v12](consumer-compatibility.md#output-family-v11) and
[trace evidence](scanner-evidence.md#traceroute-stage).

`traceroute::hosts` and `Client::trace_hosts` add bounded multi-host tracing;
standalone request/report shapes are unchanged. `traceroute::Error` gains
`TargetSelection`, `InvalidObservation`, and `Collection` with typed sources.
Hosts requests can reuse already resolved targets and sequence numbering while
reauthorizing every endpoint. `Client::with_remaining_budget` and
`with_parent_deadline` only narrow the containing operation's allowance.

CLI raw-scan publication takes an optional trace report; its terminal conversion
takes the optional trace summary. Trace packets/time contribute to scan totals,
without turning reused hops into new probe observations.

## Scan follow-ups

The scan, trace, and reverse-DNS pipeline behind `scan --traceroute` and
`--reverse-dns` is library behavior in `packetcraftr::scan::followup`.
`Client::scan_with_followups(followup::Request, sink)` runs the scan, then a
trace of every scanned host, then the PTR lookups, under one duration limit and
the policy allowance each stage leaves the next. Events arrive as
`followup::Event`; the returned `followup::Report` keeps each stage's report and
adds the endpoint inferences, `reverse_dns` lookups, and the total `stats`.
`followup::Collector::finish` rebuilds a `followup::Aggregate` from the events.
`Client::scan_connect_with_followups` does the same for TCP connect scans with
reverse DNS. `Trace::validate` and `ReverseDns::validate` reject an unusable
stage before any probe. The CLI maps its arguments to these requests and keeps
rendering.

## Send packet sets

`send` expands `--axis` templates as `build` and `exchange` do, and repeats the
set with `--repeat` and `--rate` instead of sending exactly one packet. The
current `sendResult` replaces `frame`/`route` with a `frames` list plus
`passes_completed`; each frame carries a one-based `pass` and its expansion
`index`. Invalid repeat or rate values classify as `cli.send_limit`, and the
pacing ceiling is `packetcraftr_netio::deadline::MAX_WAIT`. Rust callers use
`client.send(send::Request, sink)` (see [Client model](#client-model)).

## Replay

Replay is `client.replay(request, sink)` (see [Client model](#client-model)),
with `replay::Request::new(replay::Source::stream(reader), routing, options)`
and an optional `.with_filter(frame_selector)`. `replay::Options::interface` is
replaced by routing: route every frame through the old value with
`replay::routing::Routing::from(route::Interface::Id(interface))`, and add
`repeat: 1` and `inter_pass_delay: Duration::ZERO` for one pass. `Options` also
gains `allow_permissive_live`, the second opt-in that the removed
`SystemAuthorizer::new(.., allow_malformed_live)` took.

Routing rules can send each selected frame through its own interface:
`Routing::new(rules, Some(fallback))?` holds at most `routing::MAX_RULES`
`routing::Rule { condition, interface }` values, where the condition is
`routing::Condition::Source(id)` or `Condition::Filter(selector)`.
`Rule::parse_source(text, parse_interface)` and
`Rule::parse_filter(text, compile, parse_interface)` parse `SOURCE_ID=INTERFACE`
and `EXPR=>INTERFACE` and refuse with `replay::routing::Error`. A frame whose
rules name different interfaces fails with `replay::Error::ConflictingInterfaces`,
and one that no rule matches, with no fallback, fails with
`replay::Error::Unmapped` (replacing `InvalidLimit { field: "interface" }`);
both are `cli.error`. `replay::Error::Selection` carries the `filter::Error`
that stopped the request's filter or a filter rule.

Repetition (`repeat > 1`) needs a rewindable capture: only
`Source::seekable(reader)`, which requires `Read + Seek`, may set it, while
`Source::stream(reader)` takes any `Read`. The CLI snapshots and validates the
complete capture before live work, including compressed inputs. Repetition
shares source-frame, transmitted-byte, time, and policy budgets.
`FrameEvidence::pass` is one-based and `source_index` stays relative to the
input. `FrameEvidence::source_interface_id` is removed because it always equaled
`frame.interface`; read `evidence.frame.interface`. `replay::Report` (the former
`Summary`) adds `passes_completed` and `interfaces_used`; the aggregate
requested interface is optional, and each sent frame keeps its actual output
route. Replay also gains `Timing::BitRate` (CLI `--bps`), published in current output
as `{"bit_rate": BITS_PER_SECOND}`.

`replay::Options` gains `max_gap: Option<Duration>` (CLI `--max-gap-ms`). `None`
keeps the previous timing, so add `max_gap: None` to struct literals. A `Some`
gap must be non-zero and is valid only with original or scaled timing, which
`Options::validate` enforces with `InvalidLimit`; it clamps each inter-frame
delay after scaling, and the published timing does not record the clamp.

## Resource and output hardening

Native capture/route/TCP work shares one process-wide worker pool; TCP admission
is not an additional independent pool. Share callback admission through
`client.with_runtime(runtime.clone())`; inspect its snapshot separately.
Cancelled/timed-out workers retain permits until cleanup. NDJSON output timeout
bounds writes, not the operation; invocation deadlines take precedence.

Staged writers bind to the directory selected before input. Linux/procfs paths
use the open directory handle; other platforms recheck identity before publication
and rollback, with a remaining pathname race window and best-effort cleanup after
directory moves. No path silently overwrites existing destinations.

TCP charges include payload-page slack and transient work; DNS retention is
cumulative. Near-limit captures can therefore be refused earlier. Review
[resource contracts](analysis-resources.md) before raising a ceiling.

## Core API conventions

`Dns::from_wire(b)` is `Dns::try_from(b)` (`TryFrom<Bytes>`, `Vec<u8>`, and
`&[u8]`; use `b.as_ref()` for `&Bytes`), and the bounded
`Dns::from_wire_with_limits` stays inherent. Registry APIs take the `LinkType`
newtype (`registry::Builder::bind_link_type`, `Registry::root_for_link_type`,
`registry::Error::DuplicateLinkType`) and `impl Into<Discriminator>`
(`From<u64>`) instead of bare integers, so drop `.0` peels at call sites.
`Frame::try_with_lengths` and `try_with_optional_timestamp` take
`frame::Lengths { captured, original }`, which removes adjacent-scalar swaps,
and `Malformed::new` takes its intended protocol as `Option<String>`.
`budget::Interrupted` is `#[non_exhaustive]`, so add a wildcard arm to
exhaustive matches.

`LayerCodec::decode` takes the layer input as a refcounted `Bytes` view instead
of `&[u8]`. Custom codecs can retain ranges with `input.slice(..)` instead of
copying them, and callers holding borrowed bytes wrap them once with
`Bytes::copy_from_slice` or `Bytes::from`. `LayerDecodeContext` gains a
`parent` field naming the enclosing protocol and drops `allow_trailing_padding`:
delete it from struct literals and stop reading it in codecs. It also gains
`hop_limit: Option<u8>`, the TTL or hop limit of the enclosing IP header (`None`
when unknown, as under a non-IP parent), which the VRRP codec reads for its
destination and TTL checks; add `hop_limit: None` to struct literals, or the
real value when the caller knows it. Link padding is decided by the registry
(`registry::Builder::allow_trailing_padding`,
`Registry::allows_trailing_padding`) and the decode session.

`Layer::as_any` and `Layer::as_any_mut` are removed. `dyn Layer` upcasts to
`dyn Any`, and its inherent `is`, `downcast_ref`, and `downcast_mut` replace the
two-step call: `layer.as_any().downcast_ref::<Udp>()` becomes
`layer.downcast_ref::<Udp>()`. Hand-written `Layer` implementations delete both
methods; `clone_box` stays because `Clone` is not object safe.
`reflective_layer!`, `layer::ReflectiveField`, `layer::Refusal`, and
`layer::{reflect_get, reflect_set, reflect_set_bounded}` are now documented API
for declaring custom layers, and `protocol::transport_tuple_reversed` is
documented as well. The macro now builds its schema as a `static`, so the
`protocol:` expression must be a constant expression: `Id::new("name")`, a
`const` item, or a `const fn` call. A `protocol:` expression that ran arbitrary
runtime code compiled before and is now rejected, so hoist it into a `const Id`.
Field metadata, including `children:` values, already had to be constant, so
nothing else changes.

`BuiltinProtocol::of(layer)` and `BuiltinProtocol::identifies(layer)` decide by
the layer's concrete type, not by the protocol name in its schema. A custom
`Layer` whose schema says `ipv4` is not IPv4 to core: `of` returns `None`, route
semantics refuse it as an unknown protocol carrying a route field, and it gets
no built-in matcher or validation behavior. Give a custom layer its own
protocol name and register it through `registry::Builder`.
`BuiltinProtocol::from_id` and `from_name` still map registry identifiers and
names. `BuiltinProtocol` is not `#[non_exhaustive]` and gains `Eapol`,
`Etherip`, `Gtpu`, `Lldp`, `Stp`, `Syslog`, `Tftp`, and `Vrrp` (see
[Protocol coverage and bindings](#protocol-coverage-and-bindings)), so add arms
to exhaustive matches on it. `protocol::semantics` no longer exports its
field-name constants (`SOURCE`, `DESTINATION`, `SOURCE_PORT`,
`DESTINATION_PORT`, `SEGMENTS`, `SEGMENTS_LEFT`, `LAST_ENTRY`,
`TARGET_PROTOCOL`, `IPV4_OPTIONS`); downcast to the built-in layer and read its
field, so `layer.field(semantics::DESTINATION)` on an Ethernet layer becomes
`layer.downcast_ref::<Ethernet>().map(|ethernet| ethernet.destination)`.
`protocol::semantics::Error` messages now read "destination cannot be
determined because ..."; match on the variant, not the text. Its
`LayerIndexOutOfRange` and `SegmentCountUnrepresentable` variants are removed
because no reachable code path produces them, so delete any match arms or constructions
that name them. The enum is `#[non_exhaustive]`, so existing wildcard arms keep
compiling, and every variant classifies as `packet.semantics`.

Wire APIs return their protocol's own error: `Dns::try_from` returns
`dns::Error` (`Dns::from_wire` returned `codec::Error`), and an encoding failure
is `dns::Error::Encode` with the codec error as its source. Code that matched
`codec::Error::Truncated` on a DNS conversion matches
`dns::Error::MessageTooShort`, `TruncatedField`, or
`TruncatedLabelLength`/`TruncatedPointer`/`TruncatedLabel` instead.
`tls::Outcome::Malformed` carries the new `tls::Error` instead of
`codec::Error`, and its `Invalid` message displays exactly as the former
`codec::Error::Invalid` did.

`decode::DecodedPacket::original` is removed because it always held the same
bytes as the frame. Replace `decoded.original` with `decoded.frame.bytes()` (a
`&Bytes`; clone it if you need an owned copy), and drop the `original` field
from any hand-built `DecodedPacket { .. }` literal or destructuring pattern.

## Live-policy vocabulary out of core

Core keeps packet facts, and `packetcraftr` owns what they mean for live
traffic. `build::BuiltPacket` now records the codec `mode` it was
built with and exposes `contains_malformed()` and `contains_network_trailer()`;
the predicate is `packetcraftr::policy::requires_live_opt_in(&built)`, and the
published `requires_live_opt_in` output field is unchanged. `Deadline` gains
`limit()` and `cancellation()` getters, plus `live_remaining()` and `detach()`,
which check cancellation before the nonzero remainder. `Cancelled::into_boundary_error` is
removed; build `BoundaryError::with_source(c.to_string(), c.classification(),
Vec::new(), c)` instead. The other moved items are in
[Renamed and removed paths](#renamed-and-removed-paths).

## Limits and budgets

A configured ceiling is a `...Limits` type, validated where it is accepted and
never lowered silently; the running allowance charged against it is a
`...Budget`. `capture_file::Limits::advance(frames, bytes, len)` is replaced by
`capture_file::Budget::new(limits)?`, then `budget.charge(len)?` (or
`budget.after(len)?` to check without charging), with `budget.frames()` and
`budget.captured_bytes()`. Struct shapes changed as follows:

```rust
// Before
analysis::Limits { max_tcp_bytes_per_flow, max_tcp_reassembly_bytes,
    max_tcp_segments_per_flow, tcp_idle_expiry, max_ip_datagrams,
    max_ip_fragments_per_datagram, max_ip_bytes_per_datagram,
    max_ip_reassembly_bytes, max_ip_outcomes, ip_idle_expiry, .. }
decode::Options { max_layers, max_packet_size }
build::Options { mode, max_layers, max_packet_size }
Interner::with_limits(limit, max_bytes)
// After
analysis::Limits {
    tcp: reassembly::tcp::Limits { max_bytes_per_flow, max_aggregate_bytes,
        max_segments_per_flow, idle_expiry, max_flows },
    ip: reassembly::ip::Limits { max_datagrams, max_fragments_per_datagram,
        max_bytes_per_datagram, max_aggregate_bytes, max_retained_outcomes,
        idle_expiry },
    .. }
decode::Options { limits: packet::Limits { max_layers, max_packet_size } }
build::Options { mode, limits: packet::Limits { .. } }
Interner::with_limits(scope::Limits { max_scopes, max_bytes })?  // max_scopes <= scope::MAX_SCOPES
```

Constructors that accept limits validate them and return a `Result`:
`reassembly::ip::Reassembler::new` and `reassembly::tcp::Reassembler::new`
return `analysis::Error::InvalidLimit` (`cli.analysis_limit`), and
`scope::Interner::with_limits` returns `scope::Error::InvalidLimit`
(`cli.analysis_limit`). `reassembly::tcp::Resource::InvalidWindowLimit` is
removed because an oversized window is refused at construction. Each of these
limit types, plus `capture_file::Limits`, `compression::Limits`, `dhcp::Limits`,
`dns::Limits`, and `application::Limits`, has a public `validate()`.

- `analysis::Limits.tcp.max_flows` bounds concurrent directional TCP flows by
  itself. It was derived as twice `max_flows`, which is still its default; set
  both if you raise `max_flows` past half of `tcp.max_flows`.
- Capture writers, `rewrite`, `select`, `map_frames`, and `merge` refuse a zero
  `max_frames` or `max_bytes` with `capture_file::Error::InvalidLimit`
  (`cli.capture_limit`) before writing anything.
- `dhcp::Limits` and `dns::Limits` above their `MAX_*` ceilings fail with
  `InvalidLimit` (`policy.dhcp_limit` / `policy.dns_limit`); pass the constant
  itself to ask for the widest limit.
- `policy::WireLimits` and `policy::SocketLimits` (formerly `WireBudget` and
  `SocketBudget`) are the ceilings an operation declares for policy to
  authorize, while `policy::CaptureBudget` keeps the running allowance.
- `runtime::Runtime::new(capacity)` returns `Result<Runtime,
  runtime::CapacityError>`. A capacity above `runtime::MAX_WORKER_CAPACITY` (8),
  which used to be lowered to 8 without notice, is refused with
  `cli.worker_capacity` (`Kind::Usage`); handle or unwrap the result, and pass a
  capacity no greater than the maximum or use `Runtime::default()` for the
  maximum. Capacity 0 is still accepted and refuses every publication, and
  `runtime::Error` is unchanged.

## Core error convention

Each core module has one `Error`, used module-qualified, with typed sources; a
message no longer repeats its source's text, and every public error implements
`Classified` (classification codes are unchanged). Typed reasons replace
strings: `analysis::Error::InvalidLimit.reason` is an `analysis::Constraint`,
`protocol::semantics::Error::Field.reason` is a `semantics::Constraint`, and
`fuzz::Error::{InvalidLimit, InvalidTarget, InvalidBasePacket}` carry
`fuzz::{Constraint, TargetFault, BaseFault}`. Each renders the text the message
carried before, so messages, codes, and published output are unchanged.
`codec::Error::Rejected { protocol, source }` reports a protocol model's typed
refusal (for example a `dns::Error` from a codec) and displays as "invalid
`<protocol>` layer"; `source()` downcasts to the original error, and
`codec::Error::rejected(protocol, error)` builds one. The renamed error types
are in [Renamed and removed paths](#renamed-and-removed-paths).

`fuzz::Error` (`#[non_exhaustive]`) gains `ValueItems { items, limit }` and
`ValueNesting { limit }` for a base-packet list or object above `max_list_items`
and for value nesting above the limit; both were previously reported as
`ValueTooLarge`. Callers that matched `ValueTooLarge` to detect those failures
also match the new variants; all three classify as `policy.fuzz_resource_limit`.

## Provider contracts

Every netio capability is `<capability>::Provider` with a
`<capability>::SystemProvider`, and every provider trait has `Send + Sync`
supertraits. Transmission is one `transmit::Provider` with `send(Outbound)`:
match `Outbound::Layer2` and `Outbound::Layer3` inside `send`, or use
`transmit::SystemProvider`, which sends through the backend built for the
frame's layer and fails with `Error::Unsupported` (`capability.unsupported`)
for a layer this build does not include.

`route::Provider::classify_error` is removed: the provider's `type Error` must
implement `Classified`. A route provider that cannot fail keeps
`type Error = Infallible`, since core implements `Classified` for it. A
provider with its own error type implements `Classified` and chooses the code
that `classify_error` returned before; the old default was `io.route`. A fake
whose error was `std::io::Error` needs a local error type, because `Classified`
is a core trait.

**Deadlines.** Every provider call that can block takes the caller's core
`budget::Deadline` by reference, and the deadline carries the caller's
cancellation, so there is no separate timeout or cancellation argument. A
provider checks cancellation first, treats a zero remainder as expired, and
never waits past the remainder. Build a deadline from a timeout with
`Deadline::new(timeout)`, adding `.with_cancellation(Some(signal))` to share a
stop signal; a passive lookup whose operation has no deadline can use
`packetcraftr::deadline::PASSIVE_LOOKUP_TIMEOUT`, the allowance the backends
used to apply themselves. A fake provider that ignores time takes
`_deadline: &Deadline`; one that recorded or slept for its timeout reads
`deadline.remaining()`, and one that stalls until expiry can loop on
`deadline.live_remaining()`. A system backend stopped by
the deadline reports `route::Error::DeadlineExceeded`,
`interface::Error::DeadlineExceeded`, or `Error::DeadlineExceeded`, all
classified `io.deadline_exceeded`; a cancelled one reports the `Cancelled`
variant (`io.cancelled`). The affected signatures are listed in the netio table
below.

**Capture sessions.** `capture::Session` gains defaulted `source_count` and
`source_metadata`, and `Captured` gains a public `source` field that its
constructors set to 0, so single-source session fakes need no change.
`Session::next_captured_frame(&deadline)` takes only what is queued once the
deadline is spent. `capture::Request::validate` checks limits, native settings,
and the `capture::MAX_FILTER_BYTES` (64 KiB) filter limit, and
`capture::SystemProvider` runs it before opening an interface.

**Errors.** `packetcraftr_netio::Error`, `route::Error`, and `interface::Error`
carry one `packetcraftr_netio::Unsupported { capability, message, source }`, and
its `NativeCapability` decides the class: `Route` classifies as
`capability.route`, and `InterfaceEnumeration`, `Capture`, and
`Transmission(mode)` as `capability.unsupported`. Match with
`matches!(error, Error::Unsupported(_))`; `Unsupported::new(capability,
message).into()` builds any of the three, and messages are unchanged.
`interface::Provider::interfaces` returns `interface::Error`, not the shared
netio error: `Error::InterfaceDiscovery { message, source }` becomes
`interface::Error::Discovery { message, source }` with a required
`packetcraftr_core::error::Source`, and `Error::Unsupported` becomes
`interface::Error::Unsupported(Unsupported::new(NativeCapability::InterfaceEnumeration, message))`.
`packetcraftr_netio::Error` implements `From<interface::Error>`, so `?` still
converts an enumeration failure, and a test fake that returned
`InterfaceDiscovery { source: None }` supplies a source such as
`Source::new(std::io::Error::other("fixture"))`.

`packetcraftr_netio::SystemFault` is removed; use `Some(Source::new(error))` in
place of `Some(Arc::new(error))`. Native libpcap and Npcap failures keep their
status and diagnostic text as the source, so that text appears in `causes`
rather than in the message. `Error::InvalidSendEvidence` and
`SendEvidenceFault::UnrepresentableFrame` also stop repeating their source in
the message, and `SendEvidenceFault` implements `Classified`
(`internal.live_io_invariant`).

## Route planning and neighbor resolution

Route planning and neighbor resolution interpret packets or drive active
discovery, so they moved out of netio. netio keeps the route
contract a provider implements: `route::{Provider, Decision, Scope,
SelectionReason, SystemProvider}` and its native `route::Error` (formerly
`SystemError`). `packetcraftr::route` plans and materializes routes over it, and
`Client::plan` and `send::Options::plan` use its types. `route::Options.interface`
is an `Option<route::Interface>`: `Interface::Id(id)` for an identity a provider
confirmed, or `Interface::Name`/`Interface::Index` for a selector the client
resolves through its interface provider after admission, so a refused operation
never enumerates interfaces. An unmatched selector fails with
`packetcraftr::route::Error::UnknownInterface` (`io.device`) and an enumeration
failure with `InterfaceDiscovery`; the free `route::plan` takes only
`Interface::Id` and reports `UnresolvedInterface` otherwise.
Transmit frames take a borrowed `transmit::Route` view rather than
`&Materialized`: `try_new(bytes, materialized.transmit_route())`, and
`frame.route().plan.decision` is `frame.route().decision` (likewise `.mode` and
`.lookup_destination`). `Materialized::for_prepared_layer2_frame` is removed;
build a `route::Decision` and a `transmit::Route` view directly.
`SystemProvider` checks a preferred source's address family once, before any
native backend runs, and still reports netio's
`route::Error::SourceFamilyMismatch` (`io.route_selection`).

The `Client` resolves neighbors itself, over the transmit and capture providers
it already holds and only while materializing a route that policy has admitted;
the CLI no longer composes a second I/O stack for it. `neighbor::Resolver`,
`ActiveResolver`, `SystemResolver`, and `route::materialize` are gone. Set the
bounds with `client.with_neighbor_options(options)?`, which validates them
(`cli.neighbor_limit` on failure) and starts a fresh cache shared by every
operation of that client, and note that `neighbor::Request` no longer has a
`deadline` field because the client passes the operation deadline. Because a
Layer 2 send may resolve a neighbor, `Client::send` needs a capture provider
too: a capture fake for Layer 3 sends only can implement `arm_capture` as
unreachable, and a fake that scripts resolution answers the ARP or NDP request
through the capture session armed for it.

`link::MAX_VLAN_TAGS` (8) is `packetcraftr::neighbor::MAX_VLAN_TAGS`, because
only neighbor discovery replays a packet's VLAN stack. Route planning applies
the cap only to a plan that resolves a neighbor: a Layer 2 packet with more than
8 VLAN headers plans when its destination MAC is explicit or a broadcast or
multicast address, where it failed with `InvalidNeighborVlan`, and an unreadable
stack (priority above 7 or VLAN id above 4095) is refused before the route
provider is consulted.

## Client model

The `Client` owns every provider a workflow reaches the network through, and
every workflow is a client method that takes a request and a sink. This
replaces beta.3's free `run` and `run_with_events` functions, executor seams,
and caller-supplied authorizers. The client admits each workflow through its
own `Policy` and resolves declared targets through its `resolver` provider, so
`policy::Authorizer`, `policy::PolicyAuthorizer`, and
`policy::unsupported_operation` are no longer public. To apply a policy without
a client, call `Policy::authorize(operation)` or
`Policy::resolve_target(target, &resolver)`.

**Composition.** Construct `Client<P, K = SystemClock>` with
`Client::new(registry, policy, providers)`. `ProviderSet` holds `route`,
`interface`, `capture`, `transmit`, `tcp`, `resolver`, and `udp`; `SystemProviders`
selects system implementations. `PacketIo` is removed. Use partial bundles so
unused capabilities need no filler implementation:

```rust
let capture_only = ProviderSet::capture(interface, capture);
let packet_io = ProviderSet::packet(route, interface, capture, transmit);
let connect_only = ProviderSet::tcp(tcp, resolver);
let sockets = connect_only.with_udp(udp);
```

Each type parameter defaults to `()`. Custom provider bundles implement only the
capability traits their workflows need; there is no broad `Providers` marker.

| Capability | Fields / purpose |
| --- | --- |
| `CaptureProviders` | `interface`, `capture` for capture workflows |
| `PacketProviders: CaptureProviders` | adds `route`, `transmit` for packet workflows |
| `TargetProviders` | `resolver` for target planning and resolution |
| `TcpProviders` | `tcp` for connect scans and DNS TCP |
| `UdpProviders` | `udp`; identification requires it and `TcpProviders` |

Configure shared clock, runtime, cancellation, and neighbor bounds with the
client's `with_*` methods. Fakes shared between capture/transmit fill both fields;
all network providers remain explicit.

**Running a workflow.** Every workflow follows one pattern. The request goes in,
events reach the sink as each becomes final, and the terminal `Report` comes
back; the workflow's `Collector` sink rebuilds the full `Aggregate`:

```rust
// Before (scan shown; traceroute, dns, and fuzz were the same shape)
let report = scan::run(&request, &mut authorizer, &registry, &mut executor, &mut clock)?;
// After
let collector = scan::Collector::default();
let report = client.scan(request, collector.clone())?;
let aggregate = collector.finish(report)?; // fuzz's finish returns the Aggregate directly
```

Pass a sink instead of a collector to stream: `S: Sink<Event, Ack = ()>`, where
`Sink<E>` has an `Ack` answer type and `publish(&mut self, event: E) ->
Result<Self::Ack, BoundaryError>`, and every `FnMut(E) -> Result<A,
BoundaryError> + Send + 'static` closure is a sink. A closure whose argument
type was inferred from the old closure bound names it now
(`|event: scan::Event| { ...; Ok(()) }`). The sink runs on a worker admitted by
the client's runtime and answers each event before the next one is sent, and it
may finish after the method returns while it holds its permit.
`progress::Sink<T>` is renamed `runtime::Worker<T, A = ()>`: the worker thread a
runtime admits, whose callback returns `Result<A, BoundaryError>` and whose
`emit` returns that `A`. Name the answer type when the callback never returns
`Ok` (`Worker::<()>::new_in(&runtime, |_| Err(error))`). For scan, traceroute,
exchange, replay, DNS, and fuzz, the terminal `Report` is the former `Summary`
and the `Aggregate` is the former events-joined `Report`.

Each beta.3 entry point maps to a client method (see the packetcraftr table in
[Renamed and removed paths](#renamed-and-removed-paths)):
`client.send(send::Request::packet(packet, options), sink)` replaces
`client.send(packet, options)`, and the `dns::tcp::exchange(request)` helper is
`dns::tcp::query(request, provider)`. The offline fuzz campaign is
`packetcraftr_core::fuzz::run_observed(&campaign, packet, registry, emit)`,
publishing through a `runtime::Worker` if needed.
`client.capture`, `client.scan_connect`, and `client.dns_batch` are new.

**Clock and cancellation.** `Clock` is `Clone + Send + Sync + 'static`; `now`
takes `&self`, and `sleep(&self, delay, deadline)` returns early once the
deadline's cancellation is signaled (it was `sleep(&mut self, delay)`). The
client anchors every deadline, duration limit, and pacing delay on its clock. A
fake clock shares its state behind an `Arc` and starts from `Instant::now()`,
so its deadlines and capture timestamps share one monotonic base.
`Clock::cancellation` and `CancellableClock` are removed: cancel through
`Client::with_cancellation`, which every workflow's deadline carries.

**Send.** `send::Request { template, send, repeat, rate, max_template_packets }`
expands the template `repeat` times under one packet and byte budget
(`Request::packet(packet, options)` sends one packet once), and
`Request::validate` and `Request::packet_count` check it. Events are
`send::Event::Sent(SentFrame { pass, index, packet })`, and `send::Aggregate`
holds `sent: Vec<SentFrame>`. `send::Error` wraps the preparation error
`packetcraftr::Error` as `Preparation` and adds `InvalidRequest` (`cli.send_limit`),
`Output`, `IncoherentEvents` (`internal.send_event_coherence`, for a collector
finished with another run's report), and `Clock` (`io.send_clock`, for a pacing
clock that fails).

**Exchange.** `exchange::Options` splits: the per-run fields become
`exchange::Request { template, send, timeout, max_template_packets, collection,
stop }`, and the capture, decode, and retention bounds become the reusable
`exchange::Collection { capture, decode, max_responses, max_unmatched_frames }`
that scan, traceroute, DNS, and fuzz requests reuse. `Collector::observe` is
gone: the collector is a `Sink<Event>`, so clone it and pass one clone.
`options.validate()` becomes `request.validate()` and `collection.validate()`.
`stop: exchange::StopCondition` defaults to `Window`, which collects until the
window closes as before (`Request::new` sets it); `AllAnswered` (CLI
`--stop-when-answered`) ends collection once every request of the packet set has
at least one retained response, never before the last send. `Client::exchange`
honors it, while workflows that hook an exchange, such as fuzz, supply their own
stop predicate and set `stop: StopCondition::Window`. The terminal
`exchange::Report` (the former `Summary`) is `Report { unanswered, stats }`: its
`diagnostics` field is removed, so drop it from any `Report` you build or
destructure. It was always empty, and diagnostics still arrive as
`Event::Diagnostic` events and, through `exchange::Collector`, in
`Aggregate::diagnostics`.

**Scan and traceroute.** The request carries the route and collection bounds
that the `ExchangeExecutor` held before: `route: route::Options` (the executor's
`send.plan`) and `collection: exchange::Collection`. Requests are no longer
serde types, because those bounds are not. `IncoherentEvents`
(`internal.scan_event_coherence`, `internal.traceroute_event_coherence`) reports
a collector finished with another run's report, and a pipeline failure still
reaches the caller as `scan::Error::PipelineExecution`, whose source chain
holds the `scan::PipelineFailure` with the pending evidence. Each workflow now
reports its own error enum whose variants are the former `probe::ErrorKind`s,
so `matches!(error, scan::Error::InvalidLimit { .. })` replaces
`matches!(error.kind, ErrorKind::InvalidLimit { .. })`. Codes, messages,
remediations, probe-sequence coordinates, and causes are unchanged, with two
exceptions. A traceroute UDP port range that overflows 65535 reports
`base UDP port B plus probe N exceeds 65535`, where N is the last probe's
zero-based offset (the probe count minus one), instead of `plus K unique
probe(s)`; it is still `cli.traceroute_limit`. And a serial scan or a
traceroute checks its `collection` before any capture or send: a `collection`
that captures more frames or bytes than `max_evidence_frames` or
`max_evidence_bytes` retain is `cli.scan_limit` or `cli.traceroute_limit`, where
it used to fail after transmission with `internal.scan_evidence` or
`internal.traceroute_evidence`, and a traceroute `collection.max_responses`
below `probes_per_hop` is `cli.traceroute_limit` up front, where it failed at
the executor with `cli.traceroute_executor`.

`traceroute::Request` and `traceroute::Probe` gain `payload_size: u16`,
`dont_fragment: bool`, and `dscp: u8` (CLI `--payload-size`, `--dont-fragment`,
and `--dscp`). Add `payload_size: 0, dont_fragment: false, dscp: 0` to struct
literals to keep the previous probe. `payload_size` appends zero bytes to UDP
and ICMP echo probes (at most `traceroute::MAX_PAYLOAD_SIZE`, 9000), TCP probes
carry none, `dscp` is at most 63, and `dont_fragment` is refused for an IPv6
destination. The wire-byte admission check uses the probe's real size.

**Replay** takes `Sink<replay::Event, Ack = ()>` with `Event::Frame(FrameEvidence)`
in place of the `FnMut(FrameEvidence) -> Result<(), replay::Error>` callback,
and `replay::Collector` rebuilds `replay::Aggregate { frames, report }`. A sink
returns a `BoundaryError`, which replay reports as `Error::Output { source_index,
source }` (replacing `Error::output_at_source_index(index, message)`); a sink
whose `BoundaryError` has a `Cancelled`, `DeadlineExceeded`, or `Interrupted`
source stops the replay as `Error::Cancelled` or `Error::DurationLimit` rather
than as an output failure. `replay::Error` adds `IncoherentEvents`
(`internal.replay_event_coherence`). Only replay checked the final wire through
the authorizer, and it now does so internally, so
`policy::Authorizer::authorize_final_wire` is removed. Replay frame admission is
internal to the crate: `policy::Operation::Replay`, `policy::ReplayFrame`, the
`UnsupportedOperation` error (`packetcraftr::Error::UnsupportedOperation` in
beta.3), and `policy::Operation::shape()`, which only labeled that error, are
removed, and the client's policy admits each replay frame itself. The
`internal.unsupported_operation` code is no longer published. `Client::replay`
is unchanged; drop any `Replay` arm from an exhaustive match on
`policy::Operation` and any `UnsupportedOperation` arm from a match on the
error. There is no public replacement.

**Capture** is `client.capture(capture::Request::new(group_request, window), sink)`
with an optional `.with_selector(|number, frame| Ok(keep))`. The client's
capture provider arms the group, its policy sets the frame and byte budget, and
its cancellation stops the capture. The sink is `Sink<capture::Event>` whose
answer converts into `capture::Control` (`()` continues); it runs on a runtime
worker, so it is `Send + 'static` and keeps any state the caller needs
afterwards behind an `Arc<Mutex<_>>`. The selector runs on the capture's own
thread before the sink. `Control::{StopBefore, StopAfter}` stop the capture
without or with publishing the current frame; a stop is a success whose
evidence is kept. `capture::Source` holds `index`, `metadata`, and the other
source fields itself, and `Event::Started` carries `capture::Source` values.

**DNS.** `client.dns(request, sink)` returns `dns::Report`, and `dns::Collector`
rebuilds `dns::Aggregate`, whose `report()` replaces `summary()`.
`client.dns_batch(dns::batch::Request { questions }, sink)` returns
`dns::batch::Report`, publishes question-tagged `dns::batch::Event { question,
event }`, and `dns::batch::Collector` rebuilds `dns::batch::Aggregate`, whose
questions carry `dns::Aggregate` results. A batch's questions share the server,
server port, route, and collection. `dns::Request` gains `route: route::Options`
(the UDP exchanges' route; kernel TCP accepts only the default) and
`collection: exchange::Collection` (the capture bounds, which must fit the
request's evidence limits); both are live settings that serde skips.
`dns::Error::Authorization` (like `fuzz::Error::Authorization`) no longer
converts from `BoundaryError`, so construct it explicitly instead of using `?`,
`InvalidEvidence { attempt, fault: dns::EvidenceFault }` replaces its message,
and a TCP executor that rejects the workflow's own request is
`TcpRequestRejected { attempt, source }`. `Query` no longer repeats its source
in the message. `dns::Probe` and `dns::classify_response` stay public for
offline response classification.

**Fuzz.** Core owns the campaign (its cases, their offline outcomes, and the
coherence check), and the live types add only what a live run observes:
`fuzz::Request` wraps core's campaign request and replaces `RunInput`,
`LiveOptions`, and `LiveLimits`, and `fuzz::Trial` pairs a core `Case` with the
optional live `fuzz::Evidence`.
The events are `fuzz::Event::Case(Trial)`, one per case in case order, each
answered before the next case is sent. A rejected case has no evidence, and a
transmitted case's `case.built` and `case.decoded` are the packet actually sent
on its route. `campaign` holds core's preparation statistics (cases generated
and built, built bytes, preparation time), while `stats` holds the live
traffic, including pacing delays. Codes and the published output are unchanged;
the CLI derives the four published outcomes from the two sources. An executor
result that contradicts its own statistics fails as `Error::InvalidEvidence`
with the shared evidence wording, such as
`successful exchange statistics do not account for every fuzz probe` or
`successful exchange reported N sent bytes for M exact frame bytes`, in place of
the bespoke fuzz messages. Case validation no longer tests the invocation
deadline between its checks, so such a result found after the deadline expired
is `InvalidEvidence` where it was `Error::DurationLimit`; the recorder still
enforces the deadline once a case's evidence is recorded.

## CLI library API

The `packetcraftr_cli` library now holds the whole command-line application.
`packetcraftr_cli::main()` parses the process arguments, runs the command, and
returns its `ExitCode`; the `packetcraftr` binary only calls it. This entry-point
move does not itself change flags, exit codes, or output documents.
`output::contract::Format` and `output::stats::Table` are plain output types and
no longer implement `clap::ValueEnum`: code that parsed them with clap declares
its own value enum and converts it with `From`, as the CLI does.

`output::contract::Command` is generated from the same declaration as the
command line, so its variants, serialized names, and `formats()` cannot drift
from the commands the binary accepts. Serialized names and each command's
formats are unchanged. `Command::ALL` lists commands in `--help` order; code
that relied on the previous canonical order sorts by `Command::as_str()`.
`Command::require_format(format) -> Result<Format, contract::Error>` returns
the validated `Format` instead of `()`, so a command that cannot emit a format
fails at dispatch and dead rendering arms surface typed `internal` errors
instead of panicking.

## Output field types

`packetcraftr_cli::output` fields embed the library type directly wherever the
library already serializes to the published shape — `packetcraftr::Stats`
(`output::envelope::Stats`), `packetcraftr::capture::StopReason`,
`packetcraftr::probe::{Transport, ProbeStatus}`, core
`diagnostic::{Diagnostic, Severity}` and `frame::Direction`, netio
`capture::{Stats, TimestampSource, TimestampPrecision, Realized,
RealizedSettings}`, and the capture-file compression `Format` are re-exported
from their output modules, and `output::diagnostic` and `output::probe` are
removed. CLI-owned types remain where the contract's field names or variants
differ from the library's. Common replacements:

| Library type | Output type |
| --- | --- |
| `core::error::Coordinate` (in `envelope::Error.context`) | `output::envelope::ErrorContext` |
| `core::layout::PacketLayout` | `output::frame::Layout` |
| `netio::interface::Id`, `link::Mode`, `route::{Scope, SelectionReason}` | `output::network::{InterfaceId, LinkMode, Scope, SelectionReason}` |
| `core::analysis::{scope::Definition, ClockReport, StreamTransport, Endpoint, StreamRef}` | `output::analysis::{Scope, Clock, StreamTransport, Endpoint, StreamRef}` |
| `packetcraftr::fuzz::Outcome`, `core::fuzz::{CaseOutcome, Strategy}` | `output::fuzz::{Outcome, Strategy}` |

Use `From` / `TryFrom` in place of the old `from_*`, `try_from_*`, and
`complete_from_*` constructors. Scan publication additionally requires an explicit
plan and stage data through `publish` / `Summary::new`. A conversion
whose source also carries diagnostics or totals yields
`output::envelope::Published<T>` (`result`, `diagnostics`, `stats`), which
`Envelope::published` and `StreamEncoder::{emit_published, complete_published}`
publish:

| Before | After |
| --- | --- |
| `send::Report::try_from_report(r)` returning `(report, diagnostics, stats)` | `Published::<send::Report>::try_from(aggregate)` |
| `scan::Event::try_from_scan(e)`, `complete_from_scan(s)` | `Published::<scan::Event>::try_from(e)`, `Published::<scan::Event>::from((s, plan, trace_summary))` |
| `fuzz::Report::try_from_offline(r)` / `try_from_live(r)` | `Published::<fuzz::Report>::try_from(r)` |
| `build::Report::from_built(b)` | `Published::<build::Report>::from(b)` |
| `dissect::Report::from_decoded(d)` plus `AggregateResult::new` | `Published::<dissect::AggregateResult>::from((matched, d))` |
| `frame::Captured::try_from_frame(f)`, `Wire::new(b)` | `Captured::try_from(f)`, `Wire::from(b)` |
| `read::Frame::try_from_frame(n, f)` / `try_from_decoded(n, f, &d)` | `read::Frame::try_from((n, f))` / `try_from((n, f, &d))` |
| `stats::Report::try_from_report(t, r, n)` | `stats::Report::try_from((t, r, n))` |
| `replay::Report::from_summary(s, interface, mode, frames)` | `replay::Report::try_from((s, Option<interface>, mode, frames))` |
| `interfaces::Report::new(infos)` | `interfaces::Report::from(infos)` |

The other command outputs follow the same pattern (exchange, traceroute, dns,
tls, expert, follow, and the reassembly report). A library value the published
contract has no spelling for (a future variant of a `non_exhaustive` enum) fails
with `contract::Error::Unpublished` (`internal.error`), except an error
coordinate, which is omitted like other optional error metadata.

`output::protocols::Detail` embeds a flattened `summary: Summary` instead of
repeating its seven fields: `detail.protocol`, `.aliases`, `.build`,
`.dissect`, `.exact_round_trip`, `.matcher`, and `.decode_only` become
`detail.summary.<field>`. The JSON is unchanged, and the summary keys are still
flattened at the top level. `FilterField::for_protocol` and
`FilterField::from_binding` are removed; use
`FilterField::try_from((path, binding))`, which returns
`Err(contract::Error::Unpublished)` for a binding variant the contract has no
spelling for instead of omitting it from `filter_fields`.

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
| `scan::Limits`, `traceroute::Limits`, `dns::Limits` fields `max_evidence_frames`, `max_evidence_bytes`, `max_undecoded` | `limits.evidence` (`evidence::Limits { max_frames, max_bytes, max_undecoded }`); serialized names unchanged |

### packetcraftr-cli

| 0.5.0-beta.3 | Current main |
| --- | --- |
| `output::contract::SCHEMA_V2` | `output::contract::SCHEMA_V12` |
| `Command::require_format(format) -> Result<(), Error>` | `require_format(format) -> Result<Format, Error>` |
| `impl clap::ValueEnum` for `output::contract::Format` and `output::stats::Table` | removed; declare your own value enum and convert with `From` |
| `try_from_*`, `from_*`, and `complete_from_*` constructors on output types | `From`/`TryFrom`, yielding `output::envelope::Published<T>` where diagnostics or stats travel with the result (see [Output field types](#output-field-types)) |

## Callers tracking main

Items introduced and removed entirely after beta.3 have no released migration.
Pin a reviewed revision rather than depending on intermediate names. This cleanup
changes provider composition only; CLI behavior and output/v12 remain unchanged:

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
These semantics are retained in current output/v12; historical native evidence
keeps its original schema identity. See [scanner timing](scanner-evidence.md).
