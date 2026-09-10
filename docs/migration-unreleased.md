# Migrating from 0.5.0-beta.3

These notes describe the pending changes in `[Unreleased]`.

## Numeric DNS types and output/v4

All structured command envelopes now identify `packetcraftr.output/v4` and
validate against `schemas/packetcraftr.output.v4.schema.json`. Packet documents
remain `packetcraftr.packet/v1`.

Output/v4 also adds streamed `build` packet/completion events and replay
`{"bit_rate": BITS_PER_SECOND}` timing. Successful TCP DNS can have
`fallback_attempted=false`: this represents a direct TCP query. Consumers
must inspect the actual attempt transport rather than infer it from fallback.
Fallback attempts retain a preceding truncated UDP phase with the same attempt
number. These changes supersede the earlier unreleased output/v3 contract.

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
contract constant is now `SCHEMA_V4`.
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

Rust `scan::Request` and `scan::Probe` gain `udp_payload: bytes::Bytes`; add
`udp_payload: bytes::Bytes::new()` to request/probe literals to retain empty
datagrams. Request deserialization defaults missing payloads to empty.
`scan::Probe` is now `Clone` rather than `Copy`, with shared payload storage.
Payloads are bounded to `scan::MAX_UDP_PAYLOAD_BYTES` (65,507), included in the
operation budget, and rejected when non-empty for TCP or ICMP.

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
the output/v4 and packet/v1 contracts are unchanged by these request settings.

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

DNS reflection adds `answers`, `authorities`, and `additionals` fields. Each is
a list of `[owner, type_code, class, ttl, rdata]` records using the existing typed
`FieldValue` lists. The `rdata` list starts with a tag:

| Tag | Following values |
| --- | --- |
| `a`, `aaaa` | IPv4 or IPv6 address |
| `cname`, `ns`, `ptr` | Name |
| `mx` | Preference, exchange name |
| `soa` | Primary name server, responsible mailbox, serial, refresh, retry, expire, minimum |
| `srv` | Priority, weight, port, target name |
| `caa` | Flags, tag bytes, value bytes |
| `txt` | List of character-string bytes |
| `unknown` | Exact RDATA bytes |
| `opt` | UDP payload size, extended response code, version, DO bit, flags, list of `[option_code, option_bytes]` |

Ordinary typed records are decoded for the Internet (`IN`) class. Other
classes retain exact RDATA as `unknown`; their class-specific formats are not
interpreted as Internet addresses or records.

OPT records remain in their original section. Offline inspection retains
unknown EDNS versions; live queries still enforce their existing OPT version,
owner, section, and uniqueness rules. These fields fit the existing recursive
packet/v1 field contract.

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

Existing client constructors, public limit structs and default output/v4 records
remain compatible. Share callback admission explicitly with
`client.with_progress_runtime(runtime.clone())`; inspect it with
`client.progress_runtime().snapshot()`. Native admission remains process-wide.

`--resource-diagnostics` opts into an optional `resources` envelope member.
Older strict output schemas may reject this member, so upgrade those consumers
before enabling it. No additional NDJSON events or sequence positions are added.
`--output-timeout-ms` affects NDJSON writes only; the default and terminal-error
cleanup allowance remain one second, and operation deadlines take precedence.

TCP memory charges now include payload-page slack and transient allocations.
A previously accepted capture near an aggregate limit can be rejected earlier;
raise an explicit budget only after considering the hosting process limit.
Packet-document key reordering no longer changes semantic acceptance. Existing
input/depth and duplicate-field checks still apply. See
[resource contracts](analysis-resources.md).
