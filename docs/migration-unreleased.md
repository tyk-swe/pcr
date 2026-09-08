# Migrating from 0.5.0-beta.3

These notes describe the pending changes in `[Unreleased]`.

## Numeric DNS types and output/v3

All structured command envelopes now identify `packetcraftr.output/v3` and
validate against `schemas/packetcraftr.output.v3.schema.json`. Packet documents
remain `packetcraftr.packet/v1`.

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
contract constant is now `SCHEMA_V3`.
The `.as_str()` method is removed; use `Display` or `.to_string()` instead.
Text parsing returns `QueryTypeParseError`, preserving the original integer
parse error for out-of-range values.
CLI DNS output structs store `query_type` as `u16`; use `.code()` when
constructing their summaries or events from a `QueryType`.

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
the output/v3 and packet/v1 contracts are unchanged by these request settings.

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

A bare `packetcraftr::probe::ExchangeExecutor` now reports unsupported TCP
fallback. Opt in with `.with_dns_tcp(provider)`; the CLI selects
`packetcraftr_netio::tcp::SystemProvider` explicitly. Injected UDP providers
therefore cannot silently open a system TCP socket after a truncated response.

Low-level callers pass a provider to `dns::tcp::exchange(request, &provider)`.
`packetcraftr_netio::tcp::{Provider, Stream}` owns the narrow connection and
stream capability; `dns::tcp` retains framing, finite deadlines, and evidence.
The standard-library provider works independently of native packet and route
feature flags. Interface, preferred-source, and link-mode overrides remain
unsupported for kernel TCP, and each fallback retains endpoint reauthorization
and final query-byte checks.
