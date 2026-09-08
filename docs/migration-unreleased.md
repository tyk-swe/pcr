# Migrating from 0.5.0-beta.3

These notes describe the pending changes in `[Unreleased]`.

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
