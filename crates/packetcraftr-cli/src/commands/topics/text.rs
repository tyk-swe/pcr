// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) const EXPRESSIONS: &str = r#"Packet expressions

A packet expression stacks protocol layers from outermost inward, separated by
`/`. Each layer is `protocol(field=value, ...)`; a bare protocol name takes
defaults. Protocol and field names are case-insensitive and accept schema
aliases (`src`, `dst`, `sport`, `dport`). Run `packetcraftr reference protocols [NAME]`
to inspect protocols and fields.

Supply `--packet`, `--packet-file` (JSON/YAML), or stdin when neither is given.

Examples:
    raw(text=hello)
    ethernet()/ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=40000,dport=53)
    ipv4(src=192.0.2.1,dst=198.51.100.7,ttl=5)/tcp(dport=443)/raw(bytes=hex("16030100"))
    ipv6(src=2001:db8::1,dst=2001:db8::2)/udp(dport=9000)/raw(text=ping)

Values:
  Integers: decimal, `0x` hex, `0b` binary, `0o` octal (`_` separators allowed).
  Addresses & booleans: IPv4, IPv6, MAC (`02:00:00:00:00:01`), `true`, `false`.
  Text: bare word or double-quoted string with `\n`, `\r`, `\t`, `\"`, `\\`.
  Lists & objects: `[80,443]`, `{name="example.test",type=1}`.
  Bytes (shared 1 MiB generated-byte budget per expression):
    hex("0aff")
    bytes("GET / HTTP/1.1\r\n")
    repeat(0x41,16)
    zeros(8)
    cyclic(32)                # Aa0Aa1Aa2... up to 20280 bytes

Limits: 1 MiB text, 64 layers, 64 nesting levels.

Selectors (`--set`, `--axis`, `--payload-file`):
  `<protocol>[#occurrence].<field>` (1-based from outermost) or zero-based `LAYER.FIELD`.
    ipv4.ttl
    ipv4#2.ttl
    udp.destination_port
    1.dport

Overrides & axes:
  `--set SELECTOR=VALUE` applies up to 64 field overrides in order before expansion.
  `--axis SELECTOR=[V1,V2,...]` or `SELECTOR=START..END[:STEP]` expands a Cartesian
  product (last axis varies fastest, bounded by `--max-template-packets`).

See also `packetcraftr reference topics filters`.
"#;

pub(super) const FILTERS: &str = r#"Display filters

A boolean expression over one dissected frame, accepted as `--filter` by `read`,
`dissect`, `capture`, `stats`, `expert`, `export`, `rewrite`, and `replay`.

Paths:
  A bare protocol tests presence; a bare flag tests that bit (`!tcp.flags.ack`).
  Reserved `frame.*` and `*.stream` resolve first, registered aliases second,
  and schema paths last.
    tcp
    ip.src == 192.0.2.1
    tcp.flags.syn == 1 && !tcp.flags.ack
    udp.destination_port == 53

Operators:
  ==  !=  <  <=  >  >=    (or eq ne lt le gt ge)
  &&  ||  !               (or and, or, not)
  in                      membership in a CIDR prefix, `A..B` range, or `{a, b..c}` set
  contains                substring or byte-sequence search
  startswith  endswith    anchored text or byte search
  icontains  iequals      ASCII case-insensitive search/equality (no regex)
    dns.qname endswith ".example.com."
    tls.sni icontains "EXAMPLE"
    raw.bytes startswith b"GET "
    ip.src in 192.0.2.0/24
    udp.port in {53, 5353, 49152..65535}

Masks, literals, and slices:
  `field & MASK` tests masked bits (`tcp.flags & 0x12 == 0x12`).
  Quoted text supports `\\`, `\"`, `\r`, `\n`, `\t`, `\0`, and `\x00`..`\x7f`.
  Byte literals use `b"..."` (`\x00`..`\xff`) or separated hex pairs (`02:00:00`);
  unquoted hex words like `c000` or `c0:0` are rejected.
  `path[N]` and `path[START:END]` slice bytes (`ethernet.source[0:3] == 02:00:00`).

Lists, functions, and tunnel occurrences:
  List fields take `[N]`, `[*]` (any element), or `[-1]` (last).
  `len(path)` returns byte length; `count(path)` returns list length.
  `#n` selects the nth occurrence from outermost; `#last` or `#-1` selects innermost.
    dns.answers[*].type == 1
    len(raw.bytes) > 1400 || count(tcp.options) > 4
    ipv4#1.destination == 192.0.2.5 || ipv4#last.destination == 192.0.2.5

Reserved fields:
  `frame.number`, `frame.time_epoch`, `frame.time_nsec`, `frame.len`,
  `frame.cap_len`, `frame.interface_id`, `frame.link_type`, `frame.direction`,
  `frame.truncated`, `frame.layer_count`, `frame.protocols` (whole-list and
  `count()` only).
  `tcp.stream` and `udp.stream` are supported by conversation-numbering commands
  (`stats`, `expert`, `export`, `verify-forwarding`, and `read --field`).

Limits: 64 KiB text, 1024 terms, 1024 set members, 64 nesting levels.

See also `packetcraftr reference topics expressions`.
"#;
