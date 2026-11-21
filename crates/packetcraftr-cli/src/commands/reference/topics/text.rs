// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) const EXPRESSIONS: &str = r#"Packet expressions

A packet expression stacks protocol layers from outermost inward, separated by
`/`. Each layer is `protocol(field=value, ...)`, and a bare protocol name takes
defaults. Protocol and field names are case-insensitive and accept schema
aliases (`src`, `dst`, `sport`, `dport`). Run `packetcraftr reference protocols [NAME]`
to inspect protocols and fields.

Supply `--packet`, `--packet-file` (`packetcraftr.packet/v1` JSON or YAML, up
to 16 MiB), or stdin when neither is given.

Examples:
    raw(text=hello)
    ethernet()/ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=40000,dport=53)
    ipv4(src=192.0.2.1,dst=198.51.100.7,ttl=5)/tcp(dport=443)/raw(bytes=hex("16030100"))
    ipv6(src=2001:db8::1,dst=2001:db8::2)/udp(dport=9000)/raw(text=ping)

Values:
  Integers: decimal, `0x` hex, `0b` binary, `0o` octal (`_` separators allowed).
  Addresses and booleans: IPv4, IPv6, MAC (`02:00:00:00:00:01`), `true`, `false`.
  Text: bare word or double-quoted string with `\n`, `\r`, `\t`, `\"`, `\\`.
  Lists and objects: `[80,443]`, `{name="example.test",type=1}`.
  Bytes (shared 1 MiB generated-byte budget per expression):
    hex("0aff")
    bytes("GET / HTTP/1.1\r\n")
    repeat(0x41,16)
    zeros(8)
    cyclic(32)                # Aa0Aa1Aa2... up to 20280 bytes

Limits: 1 MiB text, 64 layers, 64 nesting levels.

Selectors (`--set`, `--axis`, `--payload-file`, and `packet fuzz --field`):
  `<protocol>[#occurrence].<field>` (1-based from outermost) or zero-based `LAYER.FIELD`.
    ipv4.ttl
    ipv4#2.ttl
    udp.destination_port
    1.dport

Overrides and axes:
  `--set SELECTOR=VALUE` applies up to 64 field overrides in order before expansion.
  `--axis SELECTOR=[V1,V2,...]` or `SELECTOR=START..END[:STEP]` expands a Cartesian
  product over expression value lists or inclusive unsigned integer ranges (`STEP`
  defaults to 1, last axis varies fastest, bounded by `--max-template-packets`,
  default 10000).

See also `packetcraftr reference topics filters`.
"#;

pub(super) const FILTERS: &str = r#"Display filters

A boolean expression over one dissected frame, accepted as `--filter` by
`packet dissect`, `files read`, `files rewrite`, `files export`, `analyze stats`,
`analyze expert`, `analyze inventory`, `analyze quic`, `analyze http3`,
`analyze hunt`, `analyze dns-anomalies`, `analyze beacons`, `network capture`,
and `network replay` (plus `--ingress-filter` and `--egress-filter` on
`analyze verify-forwarding`, and `--map-filter` on `network replay`).

Paths:
  A bare protocol tests presence, and a bare flag tests that bit (`!tcp.flags.ack`).
  Reserved `frame.*` and `*.stream` resolve first, registered aliases second,
  and schema paths last.
    tcp
    ip.src == 192.0.2.1
    tcp.flags.syn == 1 && !tcp.flags.ack
    udp.destination_port == 53

Operators:
  ==  !=  <  <=  >  >=    (or eq ne lt le gt ge)
  &&  ||  !               (or and, or, not)
  in                      membership in a value or `{a, b..c}` set (including CIDR prefixes and `A..B` ranges)
  contains                substring or byte-sequence search
  startswith  endswith    anchored text or byte search
  icontains  iequals      ASCII case-insensitive search or equality (no regex)
    dns.qname endswith ".example.com."
    tls.sni icontains "EXAMPLE"
    raw.bytes startswith b"GET "
    ip.src in 192.0.2.0/24
    udp.port in {53, 5353, 49152..65535}

Masks, literals, and slices:
  `field & MASK` tests masked bits (`tcp.flags & 0x12 == 0x12`).
  Quoted text supports `\\`, `\"`, `\r`, `\n`, `\t`, `\0`, and `\x00`..`\x7f`.
  Byte literals use `b"..."` (`\x00`..`\xff`) or colon- or dash-separated hex
  pairs (`02:00:00`, at least two bytes). Unquoted hex words like `c000` or
  malformed groups like `c0:0` are rejected on byte fields.
  `path[N]` and `path[START:END]` slice bytes (`ethernet.source[0:3] == 02:00:00`).

Lists, functions, and tunnel occurrences:
  List fields take `[N]`, `[*]` (any element), or `[-1]` (last).
  `len(path)` returns byte length and `count(path)` returns list length, each
  compared to an unsigned integer.
  `#n` selects the nth occurrence from outermost, and `#last` or `#-1` selects innermost.
    dns.answers[*].type == 1
    len(raw.bytes) > 1400 || count(tcp.options) > 4
    ipv4#1.destination == 192.0.2.5 || ipv4#last.destination == 192.0.2.5

Reserved fields:
  `frame.number`, `frame.time_epoch`, `frame.time_nsec`, `frame.len`,
  `frame.cap_len`, `frame.interface_id`, `frame.link_type`, `frame.direction`,
  `frame.truncated`, `frame.layer_count`, `frame.protocols` (whole-list
  comparison, search, and `count()` only).
  `tcp.stream` and `udp.stream` are supported by conversation-numbering commands
  (`files read --field`, `files export`, `analyze stats`, `analyze expert`,
  `analyze inventory`, `analyze quic`, `analyze http3`, `analyze hunt`,
  `analyze dns-anomalies`, `analyze beacons`, and `analyze verify-forwarding`).
  Frame-only commands (`packet dissect`, `files read` without `--field`,
  `files rewrite`, `network capture`, and `network replay`) reject stream filters.

Limits: 64 KiB text, 1024 terms, 1024 set members, 64 nesting levels.

See also `packetcraftr reference topics expressions`.
"#;

pub(super) const SCOPE: &str = r"Engagement scope

Commands accept `--scope-file PATH` with a `packetcraftr.scope/v1` JSON
document (a regular file, at most 1 MiB). One Scope can be reused across
`network preflight`, `network plan`, `network send`, `network exchange`,
`network capture` (budgets only), `network replay`, `network scan`,
`network identify`, `network identify-os`, `network traceroute`, `network dns`,
`network audit-tls`, `network audit-http`, `network differential`,
`packet fuzz` (with `--live`), and `analyze report` (records the Scope digest
in the report and both label and digest in the Evidence bundle).

A Scope only narrows. Its `allow_*` booleans are ceilings, so a Scope can take
away a policy opt-in the flags gave and can never grant one they did not.
`max_packets` and `max_bytes` keep the smaller of the Scope and flag budgets. A
destination must satisfy the flag allowlist, every Scope `allowed_destinations`
group, and no `denied_destinations` entry, and the public destination check
still applies after all of those.

Fields:
  schema (required)         the string `packetcraftr.scope/v1`
  label (required)          printable string, 1 to 128 characters
  allowed_destinations      up to 1024 IP addresses or canonical CIDR networks
  denied_destinations       up to 1024 IP addresses or canonical CIDR networks
  allow_public_destinations, allow_hostname_resolution,
  allow_permissive_packets, allow_source_spoofing
                            boolean ceilings, false when omitted
  max_packets, max_bytes    optional budget ceilings

Unknown fields are rejected. Destination entries must spell the canonical
network address, so `192.0.2.0/24` is accepted and `192.0.2.1/24` is not.

Run `packetcraftr network preflight --scope-file PATH` to validate a Scope
without sending anything. It prints the label and a digest of the Scope
contents, which is stable across JSON formatting and list order, so an
engagement record can name the exact Scope a run used.

See `examples/documents/scope.json` and
`schemas/packetcraftr.scope.v1.schema.json`.
";
