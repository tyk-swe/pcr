# Built-in protocol support

This document defines PacketcraftR's built-in packet-layer contract. The
matching public Rust value is `BUILTIN_PROTOCOL_SUPPORT`; serializing it
produces a manifest whose schema identifier is
`packetcraftr.protocol-support/v1`. Registry invariant tests require the
manifest to contain exactly every built-in codec, numeric capture root,
response matcher, and CLI workflow.

This is a protocol-layer contract. The [platform matrix](platform-support.md)
records separate native capability and privilege requirements.

## Codec matrix

“Exact” means an untouched decoded layer stack rebuilds the original protocol
bytes. `raw_ip` is a decode-only dispatch root: it selects IPv4 or IPv6 from the
first nibble, and the resulting typed packet rebuilds exactly.

| Protocol ID | Expression aliases | Build | Dissect | Exact | Matcher |
| --- | --- | :---: | :---: | :---: | :---: |
| `arp` | — | Yes | Yes | Yes | — |
| `bsd_loop` | `loop` | Yes | Yes | Yes | — |
| `bsd_null` | `null` | Yes | Yes | Yes | — |
| `ethernet` | `eth`, `ether`, `ethernet2` | Yes | Yes | Yes | — |
| `icmpv4` | `icmp`, `icmp4` | Yes | Yes | Yes | Yes |
| `icmpv6` | `icmp6` | Yes | Yes | Yes | Yes |
| `ipv4` | `ip`, `ip4` | Yes | Yes | Yes | — |
| `ipv6` | `ip6` | Yes | Yes | Yes | — |
| `ipv6_destination_options` | `destopts`, `destination_options` | Yes | Yes | Yes | — |
| `ipv6_fragment` | `fragment6`, `frag6` | Yes | Yes | Yes | — |
| `ipv6_hop_by_hop` | `hop`, `hopopts`, `hbh` | Yes | Yes | Yes | — |
| `ipv6_srh` | `srh`, `segment_routing` | Yes | Yes | Yes | — |
| `linux_sll` | `sll` | Yes | Yes | Yes | — |
| `linux_sll2` | `sll2` | Yes | Yes | Yes | — |
| `malformed` | — | Yes | Yes | Yes | — |
| `padding` | `pad` | Yes | Yes | Yes | — |
| `raw` | `payload`, `bytes` | Yes | Yes | Yes | — |
| `raw_ip` | `rawip` | Decode-only | Yes | Yes | — |
| `tcp` | — | Yes | Yes | Yes | Yes |
| `udp` | — | Yes | Yes | Yes | Yes |
| `vlan` | `dot1q`, `8021q` | Yes | Yes | Yes | — |
| `vlan8021ad` | `dot1ad`, `8021ad`, `qinq` | Yes | Yes | Yes | — |

The four matchers correlate reverse TCP/UDP tuples and ICMPv4/ICMPv6 echo
responses. They do not infer application protocols from port numbers.

## Capture roots

Numeric DLT/LINKTYPE values remain open: an unregistered value is preserved as
one `raw` layer with a typed diagnostic. The default registry has these exact
nine bindings:

| DLT/LINKTYPE | Root codec | Byte-order rule | Fixture evidence |
| ---: | --- | --- | --- |
| 0 | `bsd_null` | Captured host order, little or big | Both orders, exact rebuild |
| 1 | `ethernet` | Protocol-defined | Exact rebuild |
| 12 | `raw_ip` | IP-defined | IPv4 exact rebuild |
| 101 | `raw_ip` | IP-defined | IPv4 and IPv6 exact rebuild |
| 108 | `bsd_loop` | Network order | IPv6 exact rebuild |
| 113 | `linux_sll` | Network order | IPv4 exact rebuild |
| 228 | `ipv4` | IP-defined | IPv4 exact rebuild |
| 229 | `ipv6` | IP-defined | IPv6 exact rebuild |
| 276 | `linux_sll2` | Network order | IPv6 exact rebuild |

The provenance-checked corpus also contains an unregistered DLT 147 frame to
verify unknown-root raw preservation.

## Workflow obligations

The manifest maps all 14 command names to concrete build, dissect,
matcher, and capture-root obligations. “Live recipe” includes the constructible
Ethernet/VLAN, ARP, IPv4/IPv6/extension, ICMP, TCP, UDP, raw, padding, and
explicit malformed layers; capture-only BSD/SLL envelopes fail explicitly in
live planning.

| Workflow | Build obligation | Dissect/matcher obligation | Capture roots |
| --- | --- | --- | :---: |
| `build` | Every constructible codec | — | — |
| `dissect` | — | Every codec | Yes |
| `plan` | Live recipe | — | — |
| `send` | Live recipe and route materialization | — | — |
| `exchange` | Live recipe | Every codec; all four matchers | Yes |
| `capture` | Live route recipe | Preserve frames without relabeling | Yes |
| `read` | — | Preserve capture records | Yes |
| `replay` | — | Preserve authoritative frames | Yes |
| `scan` | Live recipe | Every codec; all four matchers | Yes |
| `traceroute` | Live recipe | Every codec; all four matchers | Yes |
| `dns` | Ethernet/VLAN, IPv4/IPv6, TCP/UDP, raw | Same stack; TCP/UDP matchers | Yes |
| `fuzz` | Every constructible codec | Every codec; all four matchers for optional live cases | Yes for optional live cases |
| `interfaces` | Packet-independent | — | — |
| `routes` | Packet-independent | — | — |

DNS message parsing and correlation are owned by the structured DNS workflow;
UDP/TCP destination port 53 does not cause implicit DNS dissection. The live
CLI uses capture-ready UDP; the pure length-prefixed TCP frame decoder applies
the same bounded message validation without claiming a raw TCP packet is a
connected DNS session. Replay and read preserve captured bytes and metadata
rather than manufacturing a typed interpretation.

Fuzzing enumerates reflective fields from every constructible codec. Offline
cases build and dissect without a native boundary. Explicit live cases reuse
the normal route materialization, registered response matchers, capture roots,
traffic policy, and permissive-packet opt-in instead of introducing a
payload-only or protocol-specific send path.

## Strictness and preservation

- Strict building derives or validates discriminators, dependent lengths, and
  checksums. A known discriminator requires its registered typed child; `raw`
  cannot bypass that codec.
- Permissive building may preserve deliberate dependent-field mismatches with
  diagnostics. Sending those bytes requires both policy and operation opt-in.
- Unknown discriminators remain `raw` and rebuild exactly. Truncated or invalid
  known layers become explicit `malformed` evidence instead of being dropped.
- IPv4/IPv6 declared lengths bound child decoding; extra link bytes remain
  `padding`. Fragment payloads stay raw until the bounded reassembly stage.
- IPv6 Hop-by-Hop is accepted only immediately after IPv6. The supported typed
  routing header is RFC 8754 SRH; routing type 0 and unsupported generic routing
  headers fail explicitly.
- External modules register through the same codec/binding/matcher interfaces
  and are tested from outside the crate. They do not mutate the built-in
  manifest or receive a fallback around strict discriminator rules.

The authoritative corpus and its maintenance rules are documented in the
[fixture policy](../tests/fixtures/README.md).
