# Packet v2 Field Audit

This document records the migration of all reflective layer fields from the legacy `derived: bool, required: bool` model to the Packet v2 `Tier` system (`Required`, `Derived`, `Optional`), including constant defaults, integer maximums, aliases, and list element kinds.

## Reclassified as Derived

All fields with computed or contextual wire values across all protocols were audited against their respective `LayerCodec::encode` implementations. In the PacketcraftR codebase, computed fields already use `WireValue<T>` members and were previously marked `derived: true`. The audit confirmed their derivations:

- `ipv4.total_length` (`WireValue<u16>`): `ipv4.rs:111` computes total packet length from header and covered payload.
- `ipv4.protocol` (`WireValue<u8>`): `ipv4.rs:125` resolves next protocol discriminator from child layer binding.
- `ipv4.checksum` (`WireValue<u16>`): `ipv4.rs:133` computes IPv4 one's-complement header checksum.
- `ipv6.payload_length` (`WireValue<u16>`): `ipv6.rs:94` computes IPv6 payload length from covered payload.
- `ipv6.next_header` (`WireValue<u8>`): `ipv6.rs:108` resolves IPv6 next-header discriminator from child layer binding.
- `ipv6_fragment.next_header` (`WireValue<u8>`): `ipv6/fragment.rs:111` resolves next-header discriminator.
- `ipv6_hop_by_hop.next_header` (`WireValue<u8>`): `ipv6/options.rs:99` resolves next-header discriminator.
- `ipv6_destination_options.next_header` (`WireValue<u8>`): `ipv6/options.rs:99` resolves next-header discriminator.
- `ipv6_srh.next_header` (`WireValue<u8>`): `ipv6/srh.rs:105` resolves next-header discriminator.
- `ipv6_srh.segments_left` (`WireValue<u8>`): `ipv6/srh.rs:115` suggested default derived from final segment index.
- `ipv6_srh.last_entry` (`WireValue<u8>`): `ipv6/srh.rs:134` computed from `segments.len() - 1`.
- `arp.hardware_len` (`WireValue<u8>`): `arp.rs:108` derived as 6 for Ethernet hardware type.
- `arp.protocol_len` (`WireValue<u8>`): `arp.rs:118` derived as 4 for IPv4 protocol type.
- `ethernet.ether_type` (`WireValue<u16>`): `ethernet.rs:198` resolves EtherType discriminator from child layer.
- `llc/snap.protocol_id` (`WireValue<u16>`): `llc.rs:275` resolves EtherType/protocol discriminator from child layer.
- `vlan.ether_type` (`WireValue<u16>`): `vlan.rs:125` resolves encapsulated EtherType from child layer.
- `vlan8021ad.ether_type` (`WireValue<u16>`): `vlan.rs:125` resolves encapsulated EtherType from child layer.
- `igmp.checksum` (`WireValue<u16>`): `igmp.rs:110` computes IGMP message checksum.
- `icmpv4.checksum` (`WireValue<u16>`): `icmp.rs:130` computes ICMPv4 header and payload checksum.
- `icmpv6.checksum` (`WireValue<u16>`): `icmp.rs:226` computes ICMPv6 pseudo-header and message checksum.
- `sctp.checksum` (`WireValue<u32>`): `sctp.rs:121` computes SCTP CRC32c checksum.
- `tcp.checksum` (`WireValue<u16>`): `tcp.rs:141` computes TCP pseudo-header and segment checksum.
- `udp.length` (`WireValue<u16>`): `udp.rs:109` computes UDP header + payload length.
- `udp.checksum` (`WireValue<u16>`): `udp.rs:128` computes UDP pseudo-header and datagram checksum.
- `ah.next_header` (`WireValue<u8>`): `ah.rs:115` resolves authenticated payload next-header discriminator.
- `ah.payload_length` (`WireValue<u8>`): `ah.rs:133` computes AH header length from ICV length.
- `pppoe.length` (`WireValue<u16>`): `pppoe.rs:98` computes PPPoE payload length.
- `ppp.protocol` (`WireValue<u16>`): `pppoe.rs:335` resolves PPP protocol discriminator from child layer.
- `linux_sll.protocol` (`WireValue<u16>`): `sll.rs:121` resolves SLL protocol discriminator from child layer.
- `linux_sll2.protocol` (`WireValue<u16>`): `sll.rs:221` resolves SLL2 protocol discriminator from child layer.
- `gre.protocol_type` (`WireValue<u16>`): `gre.rs:124` resolves encapsulated EtherType from child layer.
- `gre.checksum` (`Option<WireValue<u16>>`): `gre.rs:143` computes GRE header and payload checksum when enabled.
- `geneve.protocol_type` (`WireValue<u16>`): `geneve.rs:143` resolves encapsulated EtherType from child layer.

## Decode-Only Layers

The following protocol layers have setters that return `FieldError::ReadOnly` exclusively and cannot be constructed from documents:
- `dns` (`protocol/application/dns.rs`): `decode_only: true`
- `tls` (`protocol/application/tls/codec.rs`): `decode_only: true`

## Field Audit Table

| Protocol | Field | Old derived/required | New Tier | Default | Max | Element | Note |
|---|---|---|---|---|---|---|---|
| `raw` | `bytes` | derived=false, required=false | `Optional` | `"0x"` | - | - | Verbatim bytes, empty by default |
| `padding` | `bytes` | derived=false, required=false | `Optional` | `"0x"` | - | - | Trailing padding bytes |
| `padding` | `outside_layer` | derived=false, required=false | `Optional` | `"0"` | 18446744073709551615 | - | Excluded layer index; None on link padding default |
| `malformed` | `protocol` | derived=false, required=false | `Optional` | `""` | - | - | Intended protocol identifier; None on default |
| `malformed` | `bytes` | derived=false, required=false | `Optional` | `"0x"` | - | - | Preserved malformed bytes |
| `malformed` | `reason` | derived=false, required=true | `Required` | - | - | - | Decode or construction finding |
| `dns` | `id` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Transaction identifier |
| `dns` | `response` | derived=false, required=false | `Optional` | `"false"` | - | - | Query/response flag |
| `dns` | `opcode` | derived=false, required=false | `Optional` | `"0"` | 15 | - | 4-bit operation code |
| `dns` | `authoritative_answer` | derived=false, required=false | `Optional` | `"false"` | - | - | Authoritative-answer flag |
| `dns` | `truncated` | derived=false, required=false | `Optional` | `"false"` | - | - | Truncated response flag |
| `dns` | `recursion_desired` | derived=false, required=false | `Optional` | `"false"` | - | - | Recursion-desired flag |
| `dns` | `recursion_available` | derived=false, required=false | `Optional` | `"false"` | - | - | Recursion-available flag |
| `dns` | `authenticated_data` | derived=false, required=false | `Optional` | `"false"` | - | - | Authenticated-data flag |
| `dns` | `checking_disabled` | derived=false, required=false | `Optional` | `"false"` | - | - | Checking-disabled flag |
| `dns` | `rcode` | derived=false, required=false | `Optional` | `"0"` | 15 | - | 4-bit response code |
| `dns` | `question_count` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Question count |
| `dns` | `answer_count` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Answer count |
| `dns` | `authority_count` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Authority-record count |
| `dns` | `additional_count` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Additional-record count |
| `dns` | `qname` | derived=false, required=false | `Optional` | `"[]"` | - | Text | Question names list |
| `dns` | `qtype` | derived=false, required=false | `Optional` | `"[]"` | - | Unsigned | Question type codes list |
| `dns` | `qclass` | derived=false, required=false | `Optional` | `"[]"` | - | Unsigned | Question class codes list |
| `tls` | `content_type` | derived=false, required=false | `Optional` | `"0"` | 255 | - | Record content type |
| `tls` | `version` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Record version |
| `tls` | `record_count` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Complete records in segment |
| `tls` | `handshake_type` | derived=false, required=false | `Required` | - | 255 | - | Handshake message type |
| `tls` | `cipher_suite` | derived=false, required=false | `Required` | - | 65535 | - | Selected cipher suite |
| `tls` | `selected_version` | derived=false, required=false | `Required` | - | 65535 | - | Selected version |
| `tls` | `key_share_group` | derived=false, required=false | `Required` | - | 65535 | - | Key share group |
| `tls` | `incomplete` | derived=false, required=false | `Optional` | `"false"` | - | - | Incomplete record flag |
| `tls` | `ech` | derived=false, required=false | `Optional` | `"false"` | - | - | Encrypted client hello flag |
| `tls` | `sni` | derived=false, required=false | `Required` | - | - | - | Server name indication |
| `tls` | `sni_raw` | derived=false, required=false | `Required` | - | - | - | Raw SNI bytes |
| `tls` | `ja3` | derived=false, required=false | `Required` | - | - | - | JA3 fingerprint hash |
| `tls` | `ja3_raw` | derived=false, required=false | `Required` | - | - | - | JA3 fingerprint string |
| `tls` | `ja4` | derived=false, required=false | `Required` | - | - | - | JA4 fingerprint string |
| `tls` | `alpn` | derived=false, required=false | `Required` | - | - | Text | ALPN protocol list |
| `tls` | `cipher_suites` | derived=false, required=false | `Required` | - | - | Unsigned | Client cipher suites list |
| `tls` | `supported_versions` | derived=false, required=false | `Required` | - | - | Unsigned | Supported versions list |
| `tls` | `supported_groups` | derived=false, required=false | `Required` | - | - | Unsigned | Supported groups list |
| `bsd_loop` | `family` | derived=false, required=true | `Required` | - | 4294967295 | - | Address-family discriminator |
| `bsd_null` | `family` | derived=false, required=true | `Required` | - | 4294967295 | - | Address-family discriminator |
| `bsd_null` | `byte_order` | derived=false, required=true | `Required` | - | - | - | Byte order ("little" or "big") |
| `linux_sll` | `protocol` | derived=true, required=false | `Derived` | - | 65535 | - | Protocol discriminator (wire) |
| `linux_sll` | `packet_type` | derived=false, required=true | `Required` | - | 65535 | - | Packet direction/type |
| `linux_sll` | `arp_hardware_type` | derived=false, required=true | `Required` | - | 65535 | - | ARP hardware type |
| `linux_sll` | `address_length` | derived=false, required=true | `Required` | - | 8 | - | Link address length, bounded by 8 |
| `linux_sll` | `address` | derived=false, required=false | `Optional` | `"0x0000000000000000"` | - | - | Eight-byte link address slot |
| `linux_sll2` | `protocol` | derived=true, required=false | `Derived` | - | 65535 | - | Protocol discriminator (wire) |
| `linux_sll2` | `packet_type` | derived=false, required=true | `Required` | - | 255 | - | Packet direction/type |
| `linux_sll2` | `arp_hardware_type` | derived=false, required=true | `Required` | - | 65535 | - | ARP hardware type |
| `linux_sll2` | `interface_index` | derived=false, required=false | `Optional` | `"0"` | 4294967295 | - | Interface index |
| `linux_sll2` | `address_length` | derived=false, required=true | `Required` | - | 8 | - | Link address length, bounded by 8 |
| `linux_sll2` | `address` | derived=false, required=false | `Optional` | `"0x0000000000000000"` | - | - | Eight-byte link address slot |
| `gre` | `protocol_type` | derived=true, required=false | `Derived` | - | 65535 | - | Encapsulated EtherType (wire) |
| `gre` | `checksum` | derived=true, required=false | `Derived` | - | 65535 | - | Optional GRE checksum (derived when enabled) |
| `gre` | `key` | derived=false, required=false | `Optional` | `"0"` | 4294967295 | - | Optional GRE key (None in default) |
| `gre` | `sequence` | derived=false, required=false | `Optional` | `"0"` | 4294967295 | - | Optional GRE sequence (None in default) |
| `gre` | `reserved_bits` | derived=false, required=false | `Optional` | `"0"` | 255 | - | Reserved bits 6-12 |
| `icmpv4` | `type` | derived=false, required=true | `Required` | - | 255 | - | ICMP message type |
| `icmpv4` | `code` | derived=false, required=true | `Required` | - | 255 | - | ICMP message code |
| `icmpv4` | `checksum` | derived=true, required=false | `Derived` | - | 65535 | - | ICMP checksum (wire) |
| `icmpv4` | `body` | derived=false, required=false | `Optional` | `"0x00000000"` | - | - | Type-specific ICMP body (4 bytes) |
| `icmpv6` | `type` | derived=false, required=true | `Required` | - | 255 | - | ICMPv6 message type |
| `icmpv6` | `code` | derived=false, required=true | `Required` | - | 255 | - | ICMPv6 message code |
| `icmpv6` | `checksum` | derived=true, required=false | `Derived` | - | 65535 | - | ICMPv6 checksum (wire) |
| `icmpv6` | `body` | derived=false, required=false | `Optional` | `"0x00000000"` | - | - | Type-specific ICMPv6 body (4 bytes) |
| `ipv6_fragment` | `next_header` | derived=true, required=false | `Derived` | - | 255 | - | Next-header discriminator (wire) |
| `ipv6_fragment` | `fragment_offset` | derived=false, required=true | `Required` | - | 8191 | - | Offset in 8-byte units (bounded 0x1fff) |
| `ipv6_fragment` | `more_fragments` | derived=false, required=true | `Required` | - | - | - | More-fragments flag |
| `ipv6_fragment` | `identification` | derived=false, required=true | `Required` | - | 4294967295 | - | Fragment identification |
| `ipv6_hop_by_hop` | `next_header` | derived=true, required=false | `Derived` | - | 255 | - | Next-header discriminator (wire) |
| `ipv6_hop_by_hop` | `options` | derived=false, required=false | `Optional` | `"0x"` | - | - | Option TLV bytes |
| `ipv6_destination_options` | `next_header` | derived=true, required=false | `Derived` | - | 255 | - | Next-header discriminator (wire) |
| `ipv6_destination_options` | `options` | derived=false, required=false | `Optional` | `"0x"` | - | - | Option TLV bytes |
| `ipv6_srh` | `next_header` | derived=true, required=false | `Derived` | - | 255 | - | Next-header discriminator (wire) |
| `ipv6_srh` | `segments_left` | derived=true, required=false | `Derived` | - | 255 | - | Remaining segments count (wire) |
| `ipv6_srh` | `last_entry` | derived=true, required=false | `Derived` | - | 255 | - | Highest segment-list index (wire) |
| `ipv6_srh` | `flags` | derived=false, required=false | `Optional` | `"0"` | 255 | - | SRH flags |
| `ipv6_srh` | `tag` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | SRH tag |
| `ipv6_srh` | `segments` (alias `segs`) | derived=false, required=true | `Required` | - | - | Ipv6 | Segment list in visit order |
| `ipv6_srh` | `tlvs` | derived=false, required=false | `Optional` | `"0x"` | - | - | TLV bytes following segment list |
| `arp` | `hardware_type` | derived=false, required=true | `Required` | - | 65535 | - | Hardware address family |
| `arp` | `protocol_type` | derived=false, required=true | `Required` | - | 65535 | - | Protocol address family |
| `arp` | `hardware_len` | derived=true, required=false | `Derived` | - | 255 | - | Hardware address length (wire) |
| `arp` | `protocol_len` | derived=true, required=false | `Derived` | - | 255 | - | Protocol address length (wire) |
| `arp` | `operation` (alias `op`) | derived=false, required=true | `Required` | - | 65535 | - | ARP operation |
| `arp` | `sender_hardware` (alias `sha`) | derived=false, required=true | `Required` | - | - | - | Sender hardware MAC |
| `arp` | `sender_protocol` (alias `spa`) | derived=false, required=true | `Required` | - | - | - | Sender IPv4 address |
| `arp` | `target_hardware` (alias `tha`) | derived=false, required=true | `Required` | - | - | - | Target hardware MAC |
| `arp` | `target_protocol` (alias `tpa`) | derived=false, required=true | `Required` | - | - | - | Target IPv4 address |
| `ethernet` | `destination` (alias `dst`) | derived=false, required=true | `Required` | - | - | - | Destination MAC address |
| `ethernet` | `source` (alias `src`) | derived=false, required=true | `Required` | - | - | - | Source MAC address |
| `ethernet` | `ether_type` | derived=true, required=false | `Derived` | - | 65535 | - | EtherType discriminator (wire) |
| `llc` | `dsap` | derived=false, required=true | `Required` | - | 255 | - | Destination SAP |
| `llc` | `ssap` | derived=false, required=true | `Required` | - | 255 | - | Source SAP |
| `llc` | `control` | derived=false, required=true | `Required` | - | - | - | Control field bytes |
| `snap` | `oui` | derived=false, required=true | `Required` | - | 16777215 | - | OUI, bounded by 0x00ff_ffff |
| `snap` | `protocol_id` | derived=true, required=false | `Derived` | - | 65535 | - | Protocol identifier (wire) |
| `vlan` | `priority` (alias `pcp`) | derived=false, required=false | `Optional` | `"0"` | 7 | - | Priority code point (bounded 7) |
| `vlan` | `drop_eligible` (alias `dei`) | derived=false, required=false | `Optional` | `"false"` | - | - | Drop eligible indicator |
| `vlan` | `vlan_id` (alias `vid`) | derived=false, required=true | `Required` | - | 4095 | - | VLAN identifier (bounded 4095) |
| `vlan` | `ether_type` | derived=true, required=false | `Derived` | - | 65535 | - | Encapsulated EtherType (wire) |
| `vlan8021ad` | `priority` (alias `pcp`) | derived=false, required=false | `Optional` | `"0"` | 7 | - | Priority code point (bounded 7) |
| `vlan8021ad` | `drop_eligible` (alias `dei`) | derived=false, required=false | `Optional` | `"false"` | - | - | Drop eligible indicator |
| `vlan8021ad` | `vlan_id` (alias `vid`) | derived=false, required=true | `Required` | - | 4095 | - | VLAN identifier (bounded 4095) |
| `vlan8021ad` | `ether_type` | derived=true, required=false | `Derived` | - | 65535 | - | Encapsulated EtherType (wire) |
| `igmp` | `type` | derived=false, required=true | `Required` | - | 255 | - | IGMP message type |
| `igmp` | `code` | derived=false, required=true | `Required` | - | 255 | - | IGMP message code |
| `igmp` | `checksum` | derived=true, required=false | `Derived` | - | 65535 | - | IGMP checksum (wire) |
| `igmp` | `body` | derived=false, required=false | `Optional` | `"0x00000000"` | - | - | 4-byte IGMP body |
| `ipv4` | `dscp_ecn` | derived=false, required=false | `Optional` | `"0"` | 255 | - | DSCP and ECN octet |
| `ipv4` | `total_length` | derived=true, required=false | `Derived` | - | 65535 | - | Total length (wire) |
| `ipv4` | `identification` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Fragment identification |
| `ipv4` | `reserved_flag` | derived=false, required=false | `Optional` | `"false"` | - | - | Reserved flag bit |
| `ipv4` | `dont_fragment` | derived=false, required=false | `Optional` | `"false"` | - | - | Don't-fragment flag |
| `ipv4` | `more_fragments` | derived=false, required=false | `Optional` | `"false"` | - | - | More-fragments flag |
| `ipv4` | `fragment_offset` | derived=false, required=false | `Optional` | `"0"` | 8191 | - | Offset in 8-byte units (bounded 0x1fff) |
| `ipv4` | `ttl` | derived=false, required=true | `Optional` | `"64"` | 255 | - | Time to live (constant default 64) |
| `ipv4` | `protocol` | derived=true, required=false | `Derived` | - | 255 | - | Protocol discriminator (wire) |
| `ipv4` | `checksum` | derived=true, required=false | `Derived` | - | 65535 | - | Header checksum (wire) |
| `ipv4` | `source` (alias `src`) | derived=false, required=true | `Required` | - | - | - | Source IPv4 address |
| `ipv4` | `destination` (alias `dst`) | derived=false, required=true | `Required` | - | - | - | Destination IPv4 address |
| `ipv4` | `options` | derived=false, required=false | `Optional` | `"0x"` | - | - | IPv4 options |
| `ipv6` | `traffic_class` | derived=false, required=false | `Optional` | `"0"` | 255 | - | Traffic class |
| `ipv6` | `flow_label` | derived=false, required=false | `Optional` | `"0"` | 1048575 | - | Flow label (bounded 0x000f_ffff) |
| `ipv6` | `payload_length` | derived=true, required=false | `Derived` | - | 65535 | - | Payload length (wire) |
| `ipv6` | `next_header` | derived=true, required=false | `Derived` | - | 255 | - | Next-header discriminator (wire) |
| `ipv6` | `hop_limit` | derived=false, required=true | `Optional` | `"64"` | 255 | - | Hop limit (constant default 64) |
| `ipv6` | `source` (alias `src`) | derived=false, required=true | `Required` | - | - | - | Source IPv6 address |
| `ipv6` | `destination` (alias `dst`) | derived=false, required=true | `Required` | - | - | - | Destination IPv6 address |
| `sctp` | `source_port` (alias `sport`) | derived=false, required=true | `Required` | - | 65535 | - | Source port |
| `sctp` | `destination_port` (alias `dport`) | derived=false, required=true | `Required` | - | 65535 | - | Destination port |
| `sctp` | `verification_tag` (alias `vtag`) | derived=false, required=true | `Required` | - | 4294967295 | - | Verification tag |
| `sctp` | `checksum` | derived=true, required=false | `Derived` | - | 4294967295 | - | CRC32c checksum (wire) |
| `tcp` | `source_port` (alias `sport`) | derived=false, required=true | `Required` | - | 65535 | - | Source port |
| `tcp` | `destination_port` (alias `dport`) | derived=false, required=true | `Required` | - | 65535 | - | Destination port |
| `tcp` | `sequence` | derived=false, required=true | `Required` | - | 4294967295 | - | Sequence number |
| `tcp` | `acknowledgment` | derived=false, required=false | `Optional` | `"0"` | 4294967295 | - | Acknowledgment number |
| `tcp` | `reserved_bits` | derived=false, required=false | `Optional` | `"0"` | 7 | - | Reserved bits (bounded 7) |
| `tcp` | `flags` | derived=false, required=true | `Required` | - | 511 | - | TCP flags (bounded 0x01ff) |
| `tcp` | `window` | derived=false, required=true | `Required` | - | 65535 | - | Receive window |
| `tcp` | `checksum` | derived=true, required=false | `Derived` | - | 65535 | - | TCP checksum (wire) |
| `tcp` | `urgent_pointer` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Urgent pointer |
| `tcp` | `options` | derived=false, required=false | `Optional` | `"0x"` | - | - | TCP options |
| `udp` | `source_port` (alias `sport`) | derived=false, required=true | `Required` | - | 65535 | - | Source port |
| `udp` | `destination_port` (alias `dport`) | derived=false, required=true | `Required` | - | 65535 | - | Destination port |
| `udp` | `length` | derived=true, required=false | `Derived` | - | 65535 | - | Datagram length (wire) |
| `udp` | `checksum` | derived=true, required=false | `Derived` | - | 65535 | - | UDP checksum (wire) |
| `erspan` | `version` | derived=false, required=true | `Required` | - | 15 | - | Version (bounded 0xf) |
| `erspan` | `vlan` | derived=false, required=false | `Optional` | `"0"` | 4095 | - | VLAN (bounded 0xfff) |
| `erspan` | `cos` | derived=false, required=false | `Optional` | `"0"` | 7 | - | Class of service (bounded 7) |
| `erspan` | `encapsulation` | derived=false, required=false | `Optional` | `"0"` | 3 | - | Encapsulation bits (bounded 3) |
| `erspan` | `truncated` | derived=false, required=false | `Optional` | `"false"` | - | - | Truncated flag |
| `erspan` | `session_id` | derived=false, required=true | `Required` | - | 1023 | - | Session ID (bounded 0x3ff) |
| `erspan` | `index_word` | derived=false, required=false | `Optional` | `"0"` | 4294967295 | - | Port index word |
| `erspan` | `timestamp` | derived=false, required=false | `Optional` | `"0"` | 4294967295 | - | Type III timestamp (None in default) |
| `erspan` | `sgt` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Type III SGT (None in default) |
| `erspan` | `flags` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Type III flags (None in default) |
| `erspan` | `subheader` | derived=false, required=false | `Optional` | `"0x"` | - | - | Type III 8-byte subheader (None in default) |
| `geneve` | `version` | derived=false, required=false | `Optional` | `"0"` | 3 | - | Version (bounded 3) |
| `geneve` | `control` | derived=false, required=false | `Optional` | `"false"` | - | - | Control packet bit |
| `geneve` | `critical` | derived=false, required=false | `Optional` | `"false"` | - | - | Critical options bit |
| `geneve` | `reserved1` | derived=false, required=false | `Optional` | `"0"` | 63 | - | Reserved 6 bits (bounded 0x3f) |
| `geneve` | `protocol_type` | derived=true, required=false | `Derived` | - | 65535 | - | Protocol type (wire) |
| `geneve` | `vni` | derived=false, required=true | `Required` | - | 16777215 | - | 24-bit VNI (bounded VNI_MAX) |
| `geneve` | `reserved2` | derived=false, required=false | `Optional` | `"0"` | 255 | - | Reserved byte |
| `geneve` | `options` | derived=false, required=false | `Optional` | `"0x"` | - | - | Option TLV bytes |
| `ah` | `next_header` | derived=true, required=false | `Derived` | - | 255 | - | Next-header discriminator (wire) |
| `ah` | `payload_length` | derived=true, required=false | `Derived` | - | 255 | - | Header length minus 2 (wire) |
| `ah` | `reserved` | derived=false, required=false | `Optional` | `"0"` | 65535 | - | Reserved 16 bits |
| `ah` | `spi` | derived=false, required=true | `Required` | - | 4294967295 | - | Security parameters index |
| `ah` | `sequence` | derived=false, required=false | `Optional` | `"0"` | 4294967295 | - | Anti-replay sequence number |
| `ah` | `icv` | derived=false, required=false | `Optional` | `"0x000000000000000000000000"` | - | - | 12-byte placeholder ICV |
| `esp` | `spi` | derived=false, required=true | `Required` | - | 4294967295 | - | Security parameters index |
| `esp` | `sequence` | derived=false, required=false | `Optional` | `"0"` | 4294967295 | - | Anti-replay sequence number |
| `l2tpv3` | `session_id` | derived=false, required=true | `Required` | - | 4294967295 | - | 32-bit session identifier |
| `mpls` | `label` | derived=false, required=true | `Required` | - | 1048575 | - | 20-bit label (bounded LABEL_MAX) |
| `mpls` | `traffic_class` | derived=false, required=false | `Optional` | `"0"` | 7 | - | Traffic class (bounded 7) |
| `mpls` | `bottom_of_stack` | derived=false, required=false | `Optional` | `"true"` | - | - | S bit (true on default) |
| `mpls` | `ttl` | derived=false, required=false | `Optional` | `"64"` | 255 | - | Time to live (64 on default) |
| `pppoe` | `version` | derived=false, required=false | `Optional` | `"1"` | 15 | - | Version (1 on default, bounded 0xf) |
| `pppoe` | `type` | derived=false, required=false | `Optional` | `"1"` | 15 | - | Type (1 on default, bounded 0xf) |
| `pppoe` | `code` | derived=false, required=false | `Optional` | `"0"` | 255 | - | Stage code |
| `pppoe` | `session_id` | derived=false, required=true | `Required` | - | 65535 | - | Session identifier |
| `pppoe` | `length` | derived=true, required=false | `Derived` | - | 65535 | - | Payload length (wire) |
| `ppp` | `protocol` | derived=true, required=false | `Derived` | - | 65535 | - | PPP protocol number (wire) |
| `vxlan` | `flags` | derived=false, required=true | `Required` | - | 255 | - | Flag byte (VNI_VALID_FLAG 0x08) |
| `vxlan` | `reserved1` | derived=false, required=false | `Optional` | `"0"` | 16777215 | - | Reserved 24 bits (bounded VNI_MAX) |
| `vxlan` | `vni` | derived=false, required=true | `Required` | - | 16777215 | - | 24-bit VNI (bounded VNI_MAX) |
| `vxlan` | `reserved2` | derived=false, required=false | `Optional` | `"0"` | 255 | - | Reserved byte |
