# 16: ARP and NDP over core codecs

**What to build:**
- `packetcraftr::neighbor` builds and parses ARP and NDP frames with core's Ethernet, VLAN, ARP, ICMPv6 and IPv6 codecs, replacing about 960 hand-written lines in `wire/{ethernet,arp,ndp}.rs`.
- Parsing replies uses the dissector. IPv6 extension headers are no longer re-walked by hand in `upper_layer_icmpv6`.
- The duplicate multicast-MAC helper (`intent.rs` vs `ndp.rs`) becomes one.
- If a reply can't be parsed faithfully by codecs, use the shared header walker from ticket 12, never a new copy.

Phase 2.

**Blocked by:** 12, 15

**Status:** resolved

- [x] Before the old code is deleted, a test proves the built request frames are byte-for-byte identical to the current hand-written output. Cover ARP, NDP neighbor solicitation, VLAN-tagged, and minimum-padded frames.
- [x] Parse tests cover captured replies with VLAN tags and IPv6 extension headers.
- [x] No hand-written Ethernet, ARP or NDP byte code remains.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Decision C4: core gained `protocol::network::ndp` (NS/NA bodies, source/target
  link-layer options, `solicited_node_multicast`). They are body models over the
  opaque `Icmpv6` layer, not registered layers, so dissection output and the frozen
  documents are unchanged.
- The byte-for-byte proof is the `differential` test in commit 3b089f73 (removed
  with the old code in the next commit): ARP and NS over four address pairs, five
  VLAN stacks up to `MAX_VLAN_TAGS` with both TPIDs, minimum padding, and MTU
  refusals, plus the reply matcher on every fixture, every single-byte mutation
  (three masks), and every truncation. The golden frames it produced stay as tests.
- The header walker was not needed. The dissector types every extension header
  the old walk accepted except routing headers other than Segment Routing and
  malformed AH. An advertisement behind those is now refused (changelog "Changed").
  A routing header with segments left means the datagram is not yet at its final
  destination, and reaching ICMPv6 behind an untyped header would need a second
  ICMPv6 parse outside the codec.
- The two multicast-MAC helpers became core `MacAddress::for_ip_multicast`.
