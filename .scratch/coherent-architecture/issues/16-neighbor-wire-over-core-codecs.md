# 16: ARP and NDP over core codecs

**What to build:**
- `packetcraftr::neighbor` builds and parses ARP and NDP frames with core's Ethernet, VLAN, ARP, ICMPv6 and IPv6 codecs, replacing about 960 hand-written lines in `wire/{ethernet,arp,ndp}.rs`.
- Parsing replies uses the dissector. IPv6 extension headers are no longer re-walked by hand in `upper_layer_icmpv6`.
- The duplicate multicast-MAC helper (`intent.rs` vs `ndp.rs`) becomes one.
- If a reply can't be parsed faithfully by codecs, use the shared header walker from ticket 12, never a new copy.

Phase 2.

**Blocked by:** 12, 15

**Status:** ready-for-agent

- [ ] Before the old code is deleted, a test proves the built request frames are byte-for-byte identical to the current hand-written output. Cover ARP, NDP neighbor solicitation, VLAN-tagged, and minimum-padded frames.
- [ ] Parse tests cover captured replies with VLAN tags and IPv6 extension headers.
- [ ] No hand-written Ethernet, ARP or NDP byte code remains.
- [ ] fmt, clippy and the workspace tests pass.
