# Centralize core header walk and checksum guard

Status: open
Blocked by: none
Spec: ../spec.md §§ Implementation Decisions 4; Testing Decisions

One public core network-envelope module for bounded Ethernet/VLAN and IPv6 extension walks, typed checksum-coverage refusals and pseudo-header/UDP-zero rules. Migrate header rewrite, field edits, fragmentation and netio neighbor parser; keep structural policy local and codecs/pcap wire unchanged. First enumerate existing differing accepted/refused chains; table tests of bounds/truncation/all guards/checksums and contract regressions. Report newly refused chains for `[Unreleased]` at integration.
