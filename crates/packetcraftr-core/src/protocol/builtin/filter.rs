// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Conventional display-filter spellings for the built-in protocols.
//!
//! Every reflective field is already filterable under its canonical
//! `<protocol-or-alias>.<field>` path, so this table exists only for the
//! shorter names operators actually type and for the packed fields that are
//! more useful one flag at a time.
//!
//! Deliberately absent are the spellings that need no entry because a protocol
//! alias already produces them: `ip.ttl`, `icmp.type`, `udp.checksum`, and
//! their kin resolve straight through the schema. Registering those would be
//! rejected when the registry is built, so one path can never mean two things.

use crate::registry::FilterFieldBinding;

type Direct = (&'static str, &'static str, &'static str);
type Either = (&'static str, &'static str, &'static [&'static str]);

/// Alternate names for exactly one reflective field, as `(path, protocol, field)`.
const DIRECT: &[Direct] = &[
    // Link layer.
    ("eth.src", "ethernet", "source"),
    ("eth.dst", "ethernet", "destination"),
    ("eth.type", "ethernet", "ether_type"),
    ("vlan.id", "vlan", "vlan_id"),
    ("vlan.dei", "vlan", "drop_eligible"),
    ("vlan.etype", "vlan", "ether_type"),
    ("qinq.id", "vlan8021ad", "vlan_id"),
    ("qinq.etype", "vlan8021ad", "ether_type"),
    // ARP, whose canonical names describe the roles rather than the wire.
    ("arp.opcode", "arp", "operation"),
    ("arp.src.hw_mac", "arp", "sender_hardware"),
    ("arp.src.proto_ipv4", "arp", "sender_protocol"),
    ("arp.dst.hw_mac", "arp", "target_hardware"),
    ("arp.dst.proto_ipv4", "arp", "target_protocol"),
    // IPv4.
    ("ip.src", "ipv4", "source"),
    ("ip.dst", "ipv4", "destination"),
    ("ip.proto", "ipv4", "protocol"),
    ("ip.len", "ipv4", "total_length"),
    ("ip.id", "ipv4", "identification"),
    ("ip.dsfield", "ipv4", "dscp_ecn"),
    ("ip.frag_offset", "ipv4", "fragment_offset"),
    ("ip.flags.df", "ipv4", "dont_fragment"),
    ("ip.flags.mf", "ipv4", "more_fragments"),
    ("ip.flags.rb", "ipv4", "reserved_flag"),
    // IPv6.
    ("ipv6.src", "ipv6", "source"),
    ("ipv6.dst", "ipv6", "destination"),
    ("ipv6.hlim", "ipv6", "hop_limit"),
    ("ipv6.plen", "ipv6", "payload_length"),
    ("ipv6.nxt", "ipv6", "next_header"),
    ("ipv6.tclass", "ipv6", "traffic_class"),
    ("ipv6.flow", "ipv6", "flow_label"),
    // IPv6 fragmentation and segment routing.
    ("frag6.offset", "ipv6_fragment", "fragment_offset"),
    ("frag6.id", "ipv6_fragment", "identification"),
    ("frag6.more", "ipv6_fragment", "more_fragments"),
    ("srh.left", "ipv6_srh", "segments_left"),
    // Transport.
    ("tcp.srcport", "tcp", "source_port"),
    ("tcp.dstport", "tcp", "destination_port"),
    ("tcp.seq", "tcp", "sequence"),
    ("tcp.ack", "tcp", "acknowledgment"),
    ("tcp.window_size", "tcp", "window"),
    ("tcp.urgent", "tcp", "urgent_pointer"),
    ("udp.srcport", "udp", "source_port"),
    ("udp.dstport", "udp", "destination_port"),
    ("sctp.srcport", "sctp", "source_port"),
    ("sctp.dstport", "sctp", "destination_port"),
    ("sctp.vtag", "sctp", "verification_tag"),
    // Tunnelling.
    ("gre.proto", "gre", "protocol_type"),
    // Conventional MPLS aliases.
    ("mpls.exp", "mpls", "traffic_class"),
    ("mpls.bottom", "mpls", "bottom_of_stack"),
    // Canonical VXLAN and GENEVE VNI paths need no aliases.
];

/// The nine TCP control flags, in their wire bit order.
///
/// The reflective `flags` field packs all nine into one number, which is
/// awkward to compare directly; each entry here reads a single flag as `0` or
/// `1`. Bit values follow RFC 9293, so bit 8 is the accurate-ECN bit
/// historically named NS.
const TCP_FLAG_BITS: &[(&str, u64)] = &[
    ("tcp.flags.fin", 0x001),
    ("tcp.flags.syn", 0x002),
    ("tcp.flags.reset", 0x004),
    ("tcp.flags.push", 0x008),
    ("tcp.flags.ack", 0x010),
    ("tcp.flags.urg", 0x020),
    ("tcp.flags.ece", 0x040),
    ("tcp.flags.cwr", 0x080),
    ("tcp.flags.ae", 0x100),
    // Keep `ns` as the conventional alias for `ae`.
    ("tcp.flags.ns", 0x100),
];

/// Paths that read either endpoint of a pair.
///
/// A comparison holds when either field satisfies it, so `tcp.port == 443`
/// finds both directions of a conversation. That also means `tcp.port != 443`
/// holds whenever *either* endpoint differs; reach for `tcp.srcport` or
/// `tcp.dstport` when the direction matters.
const EITHER: &[Either] = &[
    ("eth.addr", "ethernet", &["source", "destination"]),
    ("ip.addr", "ipv4", &["source", "destination"]),
    ("ipv6.addr", "ipv6", &["source", "destination"]),
    ("tcp.port", "tcp", &["source_port", "destination_port"]),
    ("udp.port", "udp", &["source_port", "destination_port"]),
    ("sctp.port", "sctp", &["source_port", "destination_port"]),
];

/// Registers every conventional spelling for the built-in protocols.
pub(super) fn register_filter_fields(
    builder: &mut crate::registry::Builder,
) -> Result<(), crate::registry::Error> {
    for &(path, protocol, field) in DIRECT {
        builder.bind_filter_field(
            path,
            FilterFieldBinding::Direct {
                protocol: protocol.into(),
                field,
            },
        )?;
    }
    for &(path, mask) in TCP_FLAG_BITS {
        builder.bind_filter_field(
            path,
            FilterFieldBinding::Bits {
                protocol: "tcp".into(),
                field: "flags",
                mask,
                // Shift flags to compare as 0 or 1.
                shift: mask.trailing_zeros(),
            },
        )?;
    }
    for &(path, protocol, fields) in EITHER {
        builder.bind_filter_field(
            path,
            FilterFieldBinding::Either {
                protocol: protocol.into(),
                fields,
            },
        )?;
    }
    Ok(())
}
