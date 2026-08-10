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
//! rejected when the registry is built, precisely so one path can never mean
//! two things.

use crate::registry::{FilterFieldBinding, RegistryBuilder, RegistryError};

/// An alternate name for exactly one reflective field.
struct Direct {
    path: &'static str,
    protocol: &'static str,
    field: &'static str,
}

/// One flag out of a packed field.
struct Bits {
    path: &'static str,
    protocol: &'static str,
    field: &'static str,
    mask: u64,
}

/// A name that reads either endpoint of a pair.
struct Either {
    path: &'static str,
    protocol: &'static str,
    fields: &'static [&'static str],
}

const DIRECT: &[Direct] = &[
    // Link layer.
    Direct {
        path: "eth.src",
        protocol: "ethernet",
        field: "source",
    },
    Direct {
        path: "eth.dst",
        protocol: "ethernet",
        field: "destination",
    },
    Direct {
        path: "eth.type",
        protocol: "ethernet",
        field: "ether_type",
    },
    Direct {
        path: "vlan.id",
        protocol: "vlan",
        field: "vlan_id",
    },
    Direct {
        path: "vlan.dei",
        protocol: "vlan",
        field: "drop_eligible",
    },
    Direct {
        path: "vlan.etype",
        protocol: "vlan",
        field: "ether_type",
    },
    Direct {
        path: "qinq.id",
        protocol: "vlan8021ad",
        field: "vlan_id",
    },
    Direct {
        path: "qinq.etype",
        protocol: "vlan8021ad",
        field: "ether_type",
    },
    // ARP, whose canonical names describe the roles rather than the wire.
    Direct {
        path: "arp.opcode",
        protocol: "arp",
        field: "operation",
    },
    Direct {
        path: "arp.src.hw_mac",
        protocol: "arp",
        field: "sender_hardware",
    },
    Direct {
        path: "arp.src.proto_ipv4",
        protocol: "arp",
        field: "sender_protocol",
    },
    Direct {
        path: "arp.dst.hw_mac",
        protocol: "arp",
        field: "target_hardware",
    },
    Direct {
        path: "arp.dst.proto_ipv4",
        protocol: "arp",
        field: "target_protocol",
    },
    // IPv4.
    Direct {
        path: "ip.src",
        protocol: "ipv4",
        field: "source",
    },
    Direct {
        path: "ip.dst",
        protocol: "ipv4",
        field: "destination",
    },
    Direct {
        path: "ip.proto",
        protocol: "ipv4",
        field: "protocol",
    },
    Direct {
        path: "ip.len",
        protocol: "ipv4",
        field: "total_length",
    },
    Direct {
        path: "ip.id",
        protocol: "ipv4",
        field: "identification",
    },
    Direct {
        path: "ip.dsfield",
        protocol: "ipv4",
        field: "dscp_ecn",
    },
    Direct {
        path: "ip.frag_offset",
        protocol: "ipv4",
        field: "fragment_offset",
    },
    Direct {
        path: "ip.flags.df",
        protocol: "ipv4",
        field: "dont_fragment",
    },
    Direct {
        path: "ip.flags.mf",
        protocol: "ipv4",
        field: "more_fragments",
    },
    Direct {
        path: "ip.flags.rb",
        protocol: "ipv4",
        field: "reserved_flag",
    },
    // IPv6.
    Direct {
        path: "ipv6.src",
        protocol: "ipv6",
        field: "source",
    },
    Direct {
        path: "ipv6.dst",
        protocol: "ipv6",
        field: "destination",
    },
    Direct {
        path: "ipv6.hlim",
        protocol: "ipv6",
        field: "hop_limit",
    },
    Direct {
        path: "ipv6.plen",
        protocol: "ipv6",
        field: "payload_length",
    },
    Direct {
        path: "ipv6.nxt",
        protocol: "ipv6",
        field: "next_header",
    },
    Direct {
        path: "ipv6.tclass",
        protocol: "ipv6",
        field: "traffic_class",
    },
    Direct {
        path: "ipv6.flow",
        protocol: "ipv6",
        field: "flow_label",
    },
    // IPv6 fragmentation and segment routing.
    Direct {
        path: "frag6.offset",
        protocol: "ipv6_fragment",
        field: "fragment_offset",
    },
    Direct {
        path: "frag6.id",
        protocol: "ipv6_fragment",
        field: "identification",
    },
    Direct {
        path: "frag6.more",
        protocol: "ipv6_fragment",
        field: "more_fragments",
    },
    Direct {
        path: "srh.left",
        protocol: "ipv6_srh",
        field: "segments_left",
    },
    // Transport.
    Direct {
        path: "tcp.srcport",
        protocol: "tcp",
        field: "source_port",
    },
    Direct {
        path: "tcp.dstport",
        protocol: "tcp",
        field: "destination_port",
    },
    Direct {
        path: "tcp.seq",
        protocol: "tcp",
        field: "sequence",
    },
    Direct {
        path: "tcp.ack",
        protocol: "tcp",
        field: "acknowledgment",
    },
    Direct {
        path: "tcp.window_size",
        protocol: "tcp",
        field: "window",
    },
    Direct {
        path: "tcp.urgent",
        protocol: "tcp",
        field: "urgent_pointer",
    },
    Direct {
        path: "udp.srcport",
        protocol: "udp",
        field: "source_port",
    },
    Direct {
        path: "udp.dstport",
        protocol: "udp",
        field: "destination_port",
    },
    Direct {
        path: "sctp.srcport",
        protocol: "sctp",
        field: "source_port",
    },
    Direct {
        path: "sctp.dstport",
        protocol: "sctp",
        field: "destination_port",
    },
    Direct {
        path: "sctp.vtag",
        protocol: "sctp",
        field: "verification_tag",
    },
    // Tunnelling.
    Direct {
        path: "gre.proto",
        protocol: "gre",
        field: "protocol_type",
    },
    // Conventional MPLS aliases.
    Direct {
        path: "mpls.exp",
        protocol: "mpls",
        field: "traffic_class",
    },
    Direct {
        path: "mpls.bottom",
        protocol: "mpls",
        field: "bottom_of_stack",
    },
    // Canonical VXLAN and GENEVE VNI paths need no aliases.
];

/// The nine TCP control flags, in their wire bit order.
///
/// The reflective `flags` field packs all nine into one number, which is
/// awkward to compare directly; each entry here reads a single flag as `0` or
/// `1`. Bit values follow RFC 9293, so bit 8 is the accurate-ECN bit
/// historically named NS.
const BITS: &[Bits] = &[
    Bits {
        path: "tcp.flags.fin",
        protocol: "tcp",
        field: "flags",
        mask: 0x001,
    },
    Bits {
        path: "tcp.flags.syn",
        protocol: "tcp",
        field: "flags",
        mask: 0x002,
    },
    Bits {
        path: "tcp.flags.reset",
        protocol: "tcp",
        field: "flags",
        mask: 0x004,
    },
    Bits {
        path: "tcp.flags.push",
        protocol: "tcp",
        field: "flags",
        mask: 0x008,
    },
    Bits {
        path: "tcp.flags.ack",
        protocol: "tcp",
        field: "flags",
        mask: 0x010,
    },
    Bits {
        path: "tcp.flags.urg",
        protocol: "tcp",
        field: "flags",
        mask: 0x020,
    },
    Bits {
        path: "tcp.flags.ece",
        protocol: "tcp",
        field: "flags",
        mask: 0x040,
    },
    Bits {
        path: "tcp.flags.cwr",
        protocol: "tcp",
        field: "flags",
        mask: 0x080,
    },
    Bits {
        path: "tcp.flags.ae",
        protocol: "tcp",
        field: "flags",
        mask: 0x100,
    },
    // Keep `ns` as the conventional alias for `ae`.
    Bits {
        path: "tcp.flags.ns",
        protocol: "tcp",
        field: "flags",
        mask: 0x100,
    },
];

/// Paths that read either endpoint of a pair.
///
/// A comparison holds when either field satisfies it, so `tcp.port == 443`
/// finds both directions of a conversation. Inequality complements equality
/// over both fields, so `tcp.port != 443` holds only when neither endpoint is
/// 443; reach for `tcp.srcport` or `tcp.dstport` when direction matters.
const EITHER: &[Either] = &[
    Either {
        path: "eth.addr",
        protocol: "ethernet",
        fields: &["source", "destination"],
    },
    Either {
        path: "ip.addr",
        protocol: "ipv4",
        fields: &["source", "destination"],
    },
    Either {
        path: "ipv6.addr",
        protocol: "ipv6",
        fields: &["source", "destination"],
    },
    Either {
        path: "tcp.port",
        protocol: "tcp",
        fields: &["source_port", "destination_port"],
    },
    Either {
        path: "udp.port",
        protocol: "udp",
        fields: &["source_port", "destination_port"],
    },
    Either {
        path: "sctp.port",
        protocol: "sctp",
        fields: &["source_port", "destination_port"],
    },
];

/// Registers every conventional spelling for the built-in protocols.
pub(super) fn register_filter_fields(builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
    for entry in DIRECT {
        builder.bind_filter_field(
            entry.path,
            FilterFieldBinding::Direct {
                protocol: entry.protocol.into(),
                field: entry.field,
            },
        )?;
    }
    for entry in BITS {
        builder.bind_filter_field(
            entry.path,
            FilterFieldBinding::Bits {
                protocol: entry.protocol.into(),
                field: entry.field,
                mask: entry.mask,
                // Shift flags to compare as 0 or 1.
                shift: entry.mask.trailing_zeros(),
            },
        )?;
    }
    for entry in EITHER {
        builder.bind_filter_field(
            entry.path,
            FilterFieldBinding::Either {
                protocol: entry.protocol.into(),
                fields: entry.fields,
            },
        )?;
    }
    Ok(())
}
