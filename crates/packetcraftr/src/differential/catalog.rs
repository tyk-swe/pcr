// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use bytes::Bytes;
use packetcraftr_core::field::WireValue;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Udp;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Baseline,
    Ttl(u8),
    DscpEcn(u8),
    IpId(u16),
    DontFragment,
    IpOptions(&'static [u8]),
    UdpChecksumZero,
    Fragmented { reordered: bool },
}

#[derive(Clone, Copy, Debug)]
pub struct Variant {
    pub id: &'static str,
    pub hypothesis: &'static str,
    kind: Kind,
}

const ROUTER_ALERT: &[u8] = &[0x94, 0x04, 0x00, 0x00];
const NOP_OPTIONS: &[u8] = &[0x01, 0x01, 0x00, 0x00];

const CATALOG: &[Variant] = &[
    Variant {
        id: "baseline",
        hypothesis: "Plain reference encoding is accepted on a healthy path",
        kind: Kind::Baseline,
    },
    Variant {
        id: "ttl-255",
        hypothesis: "A maximum TTL is forwarded unchanged in effect",
        kind: Kind::Ttl(255),
    },
    Variant {
        id: "ttl-1",
        hypothesis: "A minimum TTL only reaches a directly attached Responder",
        kind: Kind::Ttl(1),
    },
    Variant {
        id: "dscp-ecn",
        hypothesis: "DSCP EF with ECN ECT(0) marking is not dropped",
        kind: Kind::DscpEcn(0xBA),
    },
    Variant {
        id: "ecn-ce",
        hypothesis: "An ECN CE marking is not dropped",
        kind: Kind::DscpEcn(0x03),
    },
    Variant {
        id: "ip-id-max",
        hypothesis: "A maximum IPv4 identification is not dropped",
        kind: Kind::IpId(u16::MAX),
    },
    Variant {
        id: "df-set",
        hypothesis: "Setting DF on a datagram that fits the path is accepted",
        kind: Kind::DontFragment,
    },
    Variant {
        id: "ip-options-router-alert",
        hypothesis: "An IPv4 Router Alert option is not dropped",
        kind: Kind::IpOptions(ROUTER_ALERT),
    },
    Variant {
        id: "udp-checksum-zero",
        hypothesis: "A zero UDP checksum, legal over IPv4, is accepted",
        kind: Kind::UdpChecksumZero,
    },
    Variant {
        id: "ecn-ect1",
        hypothesis: "An ECN ECT(1) marking, distinct from ECT(0) and CE, is not dropped",
        kind: Kind::DscpEcn(0x01),
    },
    Variant {
        id: "ip-id-zero",
        hypothesis: "A zero IPv4 identification on an unfragmented datagram is not dropped",
        kind: Kind::IpId(0),
    },
    Variant {
        id: "ip-fragmented",
        hypothesis: "An IPv4 datagram split into two in-order fragments with a zero UDP checksum is reassembled and accepted",
        kind: Kind::Fragmented { reordered: false },
    },
    Variant {
        id: "ip-fragmented-reordered",
        hypothesis: "An IPv4 datagram whose second fragment arrives first, with a zero UDP checksum, is reassembled and accepted",
        kind: Kind::Fragmented { reordered: true },
    },
    Variant {
        id: "ip-options-nop",
        hypothesis: "IPv4 options holding NOPs and end-of-options padding are not dropped",
        kind: Kind::IpOptions(NOP_OPTIONS),
    },
];

#[must_use]
pub fn catalog() -> &'static [Variant] {
    CATALOG
}

fn identification(attempt_seq: u32) -> u16 {
    crate::engine::correlation::nonzero_ipv4_identification(u64::from(attempt_seq))
}

#[derive(Clone, Copy, Debug)]
pub struct AttemptShape {
    pub target: Ipv4Addr,
    pub source: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
}

fn base_ip(shape: &AttemptShape, attempt_seq: u32) -> Ipv4 {
    Ipv4 {
        destination: shape.target,
        source: shape.source,
        identification: identification(attempt_seq),
        ..Ipv4::default()
    }
}

fn datagram(
    ip: Ipv4,
    shape: &AttemptShape,
    source_port: u16,
    checksum_zero: bool,
    payload: &[u8],
) -> Packet {
    let mut packet = Packet::default();
    packet.push(ip);
    packet.push(Udp {
        source_port,
        destination_port: shape.destination_port,
        checksum: if checksum_zero {
            WireValue::Exact(0)
        } else {
            WireValue::Auto
        },
        ..Udp::default()
    });
    packet.push(Raw::new(Bytes::copy_from_slice(payload)));
    packet
}

const FIRST_FRAGMENT_BYTES: usize = 24;

fn fragmented(
    shape: &AttemptShape,
    payload: &[u8],
    attempt_seq: u32,
    reordered: bool,
) -> Vec<Packet> {
    let mut datagram = Vec::with_capacity(8 + payload.len());
    datagram.extend_from_slice(&shape.source_port.to_be_bytes());
    datagram.extend_from_slice(&shape.destination_port.to_be_bytes());
    datagram.extend_from_slice(
        &u16::try_from(8 + payload.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    datagram.extend_from_slice(&0_u16.to_be_bytes());
    datagram.extend_from_slice(payload);
    let split = FIRST_FRAGMENT_BYTES.min(datagram.len());
    let campaign_salt = payload.get(6..14).map_or(0, |bytes| {
        u64::from_be_bytes(bytes.try_into().unwrap_or_default())
    });
    let fragment_id = crate::engine::correlation::nonzero_ipv4_identification(
        u64::from(attempt_seq) ^ campaign_salt.rotate_left(17),
    );
    let fragment = |offset_units: u16, more: bool, chunk: &[u8]| {
        let mut ip = base_ip(shape, attempt_seq);
        ip.identification = fragment_id;
        ip.more_fragments = more;
        ip.fragment_offset = offset_units;
        ip.protocol = WireValue::Exact(17);
        let mut packet = Packet::default();
        packet.push(ip);
        packet.push(Raw::new(Bytes::copy_from_slice(chunk)));
        packet
    };
    let first = fragment(0, true, &datagram[..split]);
    let second = fragment(
        u16::try_from(split / 8).unwrap_or(u16::MAX),
        false,
        &datagram[split..],
    );
    if reordered {
        vec![second, first]
    } else {
        vec![first, second]
    }
}

pub fn build_attempt(
    shape: &AttemptShape,
    variant: &Variant,
    payload: &[u8],
    attempt_seq: u32,
) -> Vec<Packet> {
    if let Kind::Fragmented { reordered } = variant.kind {
        return fragmented(shape, payload, attempt_seq, reordered);
    }
    let mut ip = base_ip(shape, attempt_seq);
    let mut checksum_zero = false;
    match variant.kind {
        Kind::Baseline => {}
        Kind::Ttl(ttl) => ip.ttl = ttl,
        Kind::DscpEcn(value) => ip.dscp_ecn = value,
        Kind::IpId(value) => ip.identification = value,
        Kind::DontFragment => ip.dont_fragment = true,
        Kind::IpOptions(options) => ip.options = Bytes::from_static(options),
        Kind::UdpChecksumZero => checksum_zero = true,
        Kind::Fragmented { .. } => unreachable!("fragmented attempts return above"),
    }
    vec![datagram(
        ip,
        shape,
        shape.source_port,
        checksum_zero,
        payload,
    )]
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::build::Builder;
    use packetcraftr_core::codec::Addresses;
    use packetcraftr_core::protocol::builtin;
    use packetcraftr_core::registry::Registry;
    use std::sync::Arc;

    fn shape() -> AttemptShape {
        AttemptShape {
            target: Ipv4Addr::new(192, 0, 2, 10),
            source: Ipv4Addr::UNSPECIFIED,
            source_port: 53210,
            destination_port: 40101,
        }
    }

    fn built_bytes(registry: &Arc<Registry>, packet: Packet) -> Vec<u8> {
        Builder::new(Arc::clone(registry))
            .build(packet, Addresses::default(), Default::default())
            .expect("packet builds")
            .bytes
            .to_vec()
    }

    #[test]
    fn variants_build_with_baseline_first() {
        let registry = builtin::registry();
        let payload = vec![0xAB; 1024];
        assert_eq!(catalog()[0].id, "baseline");
        for variant in catalog() {
            let packets = build_attempt(&shape(), variant, &payload, 5);
            assert_eq!(
                packets.len(),
                if variant.id.starts_with("ip-fragmented") {
                    2
                } else {
                    1
                },
                "{}",
                variant.id
            );
            for packet in packets {
                built_bytes(&registry, packet);
            }
        }
    }

    #[test]
    fn ttl_variant_changes_only_ttl_and_checksum() {
        let registry = builtin::registry();
        let payload = vec![0xAB; 256];
        let baseline = built_bytes(
            &registry,
            build_attempt(&shape(), &catalog()[0], &payload, 5)[0].clone(),
        );
        let ttl = built_bytes(
            &registry,
            build_attempt(&shape(), &catalog()[1], &payload, 5)[0].clone(),
        );
        assert_eq!(baseline.len(), ttl.len());
        let differing: Vec<usize> = (0..baseline.len())
            .filter(|index| baseline[*index] != ttl[*index])
            .collect();
        assert!(
            differing.iter().all(|index| [8, 10, 11].contains(index)),
            "unexpected differing offsets: {differing:?}"
        );
        assert_eq!(ttl[8], 255);
    }

    #[test]
    fn appended_variants_change_only_their_named_header_fields() {
        let registry = builtin::registry();
        let payload = vec![0xAB; 64];
        let by_id = |id: &str| *catalog().iter().find(|variant| variant.id == id).unwrap();
        let bytes = |id: &str| {
            built_bytes(
                &registry,
                build_attempt(&shape(), &by_id(id), &payload, 5)[0].clone(),
            )
        };
        let baseline = bytes("baseline");
        let ids: std::collections::BTreeSet<_> =
            catalog().iter().map(|variant| variant.id).collect();
        assert_eq!(ids.len(), catalog().len(), "variant ids are unique");
        assert_eq!(bytes("ecn-ect1")[1], 0x01);
        assert_eq!(&bytes("ip-id-zero")[4..6], &[0, 0]);
        assert_ne!(&baseline[4..6], &[0, 0]);
        let nop = bytes("ip-options-nop");
        assert_eq!(nop[0], 0x46);
        assert_eq!(&nop[20..24], NOP_OPTIONS);
        assert_eq!(nop.len(), baseline.len() + 4);
    }

    #[test]
    fn fragments_reassemble_to_the_sent_udp_datagram() {
        let registry = builtin::registry();
        let payload = vec![0xAB; 64];
        let by_id = |id: &str| *catalog().iter().find(|variant| variant.id == id).unwrap();
        for (id, reordered) in [("ip-fragmented", false), ("ip-fragmented-reordered", true)] {
            let packets = build_attempt(&shape(), &by_id(id), &payload, 7);
            assert_eq!(packets.len(), 2, "{id}");
            let frames: Vec<Vec<u8>> = packets
                .into_iter()
                .map(|packet| built_bytes(&registry, packet))
                .collect();
            let offset = |frame: &[u8]| u16::from_be_bytes([frame[6], frame[7]]) & 0x1FFF;
            let more = |frame: &[u8]| frame[6] & 0x20 != 0;
            assert_eq!(frames[0][4..6], frames[1][4..6], "{id} identification");
            assert_eq!(offset(&frames[0]) == 0, !reordered, "{id} first sent");
            let (first, second) = if offset(&frames[0]) == 0 {
                (&frames[0], &frames[1])
            } else {
                (&frames[1], &frames[0])
            };
            assert!(more(first) && !more(second), "{id}");
            assert_eq!(usize::from(offset(second)) * 8, first.len() - 20, "{id}");
            let mut datagram = first[20..].to_vec();
            datagram.extend_from_slice(&second[20..]);
            assert_eq!(&datagram[0..2], &53210_u16.to_be_bytes(), "{id}");
            assert_eq!(&datagram[2..4], &40101_u16.to_be_bytes(), "{id}");
            assert_eq!(&datagram[6..8], &[0, 0], "{id} zero UDP checksum");
            assert_eq!(&datagram[8..], payload.as_slice(), "{id}");
        }
        let mut other_campaign = vec![0xAB; 64];
        other_campaign[6..14].copy_from_slice(&[0xCD; 8]);
        let mine = build_attempt(&shape(), &by_id("ip-fragmented"), &payload, 7);
        let other = build_attempt(&shape(), &by_id("ip-fragmented"), &other_campaign, 7);
        let id = |packet: &Packet| packet.get::<Ipv4>().expect("ipv4").identification;
        assert_ne!(id(&mine[0]), id(&other[0]));
    }
}
