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
}

#[derive(Clone, Copy, Debug)]
pub struct Variant {
    pub id: &'static str,
    pub hypothesis: &'static str,
    kind: Kind,
}

const ROUTER_ALERT: &[u8] = &[0x94, 0x04, 0x00, 0x00];

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

pub fn build_attempt(
    shape: &AttemptShape,
    variant: &Variant,
    payload: &[u8],
    attempt_seq: u32,
) -> Vec<Packet> {
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
    fn every_variant_builds_and_baseline_is_first() {
        let registry = builtin::registry();
        let payload = vec![0xAB; 1024];
        assert_eq!(catalog()[0].id, "baseline");
        for variant in catalog() {
            let packets = build_attempt(&shape(), variant, &payload, 5);
            assert_eq!(packets.len(), 1, "{}", variant.id);
            for packet in packets {
                built_bytes(&registry, packet);
            }
        }
    }

    #[test]
    fn ttl_variant_differs_from_baseline_only_in_ttl_and_checksum() {
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
}
