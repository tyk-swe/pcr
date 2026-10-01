// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The NDP, MLD and IGMPv3 helpers produce layers that build, dissect and
//! convert back without losing a byte.

mod common;

use common::packets::{ROOT_LINK_TYPE, ipv4, ipv6, rooted_registry};
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::network::ndp::{
    MessageOption, MtuOption, PrefixInformation, Rdnss, Redirect, RedirectedHeader,
    RouterAdvertisement, RouterSolicitation,
};
use packetcraftr_core::protocol::network::{Icmpv6, Igmp, Ipv4, Ipv6, igmpv3, mld};
use packetcraftr_core::{build, codec, decode};

fn dissect(root: &'static str, packet: Packet) -> (build::BuiltPacket, decode::DecodedPacket) {
    let registry = rooted_registry(root);
    let built = build::Builder::new(Arc::clone(&registry))
        .build(packet, codec::Context::default(), build::Options::default())
        .expect("helper layers build strictly");
    let frame = Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, built.bytes.clone())
        .expect("built bytes form a frame");
    let decoded = decode::Dissector::new(registry)
        .decode(frame, decode::Options::default())
        .expect("built bytes dissect");
    assert!(
        decoded.diagnostics.is_empty(),
        "checksums verify: {:?}",
        decoded.diagnostics
    );
    (built, decoded)
}

fn icmpv6_message(icmp: Icmpv6, destination: &str) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv6 {
        hop_limit: 255,
        ..ipv6("fe80::1", destination)
    });
    packet.push(icmp);
    packet
}

fn decoded_icmpv6(decoded: &decode::DecodedPacket) -> Icmpv6 {
    decoded
        .packet
        .layer(1)
        .and_then(|layer| layer.downcast_ref::<Icmpv6>())
        .expect("an ICMPv6 layer follows the IPv6 header")
        .clone()
}

#[test]
fn router_discovery_messages_survive_a_build_and_dissect_round_trip() {
    let router_advertisement = RouterAdvertisement {
        cur_hop_limit: 64,
        managed: true,
        other: false,
        home_agent: false,
        preference: 0b11,
        proxy: true,
        reserved: 0b10,
        router_lifetime: 1800,
        reachable_time: 0,
        retrans_timer: 0,
        options: vec![
            MessageOption::PrefixInformation(PrefixInformation {
                prefix_length: 64,
                on_link: true,
                autonomous: true,
                router_address: false,
                reserved: 0b1_0001,
                valid_lifetime: 2_592_000,
                preferred_lifetime: 604_800,
                reserved2: 7,
                prefix: "2001:db8:1::".parse().unwrap(),
            }),
            MessageOption::Mtu(MtuOption {
                reserved: 0,
                mtu: 1500,
            }),
            MessageOption::Rdnss(Rdnss {
                reserved: 0,
                lifetime: 3600,
                servers: vec!["2001:db8::53".parse().unwrap()],
            }),
        ],
    };
    let (built, decoded) = dissect(
        "ipv6",
        icmpv6_message(router_advertisement.to_icmpv6().unwrap(), "ff02::1"),
    );
    let icmp = decoded_icmpv6(&decoded);
    assert_eq!(icmp.icmp_type, 134);
    assert_eq!(
        RouterAdvertisement::decode(&icmp.body),
        Ok(router_advertisement.clone())
    );
    assert_eq!(&built.bytes[44..], router_advertisement.encode().unwrap());

    let solicitation = RouterSolicitation {
        reserved: 0,
        options: Vec::new(),
    };
    let (_, decoded) = dissect(
        "ipv6",
        icmpv6_message(solicitation.to_icmpv6().unwrap(), "ff02::2"),
    );
    assert_eq!(
        RouterSolicitation::decode(&decoded_icmpv6(&decoded).body),
        Ok(solicitation)
    );

    let redirect = Redirect {
        reserved: 0,
        target: "fe80::2".parse().unwrap(),
        destination: "2001:db8::99".parse().unwrap(),
        options: vec![MessageOption::RedirectedHeader(RedirectedHeader {
            reserved: [0; 6],
            packet: Bytes::from_static(&[0x60; 8]),
        })],
    };
    let (_, decoded) = dissect(
        "ipv6",
        icmpv6_message(redirect.to_icmpv6().unwrap(), "fe80::3"),
    );
    assert_eq!(
        Redirect::decode(&decoded_icmpv6(&decoded).body),
        Ok(redirect)
    );
}

#[test]
fn mld_messages_survive_a_build_and_dissect_round_trip() {
    let report = mld::Message::Mldv2Report(mld::Mldv2Report {
        reserved: 0,
        records: vec![
            mld::MulticastAddressRecord {
                record_type: 2,
                group: "ff3e::8000:1".parse().unwrap(),
                sources: vec![
                    "2001:db8::1".parse().unwrap(),
                    "2001:db8::2".parse().unwrap(),
                    "2001:db8::3".parse().unwrap(),
                ],
                aux_data: Bytes::new(),
            },
            mld::MulticastAddressRecord {
                record_type: 4,
                group: "ff02::fb".parse().unwrap(),
                sources: Vec::new(),
                aux_data: Bytes::new(),
            },
        ],
    });
    let query = mld::Message::Mldv1(mld::Mldv1 {
        kind: mld::Mldv1Kind::Query,
        max_response_delay: 10_000,
        reserved: 0,
        group: "ff02::fb".parse().unwrap(),
    });
    for (message, destination) in [(report, "ff02::16"), (query, "ff02::fb")] {
        let (_, decoded) = dissect(
            "ipv6",
            icmpv6_message(message.to_icmpv6().unwrap(), destination),
        );
        assert_eq!(
            mld::Message::from_icmpv6(&decoded_icmpv6(&decoded)),
            Ok(message)
        );
    }
}

#[test]
fn igmpv3_messages_survive_a_build_and_dissect_round_trip() {
    let query = igmpv3::Query {
        max_response_code: 100,
        group: "232.1.1.1".parse().unwrap(),
        reserved: 0,
        suppress_router_processing: false,
        robustness: 2,
        qqic: 125,
        sources: vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
    };
    let report = igmpv3::Report {
        reserved: 0,
        reserved2: 0,
        records: vec![igmpv3::GroupRecord {
            record_type: 1,
            group: "232.1.1.1".parse().unwrap(),
            sources: vec!["192.0.2.1".parse().unwrap()],
            aux_data: Bytes::new(),
        }],
    };
    let carried = |igmp: Igmp| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            ttl: 1,
            ..ipv4([192, 0, 2, 1], [224, 0, 0, 22])
        });
        packet.push(igmp);
        dissect("ipv4", packet)
    };
    let decoded_igmp = |decoded: &decode::DecodedPacket| {
        decoded
            .packet
            .layer(1)
            .and_then(|layer| layer.downcast_ref::<Igmp>())
            .expect("an IGMP layer follows the IPv4 header")
            .clone()
    };

    let (built, decoded) = carried(query.to_igmp().unwrap());
    let igmp = decoded_igmp(&decoded);
    assert_eq!(igmpv3::Query::from_igmp(&igmp), Ok(query.clone()));
    assert_eq!(igmp.body, query.to_igmp().unwrap().body);
    assert_eq!(built.bytes[20], igmpv3::MEMBERSHIP_QUERY);

    let (_, decoded) = carried(report.to_igmp().unwrap());
    assert_eq!(
        igmpv3::Report::from_igmp(&decoded_igmp(&decoded)),
        Ok(report)
    );
    assert!(
        igmpv3::Query::from_igmp(&Igmp::default()).is_err(),
        "an IGMPv2 query is not a v3 query"
    );
}
