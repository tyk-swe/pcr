// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::{
    build,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        builtin,
        network::{DestinationOptions, HopByHop, Ipv4, Ipv6},
        transport::Udp,
    },
    transform::{Error, FragmentOptions, InvalidInput, Limit, Unsupported, fragment},
};
use std::time::UNIX_EPOCH;

fn complete(ipv6: bool, options: bool) -> Frame {
    let mut packet = Packet::new();
    if ipv6 {
        packet.push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Default::default()
        });
        if options {
            packet.push(HopByHop::default());
            packet.push(DestinationOptions::default());
        }
    } else {
        packet.push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "192.0.2.2".parse().unwrap(),
            options: if options {
                Bytes::from_static(&[0x82, 4, 1, 2, 0x02, 4, 3, 4])
            } else {
                Bytes::new()
            },
            ..Default::default()
        });
    }
    packet.push(Udp {
        source_port: 40000,
        destination_port: 40001,
        ..Default::default()
    });
    packet.push(Raw::new(vec![0xab; 1000]));
    let built = build::Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    Frame::new(
        UNIX_EPOCH,
        if ipv6 { LinkType::IPV6 } else { LinkType::IPV4 },
        built.bytes,
    )
    .unwrap()
}

#[derive(Debug, PartialEq)]
enum Refusal {
    Invalid(InvalidInput),
    Unsupported(Unsupported),
    Limit(Limit, usize),
}

fn refusal(frame: &Frame, options: FragmentOptions) -> Refusal {
    match fragment(frame, options).expect_err("fragmenting is refused") {
        Error::Invalid(reason) => Refusal::Invalid(reason),
        Error::Unsupported(reason) => Refusal::Unsupported(reason),
        Error::Limit { field, limit } => Refusal::Limit(field, limit),
        other => panic!("unexpected refusal: {other:?}"),
    }
}

#[test]
fn frag_limits_fail_before_returning_output() {
    let original = complete(false, false);
    assert_eq!(
        fragment(&original, Default::default()).unwrap(),
        vec![original.clone()]
    );
    let mut bytes = original.bytes().to_vec();
    bytes[6] = 0x40;
    bytes[10..12].fill(0);
    let checksum = packetcraftr_core::protocol::checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    let df = Frame::new(UNIX_EPOCH, LinkType::IPV4, bytes).unwrap();
    let v6 = complete(true, true);
    let mtu_128 = FragmentOptions {
        mtu: 128,
        ..Default::default()
    };
    let once = fragment(&original, mtu_128).unwrap();
    for (frame, options, expected) in [
        (
            &original,
            FragmentOptions {
                mtu: 19,
                ..Default::default()
            },
            Refusal::Invalid(InvalidInput::MtuBelowIpv4Header),
        ),
        (
            &original,
            FragmentOptions {
                mtu: 20,
                ..Default::default()
            },
            Refusal::Invalid(InvalidInput::MtuFragmentPayload),
        ),
        (
            &original,
            FragmentOptions {
                max_fragments: 1,
                ..mtu_128
            },
            Refusal::Limit(Limit::MaxFragments, 1),
        ),
        (
            &original,
            FragmentOptions {
                max_output_bytes: 127,
                ..mtu_128
            },
            Refusal::Limit(Limit::MaxOutputBytes, 127),
        ),
        (
            &df,
            mtu_128,
            Refusal::Unsupported(Unsupported::DontFragment),
        ),
        (
            &v6,
            mtu_128,
            Refusal::Invalid(InvalidInput::Ipv6Identification),
        ),
        (
            &v6,
            FragmentOptions {
                mtu: 64,
                identification: Some(1),
                ..Default::default()
            },
            Refusal::Invalid(InvalidInput::Ipv6FirstFragment),
        ),
        (
            &once[0],
            Default::default(),
            Refusal::Unsupported(Unsupported::AlreadyFragmented),
        ),
    ] {
        assert_eq!(refusal(frame, options), expected, "{options:?}");
    }
}
