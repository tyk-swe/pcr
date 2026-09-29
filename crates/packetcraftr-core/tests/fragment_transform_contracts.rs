// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::{
    analysis, build, capture_file,
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
use std::{io::Cursor, time::UNIX_EPOCH};

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

#[test]
fn both_families_reassemble_exact_transport_bytes_in_reverse_capture_order() {
    for ipv6 in [false, true] {
        for options in [false, true] {
            let original = complete(ipv6, options);
            let fragments = fragment(
                &original,
                FragmentOptions {
                    mtu: 128,
                    identification: if ipv6 { Some(0x12345678) } else { None },
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(fragments.len() > 1);
            assert!(fragments.iter().all(|frame| frame.bytes().len() <= 128));
            if !ipv6 && options {
                assert_eq!(fragments[0].bytes()[0] & 15, 7);
                assert_eq!(fragments[1].bytes()[0] & 15, 6);
                assert_eq!(&fragments[1].bytes()[20..24], &[0x82, 4, 1, 2]);
            }
            let mut writer = capture_file::Writer::pcap(Vec::new(), original.link_type).unwrap();
            for frame in fragments.iter().rev() {
                writer.write_frame(frame).unwrap();
            }
            let mut reader = capture_file::Reader::new(Cursor::new(writer.into_inner())).unwrap();
            let mut rebuilt = None;
            analysis::run(
                &mut reader,
                builtin::registry(),
                &Default::default(),
                |record| {
                    if let Some(datagram) = record.derived() {
                        rebuilt = Some(datagram.decoded.frame.bytes().clone());
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(rebuilt.unwrap().as_ref(), original.bytes().as_ref());
        }
    }
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
fn fragment_limits_df_and_incomplete_headers_fail_before_returning_output() {
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

#[test]
fn max_fragments_outside_its_range_names_the_range_or_the_ceiling() {
    use packetcraftr_core::error::{Classified, Kind};
    let original = complete(false, false);
    for (max_fragments, message) in [
        (0, "packet transform requires max_fragments in 1..=8192"),
        (8193, "packet transform exceeds max_fragments=8192"),
    ] {
        let error = fragment(
            &original,
            FragmentOptions {
                mtu: 128,
                max_fragments,
                ..Default::default()
            },
        )
        .expect_err("max_fragments outside 1..=8192");
        assert_eq!(error.to_string(), message);
        let classification = error.classification();
        assert_eq!(classification.code, "policy.transform_limit");
        assert_eq!(classification.kind, Kind::Policy);
    }
    for max_fragments in [1, 8192] {
        assert!(
            fragment(
                &original,
                FragmentOptions {
                    mtu: 1500,
                    max_fragments,
                    ..Default::default()
                },
            )
            .is_ok()
        );
    }
}

#[test]
fn only_ethernet_and_ip_roots_frame_a_packet_for_fragmenting() {
    use packetcraftr_core::{
        error::Classified,
        protocol::{link::Ethernet, transport::Tcp},
        transform::fragment_link_type,
    };
    fn rooted(layer: impl packetcraftr_core::layer::Layer) -> Packet {
        let mut packet = Packet::new();
        packet.push(layer);
        packet
    }
    for (packet, expected) in [
        (rooted(Ethernet::default()), LinkType::ETHERNET),
        (rooted(Ipv4::default()), LinkType::IPV4),
        (rooted(Ipv6::default()), LinkType::IPV6),
    ] {
        assert_eq!(fragment_link_type(&packet).unwrap(), expected);
    }
    for packet in [
        Packet::new(),
        rooted(Udp::default()),
        rooted(Tcp::default()),
        rooted(Raw::new(vec![0x45])),
    ] {
        let error = fragment_link_type(&packet).expect_err("unsupported root");
        assert_eq!(
            error.to_string(),
            "unsupported packet transform: recipe must begin with Ethernet or IP"
        );
        assert_eq!(error.classification().code, "packet.transform_unsupported");
    }
}
