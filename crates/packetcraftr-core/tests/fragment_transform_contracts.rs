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
    transform::{FragmentOptions, fragment},
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
                        rebuilt = Some(datagram.decoded.original.clone());
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(rebuilt.unwrap().as_ref(), original.bytes().as_ref());
        }
    }
}

#[test]
fn fragment_limits_df_and_incomplete_headers_fail_before_returning_output() {
    let original = complete(false, false);
    assert_eq!(
        fragment(&original, Default::default()).unwrap(),
        vec![original.clone()]
    );
    for options in [
        FragmentOptions {
            mtu: 20,
            ..Default::default()
        },
        FragmentOptions {
            mtu: 128,
            max_fragments: 1,
            ..Default::default()
        },
        FragmentOptions {
            mtu: 128,
            max_output_bytes: 127,
            ..Default::default()
        },
    ] {
        assert!(fragment(&original, options).is_err());
    }
    let mut bytes = original.bytes().to_vec();
    bytes[6] = 0x40;
    bytes[10..12].fill(0);
    let checksum = packetcraftr_core::protocol::checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
    let df = Frame::new(UNIX_EPOCH, LinkType::IPV4, bytes).unwrap();
    assert!(
        fragment(
            &df,
            FragmentOptions {
                mtu: 128,
                ..Default::default()
            }
        )
        .is_err()
    );
    let v6 = complete(true, true);
    assert!(
        fragment(
            &v6,
            FragmentOptions {
                mtu: 128,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        fragment(
            &v6,
            FragmentOptions {
                mtu: 64,
                identification: Some(1),
                ..Default::default()
            }
        )
        .is_err()
    );
    let once = fragment(
        &original,
        FragmentOptions {
            mtu: 128,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(fragment(&once[0], Default::default()).is_err());
}
