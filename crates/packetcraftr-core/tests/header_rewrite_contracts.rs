// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use bytes::Bytes;
use packetcraftr_core::{
    analysis::pcap,
    build::Builder,
    decode::Dissector,
    error::BoundaryError,
    field::WireValue,
    frame::{Frame, Lengths, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        builtin,
        link::{Ethernet, Vlan},
        network::{Ipv4, Ipv6},
        transport::{Tcp, Udp},
    },
    transform::{self, FragmentOptions, HeaderRewrite, RewriteLimits, VlanRewrite},
};
use std::{io::Cursor, time::UNIX_EPOCH};
fn frame(ipv6: bool, tcp: bool, ethernet: bool, disabled: bool) -> Frame {
    let mut packet = Packet::new();
    if ethernet {
        packet.push(Ethernet::default());
        packet.push(Vlan::default());
    }
    if ipv6 {
        packet.push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Default::default()
        });
    } else {
        packet.push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            ..Default::default()
        });
    }
    if tcp {
        packet.push(Tcp {
            source_port: 40000,
            destination_port: 40001,
            ..Default::default()
        });
    } else {
        packet.push(Udp {
            source_port: 40000,
            destination_port: 40001,
            checksum: if disabled {
                WireValue::Exact(0)
            } else {
                WireValue::Auto
            },
            ..Default::default()
        });
    }
    packet.push(Raw::new(vec![0x51; 301]));
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    Frame::new(
        UNIX_EPOCH,
        if ethernet {
            LinkType::ETHERNET
        } else if ipv6 {
            LinkType::IPV6
        } else {
            LinkType::IPV4
        },
        built.bytes,
    )
    .unwrap()
}
#[test]
fn both_families_and_transports_rewrite_checksums_with_unchanged_entity_bytes() {
    for ipv6 in [false, true] {
        for tcp in [false, true] {
            for ethernet in [false, true] {
                let original = frame(ipv6, tcp, ethernet, false);
                let patch = HeaderRewrite {
                    source_ip: Some(
                        if ipv6 { "2001:db8::9" } else { "192.0.2.9" }
                            .parse()
                            .unwrap(),
                    ),
                    destination_ip: Some(
                        if ipv6 { "2001:db8::8" } else { "198.51.100.8" }
                            .parse()
                            .unwrap(),
                    ),
                    source_port: Some(48000),
                    destination_port: Some(48001),
                    ..Default::default()
                };
                let rewritten = transform::rewrite(&original, &patch, Default::default()).unwrap();
                assert_eq!(rewritten.bytes().len(), original.bytes().len());
                assert_eq!(rewritten.timestamp, original.timestamp);
                let decoded = Dissector::new(builtin::registry())
                    .decode(rewritten.clone(), Default::default())
                    .unwrap();
                assert_eq!(
                    decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
                    &[0x51; 301]
                );
                if tcp {
                    assert_eq!(decoded.packet.get::<Tcp>().unwrap().destination_port, 48001);
                } else {
                    assert_eq!(decoded.packet.get::<Udp>().unwrap().destination_port, 48001);
                }
                let rebuilt = Builder::new(builtin::registry())
                    .build(decoded.packet, Default::default(), Default::default())
                    .unwrap();
                assert_eq!(rebuilt.bytes, rewritten.bytes());
            }
        }
    }
}
#[test]
fn vlan_stack_replacement_and_disabled_ipv4_udp_checksum_are_faithful() {
    let original = frame(false, false, true, true);
    let patch = HeaderRewrite {
        source_mac: Some([2, 0, 0, 0, 0, 9]),
        destination_mac: Some([2, 0, 0, 0, 0, 8]),
        source_ip: Some("192.0.2.9".parse().unwrap()),
        vlans: Some(vec![
            VlanRewrite {
                ether_type: 0x88a8,
                identifier: 7,
                priority: 3,
                drop_eligible: false,
            },
            VlanRewrite {
                ether_type: 0x8100,
                identifier: 8,
                priority: 0,
                drop_eligible: true,
            },
        ]),
        ..Default::default()
    };
    let rewritten = transform::rewrite(&original, &patch, Default::default()).unwrap();
    assert_eq!(rewritten.bytes().len(), original.bytes().len() + 4);
    assert_eq!(&rewritten.bytes()[6..12], &[2, 0, 0, 0, 0, 9]);
    let decoded = Dissector::new(builtin::registry())
        .decode(rewritten.clone(), Default::default())
        .unwrap();
    assert_eq!(
        decoded.packet.get::<Udp>().unwrap().checksum,
        WireValue::Exact(0)
    );
    let stripped = transform::rewrite(
        &rewritten,
        &HeaderRewrite {
            vlans: Some(Vec::new()),
            ..Default::default()
        },
        Default::default(),
    )
    .unwrap();
    assert_eq!(&stripped.bytes()[12..14], &[8, 0]);
    assert_eq!(stripped.bytes().len(), rewritten.bytes().len() - 8);
}
#[test]
fn fragment_network_edits_truncation_and_output_growth_are_rejected() {
    let original = frame(false, false, true, false);
    let fragments = transform::fragment(
        &original,
        FragmentOptions {
            mtu: 76,
            ..Default::default()
        },
    )
    .unwrap();
    let patch = HeaderRewrite {
        source_ip: Some("192.0.2.9".parse().unwrap()),
        ..Default::default()
    };
    assert!(transform::rewrite(&fragments[0], &patch, Default::default()).is_err());
    let mac = HeaderRewrite {
        source_mac: Some([2; 6]),
        ..Default::default()
    };
    let changed = transform::rewrite(&fragments[0], &mac, Default::default()).unwrap();
    assert_eq!(&changed.bytes()[12..], &fragments[0].bytes()[12..]);
    assert!(
        transform::rewrite(
            &original,
            &patch,
            RewriteLimits {
                max_output_bytes: 10
            }
        )
        .is_err()
    );
    let truncated = Frame::try_with_lengths(
        UNIX_EPOCH,
        original.link_type,
        Lengths {
            captured: 40,
            original: original.original_length(),
        },
        original.bytes().slice(..40),
    )
    .unwrap();
    assert!(transform::rewrite(&truncated, &mac, Default::default()).is_err());
}
#[test]
fn capture_mapping_preserves_interface_options_and_rejects_declared_fcs() {
    for fcs in [false, true] {
        let original = frame(false, false, true, false);
        let mut source = pcap::Writer::pcapng(Vec::new()).unwrap();
        let interface = pcap::Interface {
            link_type: LinkType::ETHERNET,
            snap_len: 65535,
            timestamp_resolution: pcap::TimestampResolution::Decimal(9),
            timestamp_offset: 0,
        };
        let option = pcap::PcapNgOption {
            code: if fcs { 13 } else { 2 },
            value: if fcs {
                Bytes::from_static(&[32])
            } else {
                Bytes::from_static(b"fixture0")
            },
        };
        source
            .add_interface_description_with_options(interface, std::slice::from_ref(&option))
            .unwrap();
        source.write_frame(&original).unwrap();
        let mut reader = pcap::Reader::new(Cursor::new(source.into_inner())).unwrap();
        let mut output = pcap::Writer::pcapng(Vec::new()).unwrap();
        let patch = HeaderRewrite {
            source_ip: Some("192.0.2.9".parse().unwrap()),
            ..Default::default()
        };
        let result = pcap::map_frames(
            &mut reader,
            &mut output,
            Default::default(),
            0,
            |_, frame| {
                transform::rewrite(frame, &patch, Default::default())
                    .map_err(BoundaryError::from_error)
            },
        );
        if fcs {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap().frames_changed, 1);
            let mut reader = pcap::Reader::new(Cursor::new(output.into_inner())).unwrap();
            let record = reader.next_record().unwrap().unwrap();
            let pcap::RecordKind::Metadata(pcap::MetadataBlockKind::InterfaceDescription {
                options,
                ..
            }) = record.kind
            else {
                panic!("interface description")
            };
            assert!(options.contains(&option));
        }
    }
}
