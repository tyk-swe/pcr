// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use common::packets::transport_frame;
use packetcraftr_core::{
    decode::Dissector,
    field::WireValue,
    frame::{Frame, LinkType},
    protocol::{
        builtin,
        transport::{Tcp, Udp},
    },
    transform::{self, FragmentOptions, HeaderRewrite, RewriteLimits},
};
use std::time::UNIX_EPOCH;
fn frame(ipv6: bool, tcp: bool, ethernet: bool, disabled: bool) -> Frame {
    if tcp {
        transport_frame(
            ipv6,
            ethernet,
            Tcp {
                source_port: 40000,
                destination_port: 40001,
                ..Default::default()
            },
            &[0x51; 301],
        )
    } else {
        transport_frame(
            ipv6,
            ethernet,
            Udp {
                source_port: 40000,
                destination_port: 40001,
                checksum: if disabled {
                    WireValue::Exact(0)
                } else {
                    WireValue::Auto
                },
                ..Default::default()
            },
            &[0x51; 301],
        )
    }
}
#[test]
fn bad_link_rewrite_byte() {
    let trailer = [0xde, 0xad, 0xbe, 0xef, 0x01];
    for ipv6 in [false, true] {
        let datagram = frame(ipv6, false, true, false);
        let mut bytes = datagram.bytes().to_vec();
        bytes.extend_from_slice(&trailer);
        let original = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, bytes).unwrap();
        let patch = HeaderRewrite {
            source_ip: Some(
                if ipv6 { "2001:db8::9" } else { "192.0.2.9" }
                    .parse()
                    .unwrap(),
            ),
            source_port: Some(48000),
            ..Default::default()
        };
        let rewritten = transform::rewrite(&original, &patch, Default::default()).unwrap();
        let (before, after) = (original.bytes(), rewritten.bytes());
        assert_eq!(after.len(), before.len());
        assert_eq!(&after[after.len() - trailer.len()..], &trailer);
        // Ethernet 14 + VLAN 4, then the IP header and UDP.
        let ip = 18;
        let udp = ip + if ipv6 { 40 } else { 20 };
        let mut edited = vec![udp..udp + 2, udp + 6..udp + 8];
        edited.push(if ipv6 {
            ip + 8..ip + 24
        } else {
            ip + 12..ip + 16
        });
        if !ipv6 {
            edited.push(ip + 10..ip + 12);
        }
        for (offset, (old, new)) in before.iter().zip(after.as_ref()).enumerate() {
            if !edited.iter().any(|range| range.contains(&offset)) {
                assert_eq!(old, new, "byte {offset} changed outside the edited fields");
            }
        }
        let decoded = Dissector::new(builtin::registry())
            .decode(rewritten, Default::default())
            .unwrap();
        assert_eq!(decoded.packet.get::<Udp>().unwrap().source_port, 48000);
    }
}
#[test]
fn frag_network_growth_reject() {
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
    let truncated = common::truncated(&original, original.bytes().len() - 40);
    assert!(transform::rewrite(&truncated, &mac, Default::default()).is_err());
}
