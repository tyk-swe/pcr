// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use packetcraftr_packet::codec::NetworkEnvelope;

use super::{checksum, checksum_parts, transport_checksum, transport_checksum_parts};

#[test]
fn checksum_preserves_end_around_carries_above_u32_accumulator_range() {
    let words = 65_538_usize;
    assert_eq!(checksum(&vec![0xff; words * 2]), 0);
}

#[test]
fn checksum_parts_carries_odd_bytes_across_boundaries() {
    let bytes = [0x01, 0x02, 0x03, 0x04, 0x05];
    assert_eq!(
        checksum_parts(&[&bytes[..1], &bytes[1..4], &bytes[4..]]),
        checksum(&bytes)
    );
}

#[test]
fn transport_checksum_parts_match_known_vectors() {
    let header = [0x13, 0x88, 0x00, 0x35, 0x00, 0x0d, 0x00, 0x00];
    let payload = [0xde, 0xad, 0xbe, 0xef, 0x01];
    let mut segment = header.to_vec();
    segment.extend_from_slice(&payload);
    for (network, expected) in [
        (
            NetworkEnvelope {
                source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            },
            0x6142,
        ),
        (
            NetworkEnvelope {
                source: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                destination: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            },
            0xf204,
        ),
    ] {
        assert_eq!(
            transport_checksum_parts(network, 17, &[&header[..3], &header[3..], &payload]).unwrap(),
            expected
        );
        assert_eq!(transport_checksum(network, 17, &segment).unwrap(), expected);
    }
}
