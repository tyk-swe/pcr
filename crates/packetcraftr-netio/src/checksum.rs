// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private Internet-checksum primitives shared by native wire paths.

use packetcraftr_core::protocol::ChecksumAccumulator;

pub(crate) fn compute(bytes: &[u8]) -> u16 {
    let mut accumulator = ChecksumAccumulator::default();
    accumulator.add(bytes);
    accumulator.finish()
}

pub(crate) fn compute_parts(parts: &[&[u8]]) -> u16 {
    if let [bytes] = parts {
        return compute(bytes);
    }
    let mut accumulator = ChecksumAccumulator::default();
    for part in parts {
        accumulator.add(part);
    }
    accumulator.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ipv4_header_vector_matches_rfc_checksum() {
        let mut header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(compute(&header), 0xb861);

        header[10..12].copy_from_slice(&0xb861_u16.to_be_bytes());
        assert_eq!(compute(&header), 0);
    }

    #[test]
    fn known_icmpv6_neighbor_solicitation_vector_matches() {
        let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination = [
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0xab, 0xcd,
        ];
        let length = 32_u32.to_be_bytes();
        let next_header = [0, 0, 0, 58];
        let mut message: [u8; 32] = [
            135, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab,
            0xcd, 1, 1, 2, 0, 0, 0, 0, 1,
        ];

        assert_eq!(
            compute_parts(&[&source, &destination, &length, &next_header, &message]),
            0xc48f
        );
        message[2..4].copy_from_slice(&0xc48f_u16.to_be_bytes());
        assert_eq!(
            compute_parts(&[&source, &destination, &length, &next_header, &message]),
            0
        );
    }

    #[test]
    fn every_two_boundary_split_matches_contiguous_odd_length_input() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0xf6, 0xf7];
        let expected = compute(&bytes);

        for first in 0..=bytes.len() {
            for second in first..=bytes.len() {
                assert_eq!(
                    compute_parts(&[&bytes[..first], &bytes[first..second], &bytes[second..],]),
                    expected,
                    "part boundaries {first} and {second}"
                );
            }
        }
        assert_eq!(compute(&[]), u16::MAX);
        assert_eq!(compute(&[0xff, 0xff]), 0);
    }
}
