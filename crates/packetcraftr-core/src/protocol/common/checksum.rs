// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Internet checksum accumulation and transport pseudo-header checksums.

use std::net::IpAddr;

use crate::codec::NetworkEnvelope;

use super::errors::invalid;

/// Returns the 16-bit Internet Checksum (RFC 1071) of one contiguous slice.
pub fn checksum(bytes: &[u8]) -> u16 {
    checksum_parts(&[bytes])
}

/// Returns the Internet Checksum of `parts` read as one contiguous byte
/// stream, so a part may end on an odd boundary.
pub fn checksum_parts(parts: &[&[u8]]) -> u16 {
    let mut accumulator = ChecksumAccumulator::default();
    for part in parts {
        accumulator.add(part);
    }
    accumulator.finish()
}

/// Accumulates 16-bit Internet Checksum (RFC 1071) over contiguous or chunked byte slices.
#[derive(Debug, Clone, Default)]
pub struct ChecksumAccumulator {
    sum: u128,
    pending_high_byte: Option<u8>,
}

impl ChecksumAccumulator {
    /// Adds a byte slice to the accumulator.
    ///
    /// Bytes are folded in 64-bit chunks: RFC 1071 permits summing 16-bit words in wider
    /// registers because carry propagation matches ones'-complement addition modulo 2^16 - 1,
    /// and the `u128` sum has room for every chunk a slice can contribute.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "the u128 accumulator has room for far more than the 2^64 word additions a slice could contribute"
    )]
    pub fn add(&mut self, bytes: &[u8]) {
        let mut bytes = bytes;
        if let Some(high) = self.pending_high_byte {
            let Some((&low, remaining)) = bytes.split_first() else {
                return;
            };
            self.sum += u128::from(u16::from_be_bytes([high, low]));
            bytes = remaining;
            self.pending_high_byte = None;
        }

        let mut chunks8 = bytes.chunks_exact(8);
        for chunk in &mut chunks8 {
            #[expect(
                clippy::indexing_slicing,
                reason = "chunks_exact(8) yields slices of length exactly 8"
            )]
            let arr = [
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ];
            self.sum += u128::from(u64::from_be_bytes(arr));
        }

        let remainder = chunks8.remainder();
        let mut chunks2 = remainder.chunks_exact(2);
        for chunk in &mut chunks2 {
            #[expect(
                clippy::indexing_slicing,
                reason = "chunks_exact(2) yields slices of length exactly 2"
            )]
            let arr = [chunk[0], chunk[1]];
            self.sum += u128::from(u16::from_be_bytes(arr));
        }

        self.pending_high_byte = chunks2.remainder().first().copied();
    }

    /// Finalizes and returns the 16-bit Internet Checksum.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "the pending byte contributes at most 0xff00, which the u128 accumulator still has room for"
    )]
    pub fn finish(self) -> u16 {
        let sum = self.sum
            + self
                .pending_high_byte
                .map_or(0, |high| u128::from(high) << 8);
        fold_checksum(sum)
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the loop only exits once sum >> 16 is zero, so sum is at most 0xffff"
)]
#[expect(
    clippy::arithmetic_side_effects,
    reason = "each addend is a masked or shifted half of sum, so every fold step stays below u128::MAX"
)]
fn fold_checksum(mut sum: u128) -> u16 {
    sum = (sum & 0xffff_ffff_ffff_ffff) + (sum >> 64);
    sum = (sum & 0xffff_ffff) + (sum >> 32);
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// `name` is the calling codec's protocol, so a pseudo-header failure is
/// reported against a protocol that is actually in the catalog.
pub(crate) fn transport_checksum(
    name: &'static str,
    network: NetworkEnvelope,
    protocol_number: u8,
    segment: &[u8],
) -> Result<u16, crate::codec::Error> {
    transport_checksum_parts(name, network, protocol_number, &[segment])
}

/// Treats `parts` as one contiguous byte stream, including across odd boundaries.
pub(crate) fn transport_checksum_parts(
    name: &'static str,
    network: NetworkEnvelope,
    protocol_number: u8,
    parts: &[&[u8]],
) -> Result<u16, crate::codec::Error> {
    let transport_length = parts
        .iter()
        .try_fold(0_usize, |total, part| total.checked_add(part.len()))
        .ok_or_else(|| invalid(name, "segment length overflow"))?;
    let mut accumulator = ChecksumAccumulator::default();
    match (network.source, network.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let length = u16::try_from(transport_length)
                .map_err(|_| invalid(name, "IPv4 segment exceeds 65535 bytes"))?;
            accumulator.add(&source.octets());
            accumulator.add(&destination.octets());
            accumulator.add(&[0, protocol_number]);
            accumulator.add(&length.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let length = u32::try_from(transport_length)
                .map_err(|_| invalid(name, "IPv6 segment exceeds u32 length"))?;
            accumulator.add(&source.octets());
            accumulator.add(&destination.octets());
            accumulator.add(&length.to_be_bytes());
            accumulator.add(&[0, 0, 0, protocol_number]);
        }
        _ => return Err(invalid(name, "mixed IP versions in pseudo-header")),
    }
    for part in parts {
        accumulator.add(part);
    }
    Ok(accumulator.finish())
}

pub(crate) fn network_from_addresses(source: IpAddr, destination: IpAddr) -> NetworkEnvelope {
    NetworkEnvelope {
        source,
        destination,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use super::{checksum, checksum_parts};

    #[test]
    fn known_ipv4_header_vector_matches_rfc_checksum() {
        let mut header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(checksum(&header), 0xb861);

        header[10..12].copy_from_slice(&0xb861_u16.to_be_bytes());
        assert_eq!(checksum(&header), 0);
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
            checksum_parts(&[&source, &destination, &length, &next_header, &message]),
            0xc48f
        );
        message[2..4].copy_from_slice(&0xc48f_u16.to_be_bytes());
        assert_eq!(
            checksum_parts(&[&source, &destination, &length, &next_header, &message]),
            0
        );
    }
}
