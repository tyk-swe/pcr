// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Internet checksum accumulation and transport pseudo-header checksums.

use std::net::IpAddr;

use crate::codec::NetworkEnvelope;

use super::errors::invalid;

pub(crate) fn checksum(bytes: &[u8]) -> u16 {
    checksum_parts(&[bytes])
}

pub(crate) fn checksum_parts(parts: &[&[u8]]) -> u16 {
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
    /// Adds byte slice to the checksum accumulator.
    ///
    /// Performance: Processes bytes in 64-bit (8-byte) chunks instead of 16-bit (2-byte) chunks.
    /// RFC 1071 allows accumulating 16-bit big-endian words via 64-bit word additions because
    /// carry propagation in 64-bit addition matches ones' complement 16-bit word addition modulo (2^16 - 1).
    /// Using `u128` for `self.sum` prevents overflow during 64-bit chunk accumulation.
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

        // Process 8-byte chunks (64 bits) for up to 4x speedup on large byte slices.
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
fn fold_checksum(mut sum: u128) -> u16 {
    sum = (sum & 0xffff_ffff_ffff_ffff) + (sum >> 64);
    sum = (sum & 0xffff_ffff) + (sum >> 32);
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn transport_checksum(
    network: NetworkEnvelope,
    protocol_number: u8,
    segment: &[u8],
) -> Result<u16, crate::codec::Error> {
    transport_checksum_parts(network, protocol_number, &[segment])
}

/// Treats `parts` as one contiguous byte stream, including across odd boundaries.
pub(crate) fn transport_checksum_parts(
    network: NetworkEnvelope,
    protocol_number: u8,
    parts: &[&[u8]],
) -> Result<u16, crate::codec::Error> {
    let transport_length = parts
        .iter()
        .try_fold(0_usize, |total, part| total.checked_add(part.len()))
        .ok_or_else(|| invalid("transport", "transport segment length overflow"))?;
    let mut accumulator = ChecksumAccumulator::default();
    match (network.source, network.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let length = u16::try_from(transport_length)
                .map_err(|_| invalid("transport", "IPv4 transport segment exceeds 65535 bytes"))?;
            accumulator.add(&source.octets());
            accumulator.add(&destination.octets());
            accumulator.add(&[0, protocol_number]);
            accumulator.add(&length.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let length = u32::try_from(transport_length)
                .map_err(|_| invalid("transport", "IPv6 transport segment exceeds u32 length"))?;
            accumulator.add(&source.octets());
            accumulator.add(&destination.octets());
            accumulator.add(&length.to_be_bytes());
            accumulator.add(&[0, 0, 0, protocol_number]);
        }
        _ => return Err(invalid("transport", "mixed IP versions in pseudo-header")),
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
