// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Internet checksum accumulation and transport pseudo-header checksums.

use std::net::IpAddr;

use crate::codec::{CodecError, NetworkEnvelope};

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

#[derive(Default)]
struct ChecksumAccumulator {
    sum: u64,
    pending_high_byte: Option<u8>,
}

impl ChecksumAccumulator {
    fn add(&mut self, bytes: &[u8]) {
        let mut bytes = bytes;
        if let Some(high) = self.pending_high_byte {
            let Some((&low, remaining)) = bytes.split_first() else {
                return;
            };
            self.sum += u64::from(u16::from_be_bytes([high, low]));
            bytes = remaining;
            self.pending_high_byte = None;
        }
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            self.sum += u64::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        self.pending_high_byte = chunks.remainder().first().copied();
    }

    fn finish(self) -> u16 {
        let sum = self.sum
            + self
                .pending_high_byte
                .map_or(0, |high| u64::from(high) << 8);
        fold_checksum(sum)
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the loop only exits once sum >> 16 is zero, so sum is at most 0xffff"
)]
fn fold_checksum(mut sum: u64) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn transport_checksum(
    network: NetworkEnvelope,
    protocol_number: u8,
    segment: &[u8],
) -> Result<u16, CodecError> {
    transport_checksum_parts(network, protocol_number, &[segment])
}

/// Treats `parts` as one contiguous byte stream, including across odd boundaries.
pub(crate) fn transport_checksum_parts(
    network: NetworkEnvelope,
    protocol_number: u8,
    parts: &[&[u8]],
) -> Result<u16, CodecError> {
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
