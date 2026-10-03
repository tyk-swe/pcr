// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use crate::codec::NetworkEnvelope;

use super::errors::invalid;

pub fn checksum(bytes: &[u8]) -> u16 {
    checksum_parts(&[bytes])
}

pub fn checksum_parts(parts: &[&[u8]]) -> u16 {
    let mut accumulator = ChecksumAccumulator::default();
    for part in parts {
        accumulator.add(part);
    }
    accumulator.finish()
}

#[derive(Debug, Clone, Default)]
pub struct ChecksumAccumulator {
    sum: u128,
    pending_high_byte: Option<u8>,
}

impl ChecksumAccumulator {
    /// Bytes are folded in 64-bit chunks: RFC 1071 permits summing 16-bit words in wider
    /// registers because carry propagation matches ones'-complement addition modulo 2^16 - 1.
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

        let (chunks8, remainder) = bytes.as_chunks::<8>();
        for chunk in chunks8 {
            self.sum += u128::from(u64::from_be_bytes(*chunk));
        }
        let (chunks2, remainder) = remainder.as_chunks::<2>();
        for chunk in chunks2 {
            self.sum += u128::from(u16::from_be_bytes(*chunk));
        }
        self.pending_high_byte = remainder.first().copied();
    }

    pub fn finish(self) -> u16 {
        let sum = self.sum
            + self
                .pending_high_byte
                .map_or(0, |high| u128::from(high) << 8);
        fold_checksum(sum)
    }
}

// the loop only exits once sum >> 16 is zero, so sum is at most 0xffff
fn fold_checksum(mut sum: u128) -> u16 {
    sum = (sum & 0xffff_ffff_ffff_ffff) + (sum >> 64);
    sum = (sum & 0xffff_ffff) + (sum >> 32);
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn transport_checksum(
    name: &'static str,
    network: NetworkEnvelope,
    protocol_number: u8,
    segment: &[u8],
) -> Result<u16, crate::codec::Error> {
    transport_checksum_parts(name, network, protocol_number, &[segment])
}

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
