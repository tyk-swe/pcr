// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Read;

use bytes::Bytes;

use super::PcapNgState;
use crate::capture_file::pcapng::section::validate_pcapng_block_length;
use crate::capture_file::{
    error::Error,
    limits::ReaderLimits,
    record::PacketBlockKind,
    wire::{
        PCAPNG_ENHANCED_PACKET_BLOCK, PCAPNG_PACKET_BLOCK, PCAPNG_SIMPLE_PACKET_BLOCK, decode_u32,
        read_exact_append,
    },
};

pub(super) struct FramedBlock {
    pub(super) block_type: u32,
    /// The block between its length fields, sharing `raw`'s storage.
    pub(super) body: Bytes,
    pub(super) raw: Bytes,
}

pub(super) const fn packet_block_kind(block_type: u32) -> Option<PacketBlockKind> {
    match block_type {
        PCAPNG_ENHANCED_PACKET_BLOCK => Some(PacketBlockKind::Enhanced),
        PCAPNG_PACKET_BLOCK => Some(PacketBlockKind::Obsolete),
        PCAPNG_SIMPLE_PACKET_BLOCK => Some(PacketBlockKind::Simple),
        _ => None,
    }
}

pub(super) fn read<R: Read>(
    reader: &mut R,
    raw_header: [u8; 8],
    state: &mut PcapNgState,
    limits: &ReaderLimits,
) -> Result<FramedBlock, Error> {
    let block_type = decode_u32(state.endianness, &raw_header[..4])?;
    let block_length = decode_u32(state.endianness, &raw_header[4..8])?;
    validate_pcapng_block_length(block_length, limits.max_size)?;
    if let Some(remaining) = state.remaining_in_section
        && u64::from(block_length) > remaining
    {
        return Err(Error::BlockCrossesSectionBoundary {
            block_length,
            remaining,
        });
    }
    let block_length_usize =
        usize::try_from(block_length).map_err(|_| Error::InvalidBlockLength {
            length: block_length,
        })?;
    if packet_block_kind(block_type).is_none() {
        state.account_metadata(block_length_usize, limits)?;
    }

    let mut raw = Vec::new();
    raw.try_reserve_exact(block_length_usize)
        .map_err(|_| Error::AllocationFailed {
            kind: "pcapng source block",
            requested: block_length_usize,
        })?;
    raw.extend_from_slice(&raw_header);
    // `block_length >= 12` was validated, so `raw` holds at least the trailing length
    read_exact_append(reader, &mut raw, block_length_usize - 8, "pcapng block")?;
    let body_end = raw.len() - 4;
    let trailing_length = decode_u32(state.endianness, &raw[body_end..])?;
    if trailing_length != block_length {
        return Err(Error::BlockLengthMismatch {
            leading: block_length,
            trailing: trailing_length,
        });
    }
    state.commit_block(block_length);
    let raw = Bytes::from(raw);
    Ok(FramedBlock {
        block_type,
        body: raw.slice(8..body_end),
        raw,
    })
}
