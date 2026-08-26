// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Validated framing for non-section PCAPNG blocks.

use std::io::Read;

use bytes::Bytes;

use super::super::super::{
    error::Error,
    model::ReaderOptions,
    wire::{
        PCAPNG_ENHANCED_PACKET_BLOCK, PCAPNG_PACKET_BLOCK, PCAPNG_SIMPLE_PACKET_BLOCK, decode_u32,
        read_exact_vec,
    },
};
use super::super::section::validate_pcapng_block_length;
use super::PcapNgState;

pub(super) struct FramedBlock<'a> {
    pub(super) block_type: u32,
    pub(super) body: &'a [u8],
    pub(super) raw: Bytes,
}

pub(super) fn is_packet_block(block_type: u32) -> bool {
    matches!(
        block_type,
        PCAPNG_ENHANCED_PACKET_BLOCK | PCAPNG_PACKET_BLOCK | PCAPNG_SIMPLE_PACKET_BLOCK
    )
}

pub(super) fn read<'a, R: Read>(
    reader: &mut R,
    raw_header: [u8; 8],
    state: &mut PcapNgState,
    options: &ReaderOptions,
    scratch: &'a mut Vec<u8>,
) -> Result<FramedBlock<'a>, Error> {
    let block_type = decode_u32(state.endianness, &raw_header[..4])?;
    let block_length = decode_u32(state.endianness, &raw_header[4..8])?;
    validate_pcapng_block_length(block_length, options.max_size)?;
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
    if !is_packet_block(block_type) {
        state.account_metadata(block_length_usize, options)?;
    }

    let payload_length = block_length_usize
        .checked_sub(8)
        .ok_or(Error::InvalidBlockLength {
            length: block_length,
        })?;
    read_exact_vec(reader, scratch, payload_length, "pcapng block")?;
    let body_length = scratch
        .len()
        .checked_sub(4)
        .ok_or(Error::InvalidBlockLength {
            length: block_length,
        })?;
    #[expect(
        clippy::indexing_slicing,
        reason = "`body_length` is `scratch.len() - 4`, so the trailing four bytes are in bounds"
    )]
    let trailing_length = decode_u32(state.endianness, &scratch[body_length..])?;
    if trailing_length != block_length {
        return Err(Error::BlockLengthMismatch {
            leading: block_length,
            trailing: trailing_length,
        });
    }
    state.commit_block(block_length);
    let raw = raw_block(&raw_header, scratch, block_length_usize)?;
    #[expect(
        clippy::indexing_slicing,
        reason = "`body_length` is `scratch.len() - 4`, so the body prefix is in bounds"
    )]
    let body = &scratch[..body_length];
    Ok(FramedBlock {
        block_type,
        body,
        raw,
    })
}

fn raw_block(header: &[u8; 8], tail: &[u8], length: usize) -> Result<Bytes, Error> {
    let mut raw = Vec::new();
    raw.try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed {
            kind: "pcapng source block",
            requested: length,
        })?;
    raw.extend_from_slice(header);
    raw.extend_from_slice(tail);
    Ok(Bytes::from(raw))
}
