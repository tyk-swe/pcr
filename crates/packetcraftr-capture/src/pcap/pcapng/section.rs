// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Section-header block parsing and block-length validation.

use std::io::Read;

use super::super::{
    error::Error,
    model::{Endianness, Format},
    wire::{
        decode_i64, decode_u16, decode_u32, read_exact_counted, read_exact_or_eof, read_exact_vec,
    },
};
use super::options::visit_options;

#[derive(Clone, Copy)]
pub(in crate::pcap) struct SectionHeader {
    pub endianness: Endianness,
    pub length: Option<u64>,
    pub block_length: usize,
}

pub(in crate::pcap) fn read_pcapng_block_header<R: Read>(
    reader: &mut R,
) -> Result<Option<[u8; 8]>, Error> {
    let mut header = [0_u8; 8];
    if read_exact_or_eof(reader, &mut header, "pcapng block header")? {
        Ok(Some(header))
    } else {
        Ok(None)
    }
}

pub(in crate::pcap) fn read_section_header_after_type<R: Read>(
    reader: &mut R,
    max_size: usize,
    scratch: &mut Vec<u8>,
) -> Result<SectionHeader, Error> {
    let mut length = [0_u8; 4];
    read_exact_counted(reader, &mut length, "pcapng section header length")?;
    read_section_header_with_length(reader, length, max_size, None, scratch)
}

pub(in crate::pcap) fn read_section_header_with_length<R: Read>(
    reader: &mut R,
    raw_length: [u8; 4],
    max_size: usize,
    metadata_budget: Option<(usize, usize)>,
    scratch: &mut Vec<u8>,
) -> Result<SectionHeader, Error> {
    let mut raw_bom = [0_u8; 4];
    read_exact_counted(reader, &mut raw_bom, "pcapng byte-order magic")?;
    let endianness = match raw_bom {
        [0x4d, 0x3c, 0x2b, 0x1a] => Endianness::Little,
        [0x1a, 0x2b, 0x3c, 0x4d] => Endianness::Big,
        _ => {
            return Err(Error::InvalidData {
                format: Format::PcapNg,
                reason: "invalid section byte-order magic",
            });
        }
    };
    let block_length = decode_u32(endianness, &raw_length)?;
    validate_pcapng_block_length(block_length, max_size)?;
    let block_length_usize =
        usize::try_from(block_length).map_err(|_| Error::InvalidBlockLength {
            length: block_length,
        })?;
    if let Some((consumed, limit)) = metadata_budget
        && consumed
            .checked_add(block_length_usize)
            .is_none_or(|actual| actual > limit)
    {
        return Err(Error::MetadataByteLimit { limit });
    }
    if block_length < 28 {
        return Err(Error::InvalidBlockLength {
            length: block_length,
        });
    }

    let remaining_length = block_length_usize - 12;
    read_exact_vec(reader, scratch, remaining_length, "pcapng section header")?;
    let footer_offset = scratch.len() - 4;
    let trailing_length = decode_u32(endianness, &scratch[footer_offset..])?;
    if trailing_length != block_length {
        return Err(Error::BlockLengthMismatch {
            leading: block_length,
            trailing: trailing_length,
        });
    }

    let major = decode_u16(endianness, &scratch[0..2])?;
    let minor = decode_u16(endianness, &scratch[2..4])?;
    if major != 1 || (minor != 0 && minor != 2) {
        return Err(Error::UnsupportedVersion {
            format: Format::PcapNg,
            major,
            minor,
        });
    }
    let section_length = decode_i64(endianness, &scratch[4..12])?;
    if section_length < -1 {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "section length is negative but is not the unknown-length sentinel",
        });
    }
    if section_length >= 0 && section_length % 4 != 0 {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "section length is not a multiple of four",
        });
    }
    visit_options(
        &scratch[12..footer_offset],
        endianness,
        "pcapng section options",
        |_, _| Ok(()),
    )?;
    Ok(SectionHeader {
        endianness,
        length: u64::try_from(section_length).ok(),
        block_length: block_length_usize,
    })
}

pub(in crate::pcap) fn validate_pcapng_block_length(
    length: u32,
    max_size: usize,
) -> Result<(), Error> {
    if length < 12 || !length.is_multiple_of(4) {
        return Err(Error::InvalidBlockLength { length });
    }
    if length as usize > max_size {
        return Err(Error::SizeLimitExceeded {
            kind: "pcapng block",
            declared: u64::from(length),
            limit: max_size,
        });
    }
    Ok(())
}
