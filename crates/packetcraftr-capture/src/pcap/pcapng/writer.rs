// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! PCAPNG block encoding.

use std::io::Write;

use crate::{Direction, Frame, LinkType};

use super::super::models::{Endianness, Error, TimestampResolution};
use super::super::wire::{
    PCAPNG_BYTE_ORDER_MAGIC, PCAPNG_ENHANCED_PACKET_BLOCK, PCAPNG_INTERFACE_DESCRIPTION_BLOCK,
    PCAPNG_OPTION_END, PCAPNG_OPTION_EPB_FLAGS, PCAPNG_OPTION_IF_TSOFFSET,
    PCAPNG_OPTION_IF_TSRESOL, PCAPNG_SECTION_HEADER_BLOCK, write_i64, write_padding, write_u16,
    write_u32,
};

pub(in crate::pcap) fn write_section_header<W: Write>(
    writer: &mut W,
    endianness: Endianness,
) -> Result<(), Error> {
    write_u32(writer, endianness, PCAPNG_SECTION_HEADER_BLOCK)?;
    write_u32(writer, endianness, 28)?;
    write_u32(writer, endianness, PCAPNG_BYTE_ORDER_MAGIC)?;
    write_u16(writer, endianness, 1)?;
    write_u16(writer, endianness, 0)?;
    write_i64(writer, endianness, -1)?;
    write_u32(writer, endianness, 28)?;
    Ok(())
}

pub(in crate::pcap) fn write_interface_description<W: Write>(
    writer: &mut W,
    endianness: Endianness,
    link_type: LinkType,
    snap_len: u32,
    timestamp_resolution: TimestampResolution,
    timestamp_offset: i64,
) -> Result<(), Error> {
    let block_length = if timestamp_offset == 0 { 32 } else { 44 };
    write_u32(writer, endianness, PCAPNG_INTERFACE_DESCRIPTION_BLOCK)?;
    write_u32(writer, endianness, block_length)?;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "validate_new_interface rejects a link type above u16::MAX with \
                  Error::LinkTypeOutOfRange before any interface description is written"
    )]
    let link_type_field = link_type.0 as u16;
    write_u16(writer, endianness, link_type_field)?;
    write_u16(writer, endianness, 0)?;
    write_u32(writer, endianness, snap_len)?;
    write_u16(writer, endianness, PCAPNG_OPTION_IF_TSRESOL)?;
    write_u16(writer, endianness, 1)?;
    let resolution = match timestamp_resolution {
        TimestampResolution::Decimal(exponent) if exponent <= 0x7f => exponent,
        TimestampResolution::Binary(exponent) if exponent <= 0x7f => exponent | 0x80,
        TimestampResolution::Decimal(exponent) => {
            return Err(Error::InvalidTimestampResolution { base: 10, exponent });
        }
        TimestampResolution::Binary(exponent) => {
            return Err(Error::InvalidTimestampResolution { base: 2, exponent });
        }
    };
    writer.write_all(&[resolution, 0, 0, 0])?;
    if timestamp_offset != 0 {
        write_u16(writer, endianness, PCAPNG_OPTION_IF_TSOFFSET)?;
        write_u16(writer, endianness, 8)?;
        write_i64(writer, endianness, timestamp_offset)?;
    }
    write_u16(writer, endianness, PCAPNG_OPTION_END)?;
    write_u16(writer, endianness, 0)?;
    write_u32(writer, endianness, block_length)?;
    Ok(())
}

pub(in crate::pcap) fn write_enhanced_packet<W: Write>(
    writer: &mut W,
    endianness: Endianness,
    interface_id: u32,
    timestamp: u64,
    block_length: u32,
    frame: &Frame,
) -> Result<(), Error> {
    write_u32(writer, endianness, PCAPNG_ENHANCED_PACKET_BLOCK)?;
    write_u32(writer, endianness, block_length)?;
    write_u32(writer, endianness, interface_id)?;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the PCAPNG enhanced packet block stores its 64-bit timestamp as two \
                  32-bit halves, so discarding the upper bits of each half is the format"
    )]
    let (timestamp_high, timestamp_low) = ((timestamp >> 32) as u32, timestamp as u32);
    write_u32(writer, endianness, timestamp_high)?;
    write_u32(writer, endianness, timestamp_low)?;
    write_u32(writer, endianness, frame.captured_length())?;
    write_u32(writer, endianness, frame.original_length())?;
    writer.write_all(frame.bytes())?;
    write_padding(writer, frame.captured_length())?;

    if let Some(direction) = frame.direction {
        write_u16(writer, endianness, PCAPNG_OPTION_EPB_FLAGS)?;
        write_u16(writer, endianness, 4)?;
        let flags = match direction {
            Direction::Unknown => 0,
            Direction::Inbound => 1,
            Direction::Outbound => 2,
        };
        write_u32(writer, endianness, flags)?;
        write_u16(writer, endianness, PCAPNG_OPTION_END)?;
        write_u16(writer, endianness, 0)?;
    }
    write_u32(writer, endianness, block_length)?;
    Ok(())
}
