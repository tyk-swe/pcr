// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! PCAPNG block encoding and interface planning.

use std::io::Write;

use packetcraftr_packet::frame::{Direction, Frame, LinkType};

use super::super::{
    error::Error,
    model::{Endianness, Interface, TimestampResolution},
    wire::{
        PCAPNG_BYTE_ORDER_MAGIC, PCAPNG_ENHANCED_PACKET_BLOCK, PCAPNG_INTERFACE_DESCRIPTION_BLOCK,
        PCAPNG_OPTION_END, PCAPNG_OPTION_EPB_FLAGS, PCAPNG_OPTION_IF_TSOFFSET,
        PCAPNG_OPTION_IF_TSRESOL, PCAPNG_SECTION_HEADER_BLOCK, WRITER_TIMESTAMP_RESOLUTION,
        usize_to_u32_limit, validate_timestamp_resolution, write_i64, write_padding, write_u16,
        write_u32,
    },
};

#[derive(Clone, Debug)]
pub(in crate::pcap) struct InterfacePlan {
    pub id: u32,
    pub description: Interface,
    pub requires_description_block: bool,
}

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

pub(in crate::pcap) fn validate_new_interface(
    description: Interface,
    existing_interfaces: &[Interface],
    max_size: usize,
    max_interfaces: usize,
) -> Result<u32, Error> {
    validate_timestamp_resolution(description.timestamp_resolution)?;
    let block_length = if description.timestamp_offset == 0 {
        32
    } else {
        44
    };
    if max_size < block_length {
        return Err(Error::SizeLimitExceeded {
            kind: "pcapng interface description",
            declared: block_length as u64,
            limit: max_size,
        });
    }
    let next_count = existing_interfaces
        .len()
        .checked_add(1)
        .ok_or(Error::InterfaceLimit {
            limit: max_interfaces,
        })?;
    if next_count > max_interfaces {
        return Err(Error::InterfaceLimit {
            limit: max_interfaces,
        });
    }
    let interface_id =
        u32::try_from(existing_interfaces.len()).map_err(|_| Error::InterfaceLimit {
            limit: max_interfaces.min(u32::MAX as usize),
        })?;

    if description.link_type.0 > u16::MAX as u32 {
        return Err(Error::LinkTypeOutOfRange {
            link_type: description.link_type.0,
        });
    }

    Ok(interface_id)
}

pub(in crate::pcap) fn select_interface(
    frame: &Frame,
    interfaces: &[Interface],
    max_size: usize,
    max_interfaces: usize,
) -> Result<InterfacePlan, Error> {
    if let Some(interface_id) = frame.interface {
        let interface = interfaces
            .get(interface_id as usize)
            .ok_or(Error::UndefinedInterface {
                interface: interface_id,
                available: interfaces.len(),
            })?;
        if interface.link_type != frame.link_type {
            return Err(Error::InterfaceLinkTypeMismatch {
                interface: interface_id,
                expected: interface.link_type.0,
                actual: frame.link_type.0,
            });
        }
        return Ok(InterfacePlan {
            id: interface_id,
            description: interface.clone(),
            requires_description_block: false,
        });
    }

    let mut matches = interfaces
        .iter()
        .enumerate()
        .filter(|(_, interface)| interface.link_type == frame.link_type);
    let Some((index, description)) = matches.next() else {
        let description = Interface {
            link_type: frame.link_type,
            snap_len: usize_to_u32_limit(max_size)?,
            timestamp_resolution: WRITER_TIMESTAMP_RESOLUTION,
            timestamp_offset: 0,
        };
        let id = validate_new_interface(description.clone(), interfaces, max_size, max_interfaces)?;
        return Ok(InterfacePlan {
            id,
            description,
            requires_description_block: true,
        });
    };
    if matches.next().is_some() {
        return Err(Error::AmbiguousInterface {
            link_type: frame.link_type.0,
        });
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "validate_new_interface refuses indexes above u32"
    )]
    let id = index as u32;
    Ok(InterfacePlan {
        id,
        description: description.clone(),
        requires_description_block: false,
    })
}
