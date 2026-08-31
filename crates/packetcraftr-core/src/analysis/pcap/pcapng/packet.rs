// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet-block parsing.

use bytes::Bytes;

use crate::frame::{Direction, Frame};

use super::options::visit_options;
use crate::analysis::pcap::error::Error;
use crate::analysis::pcap::model::{Endianness, Format, Interface};
use crate::analysis::pcap::wire::{
    PCAPNG_OPTION_EPB_FLAGS, align_to_usize, copy_bytes_fallibly, decode_u16, decode_u32,
    timestamp_from_ticks, validate_declared_lengths,
};

/// One parsed packet block.
///
/// The single pass over the block header already reads the interface ID and
/// locates the trailing options, so both travel out with the frame instead
/// of being decoded a second time from the raw block type.
pub(in crate::analysis::pcap) struct ParsedPacket<'a> {
    pub(in crate::analysis::pcap) frame: Frame,
    pub(in crate::analysis::pcap) interface_id: u32,
    /// Option bytes following the packet data. A simple packet block has no
    /// options at all, so this is empty for one.
    pub(in crate::analysis::pcap) options: &'a [u8],
}

pub(in crate::analysis::pcap) fn parse_enhanced_packet<'a>(
    body: &'a [u8],
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
) -> Result<ParsedPacket<'a>, Error> {
    parse(
        body,
        endianness,
        interfaces,
        interface_base,
        max_size,
        false,
    )
}

pub(in crate::analysis::pcap) fn parse_obsolete_packet<'a>(
    body: &'a [u8],
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
) -> Result<ParsedPacket<'a>, Error> {
    parse(body, endianness, interfaces, interface_base, max_size, true)
}

fn parse<'a>(
    body: &'a [u8],
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
    obsolete_layout: bool,
) -> Result<ParsedPacket<'a>, Error> {
    const HEADER_LENGTH: usize = 20;

    let Some(header) = body
        .get(..HEADER_LENGTH)
        .and_then(|bytes| <[u8; HEADER_LENGTH]>::try_from(bytes).ok())
    else {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: if obsolete_layout {
                "packet block is shorter than 20 bytes"
            } else {
                "enhanced packet block is shorter than 20 bytes"
            },
        });
    };
    let interface_id = if obsolete_layout {
        u32::from(decode_u16(endianness, &header[0..2])?)
    } else {
        decode_u32(endianness, &header[0..4])?
    };
    let timestamp_ticks = (u64::from(decode_u32(endianness, &header[4..8])?) << 32)
        | u64::from(decode_u32(endianness, &header[8..12])?);
    let captured_length = decode_u32(endianness, &header[12..16])?;
    let original_length = decode_u32(endianness, &header[16..20])?;
    validate_declared_lengths(captured_length, original_length, max_size, "pcapng packet")?;
    let interface = interfaces
        .get(interface_id as usize)
        .ok_or(Error::UndefinedInterface {
            interface: interface_id,
            available: interfaces.len(),
        })?;
    if interface.snap_len != 0 && captured_length > interface.snap_len {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "captured packet exceeds its interface snap length",
        });
    }
    let padded_length = align_to_usize(captured_length as usize)?;
    let data_end = HEADER_LENGTH
        .checked_add(padded_length)
        .ok_or(Error::InvalidData {
            format: Format::PcapNg,
            reason: "packet data offset overflow",
        })?;
    if data_end > body.len() {
        return Err(Error::Truncated {
            context: "pcapng packet data",
            expected: data_end,
            actual: body.len(),
        });
    }
    let actual_data_end =
        HEADER_LENGTH
            .checked_add(captured_length as usize)
            .ok_or(Error::InvalidData {
                format: Format::PcapNg,
                reason: "packet data offset overflow",
            })?;
    let trailing_options = body.get(data_end..).ok_or(Error::Truncated {
        context: "pcapng packet data",
        expected: data_end,
        actual: body.len(),
    })?;
    let direction = parse_packet_direction(trailing_options, endianness)?;
    let timestamp = timestamp_from_ticks(
        timestamp_ticks,
        interface.timestamp_resolution,
        interface.timestamp_offset,
    )?;
    let global_interface = interface_base
        .checked_add(interface_id)
        .ok_or(Error::InterfaceLimit { limit: usize::MAX })?;
    let data = body
        .get(HEADER_LENGTH..actual_data_end)
        .ok_or(Error::Truncated {
            context: "pcapng packet data",
            expected: actual_data_end,
            actual: body.len(),
        })?;
    let mut frame = Frame::try_with_lengths(
        timestamp,
        interface.link_type,
        captured_length,
        original_length,
        Bytes::from(copy_bytes_fallibly(data)?),
    )?;
    frame.interface = Some(global_interface);
    frame.direction = direction;
    Ok(ParsedPacket {
        frame,
        interface_id,
        options: trailing_options,
    })
}

pub(in crate::analysis::pcap) fn parse_simple_packet<'a>(
    body: &'a [u8],
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
) -> Result<ParsedPacket<'a>, Error> {
    if body.len() < 4 {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "simple packet block is shorter than four bytes",
        });
    }
    let interface = interfaces.first().ok_or(Error::UndefinedInterface {
        interface: 0,
        available: 0,
    })?;
    let original_length = decode_u32(endianness, body)?;
    let captured_length = if interface.snap_len == 0 {
        original_length
    } else {
        original_length.min(interface.snap_len)
    };
    validate_declared_lengths(
        captured_length,
        original_length,
        max_size,
        "pcapng simple packet",
    )?;
    let padded_length = align_to_usize(captured_length as usize)?;
    let expected = 4_usize
        .checked_add(padded_length)
        .ok_or(Error::InvalidData {
            format: Format::PcapNg,
            reason: "simple packet data offset overflow",
        })?;
    if body.len() != expected {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "simple packet block length does not match its packet length",
        });
    }
    let data_end = 4_usize
        .checked_add(captured_length as usize)
        .ok_or(Error::InvalidData {
            format: Format::PcapNg,
            reason: "simple packet data offset overflow",
        })?;
    let data = body.get(4..data_end).ok_or(Error::Truncated {
        context: "pcapng simple packet data",
        expected: data_end,
        actual: body.len(),
    })?;
    let mut frame = Frame::try_with_optional_timestamp(
        None,
        interface.link_type,
        captured_length,
        original_length,
        Bytes::from(copy_bytes_fallibly(data)?),
    )?;
    frame.interface = Some(interface_base);
    Ok(ParsedPacket {
        frame,
        interface_id: 0,
        options: &[],
    })
}

pub(in crate::analysis::pcap) fn parse_packet_direction(
    options: &[u8],
    endianness: Endianness,
) -> Result<Option<Direction>, Error> {
    let mut direction = None;
    let mut saw_flags = false;
    visit_options(
        options,
        endianness,
        "pcapng packet options",
        |code, value| {
            if code == PCAPNG_OPTION_EPB_FLAGS {
                if saw_flags {
                    return Err(Error::InvalidData {
                        format: Format::PcapNg,
                        reason: "packet flags option appears more than once",
                    });
                }
                saw_flags = true;
                if value.len() != 4 {
                    return Err(Error::InvalidData {
                        format: Format::PcapNg,
                        reason: "epb_flags option must contain four bytes",
                    });
                }
                direction = Some(match decode_u32(endianness, value)? & 0b11 {
                    1 => Direction::Inbound,
                    2 => Direction::Outbound,
                    _ => Direction::Unknown,
                });
            }
            Ok(())
        },
    )?;
    Ok(direction)
}
