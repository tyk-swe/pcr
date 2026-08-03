// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet-block parsing.

use std::time::UNIX_EPOCH;

use bytes::Bytes;

use crate::{Direction, Frame};

use super::super::error::Error;
use super::super::model::{Endianness, Format, Interface};
use super::super::wire::{
    PCAPNG_OPTION_EPB_FLAGS, align_to_usize, copy_bytes_fallibly, decode_u16, decode_u32,
    timestamp_from_ticks, validate_declared_lengths,
};
use super::options::visit_options;

pub(in crate::pcap) fn parse_enhanced_packet(
    body: &[u8],
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
) -> Result<Frame, Error> {
    if body.len() < 20 {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "enhanced packet block is shorter than 20 bytes",
        });
    }
    let header = PacketHeader {
        interface_id: decode_u32(endianness, &body[0..4])?,
        timestamp_ticks: (u64::from(decode_u32(endianness, &body[4..8])?) << 32)
            | u64::from(decode_u32(endianness, &body[8..12])?),
        captured_length: decode_u32(endianness, &body[12..16])?,
        original_length: decode_u32(endianness, &body[16..20])?,
    };
    parse_pcapng_packet_body(
        body,
        20,
        header,
        endianness,
        interfaces,
        interface_base,
        max_size,
    )
}

pub(in crate::pcap) fn parse_obsolete_packet(
    body: &[u8],
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
) -> Result<Frame, Error> {
    if body.len() < 20 {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "packet block is shorter than 20 bytes",
        });
    }
    let header = PacketHeader {
        interface_id: u32::from(decode_u16(endianness, &body[0..2])?),
        timestamp_ticks: (u64::from(decode_u32(endianness, &body[4..8])?) << 32)
            | u64::from(decode_u32(endianness, &body[8..12])?),
        captured_length: decode_u32(endianness, &body[12..16])?,
        original_length: decode_u32(endianness, &body[16..20])?,
    };
    parse_pcapng_packet_body(
        body,
        20,
        header,
        endianness,
        interfaces,
        interface_base,
        max_size,
    )
}

struct PacketHeader {
    interface_id: u32,
    timestamp_ticks: u64,
    captured_length: u32,
    original_length: u32,
}

fn parse_pcapng_packet_body(
    body: &[u8],
    data_offset: usize,
    header: PacketHeader,
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
) -> Result<Frame, Error> {
    let PacketHeader {
        interface_id,
        timestamp_ticks,
        captured_length,
        original_length,
    } = header;
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
    let data_end = data_offset
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
    let actual_data_end = data_offset + captured_length as usize;
    let direction = parse_packet_direction(&body[data_end..], endianness)?;
    let timestamp = timestamp_from_ticks(
        timestamp_ticks,
        interface.timestamp_resolution,
        interface.timestamp_offset,
    )?;
    let global_interface = interface_base
        .checked_add(interface_id)
        .ok_or(Error::InterfaceLimit { limit: usize::MAX })?;
    let mut frame = Frame::try_with_lengths(
        timestamp,
        interface.link_type,
        captured_length,
        original_length,
        Bytes::from(copy_bytes_fallibly(&body[data_offset..actual_data_end])?),
    )?;
    frame.interface = Some(global_interface);
    frame.direction = direction;
    Ok(frame)
}

pub(in crate::pcap) fn parse_simple_packet(
    body: &[u8],
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
) -> Result<Frame, Error> {
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
    let original_length = decode_u32(endianness, &body[0..4])?;
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
    // A Simple Packet Block has no timestamp field. UNIX_EPOCH is the
    // deterministic sentinel used by the raw capture record model.
    let mut frame = Frame::try_with_lengths(
        UNIX_EPOCH,
        interface.link_type,
        captured_length,
        original_length,
        Bytes::from(copy_bytes_fallibly(&body[4..4 + captured_length as usize])?),
    )?;
    frame.interface = Some(interface_base);
    Ok(frame)
}

pub(in crate::pcap) fn parse_packet_direction(
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
