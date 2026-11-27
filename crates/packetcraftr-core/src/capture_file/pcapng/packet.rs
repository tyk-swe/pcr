// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::frame::{Direction, Frame, Lengths};

use super::options::{unique_option, visit_options};
use crate::capture_file::error::Error;
use crate::capture_file::format::{Endianness, Format};
use crate::capture_file::header::{Interface, PcapNgOption};
use crate::capture_file::limits::ReaderLimits;
use crate::capture_file::wire::{
    PCAPNG_OPTION_EPB_FLAGS, Subnanosecond, align_to_usize, decode_u16, decode_u32,
    pcapng_packet_bytes, timestamp_from_ticks, validate_declared_lengths,
};

pub(in crate::capture_file) struct ParsedPacket {
    pub(in crate::capture_file) frame: Frame,
    pub(in crate::capture_file) interface_id: u32,
    pub(in crate::capture_file) options: Vec<PcapNgOption>,
    pub(in crate::capture_file) declares_fcs: bool,
}

#[derive(Clone, Copy)]
pub(in crate::capture_file) enum PacketRead {
    Record,
    Frame(Subnanosecond),
}

impl PacketRead {
    fn subnanosecond(self) -> Subnanosecond {
        match self {
            Self::Record => Subnanosecond::Reject,
            Self::Frame(subnanosecond) => subnanosecond,
        }
    }
}

const DUPLICATE_FLAGS: &str = "packet flags option appears more than once";

pub(in crate::capture_file) fn parse_timestamped_packet(
    body: &Bytes,
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    limits: &ReaderLimits,
    obsolete_layout: bool,
    read: PacketRead,
) -> Result<ParsedPacket, Error> {
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
    validate_declared_lengths(
        captured_length,
        original_length,
        limits.max_size,
        "pcapng packet",
    )?;
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
    // `captured_length <= padded_length`, so the data ends at or before `data_end <= body.len()`
    let mut options = Vec::new();
    let mut flags = None;
    visit_options(
        &body[data_end..],
        endianness,
        "pcapng packet options",
        limits.max_options_per_block,
        |code, value| {
            if code == PCAPNG_OPTION_EPB_FLAGS && flags.replace(value).is_some() {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: DUPLICATE_FLAGS,
                });
            }
            if matches!(read, PacketRead::Record) {
                options.push(PcapNgOption {
                    code,
                    value: Bytes::copy_from_slice(value),
                });
            }
            Ok(())
        },
    )?;
    let flags = flags
        .map(|value| decode_packet_flags(value, endianness))
        .transpose()?;
    let timestamp = timestamp_from_ticks(
        timestamp_ticks,
        interface.timestamp_resolution,
        interface.timestamp_offset,
        read.subnanosecond(),
    )?;
    let global_interface = interface_base
        .checked_add(interface_id)
        .ok_or(Error::InterfaceLimit { limit: usize::MAX })?;
    let mut frame = Frame::try_with_optional_timestamp(
        Some(timestamp),
        interface.link_type,
        Lengths {
            captured: captured_length,
            original: original_length,
        },
        pcapng_packet_bytes(
            body,
            HEADER_LENGTH,
            HEADER_LENGTH + captured_length as usize,
        )?,
    )?;
    frame.interface = Some(global_interface);
    frame.direction = flags.map(|flags| match flags & 0b11 {
        1 => Direction::Inbound,
        2 => Direction::Outbound,
        _ => Direction::Unknown,
    });
    Ok(ParsedPacket {
        frame,
        interface_id,
        options,
        declares_fcs: flags.is_some_and(|flags| flags & (0b1111 << 5) != 0),
    })
}

pub(in crate::capture_file) fn simple_packet_captured_length(
    original_length: u32,
    snap_len: u32,
) -> u32 {
    if snap_len == 0 {
        original_length
    } else {
        original_length.min(snap_len)
    }
}

pub(in crate::capture_file) fn parse_simple_packet(
    body: &Bytes,
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
) -> Result<ParsedPacket, Error> {
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
    let captured_length = simple_packet_captured_length(original_length, interface.snap_len);
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
    // `body.len() == 4 + padded_length`, and `captured_length <= padded_length`
    let mut frame = Frame::try_with_optional_timestamp(
        None,
        interface.link_type,
        Lengths {
            captured: captured_length,
            original: original_length,
        },
        pcapng_packet_bytes(body, 4, 4 + captured_length as usize)?,
    )?;
    frame.interface = Some(interface_base);
    Ok(ParsedPacket {
        frame,
        interface_id: 0,
        options: Vec::new(),
        declares_fcs: false,
    })
}

fn decode_packet_flags(flags: &[u8], endianness: Endianness) -> Result<u32, Error> {
    if flags.len() != 4 {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "epb_flags option must contain four bytes",
        });
    }
    decode_u32(endianness, flags)
}

pub(in crate::capture_file) fn validate_rewritable_packet_flags(
    options: &[PcapNgOption],
    endianness: Endianness,
    malformed_reason: &'static str,
) -> Result<(), &'static str> {
    let flags = unique_option(options, PCAPNG_OPTION_EPB_FLAGS, DUPLICATE_FLAGS)
        .and_then(|value| {
            value
                .map(|value| decode_packet_flags(value, endianness))
                .transpose()
        })
        .map_err(|_| malformed_reason)?
        .unwrap_or_default();
    if flags & !3 != 0 {
        return Err("extended packet flags");
    }
    if flags == 3 {
        return Err("undefined packet direction");
    }
    Ok(())
}
