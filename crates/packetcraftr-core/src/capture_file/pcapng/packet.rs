// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::frame::{Direction, Frame, Lengths};

use super::options::{parse_options, unique_option};
use crate::capture_file::error::Error;
use crate::capture_file::format::{Endianness, Format};
use crate::capture_file::header::{Interface, PcapNgOption};
use crate::capture_file::wire::{
    PCAPNG_OPTION_EPB_FLAGS, align_to_usize, decode_u16, decode_u32, pcapng_packet_bytes,
    timestamp_from_ticks, validate_declared_lengths,
};

pub(in crate::capture_file) struct ParsedPacket {
    pub(in crate::capture_file) frame: Frame,
    pub(in crate::capture_file) interface_id: u32,
    pub(in crate::capture_file) options: Vec<PcapNgOption>,
}

pub(in crate::capture_file) fn parse_enhanced_packet(
    body: &Bytes,
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
    max_options: usize,
) -> Result<ParsedPacket, Error> {
    parse(
        body,
        endianness,
        interfaces,
        interface_base,
        max_size,
        max_options,
        false,
    )
}

pub(in crate::capture_file) fn parse_obsolete_packet(
    body: &Bytes,
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
    max_options: usize,
) -> Result<ParsedPacket, Error> {
    parse(
        body,
        endianness,
        interfaces,
        interface_base,
        max_size,
        max_options,
        true,
    )
}

fn parse(
    body: &Bytes,
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
    max_options: usize,
    obsolete_layout: bool,
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
    // `captured_length <= padded_length`, so the data ends at or before `data_end <= body.len()`
    let options = parse_options(
        &body[data_end..],
        endianness,
        "pcapng packet options",
        max_options,
    )?;
    let direction = packet_direction(&options, endianness)?;
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
    frame.direction = direction;
    Ok(ParsedPacket {
        frame,
        interface_id,
        options,
    })
}

/// Simple packet blocks carry no options; `max_options` keeps the packet
/// parsers signature-compatible for the block-kind dispatch table.
pub(in crate::capture_file) fn parse_simple_packet(
    body: &Bytes,
    endianness: Endianness,
    interfaces: &[Interface],
    interface_base: u32,
    max_size: usize,
    _max_options: usize,
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
    })
}

fn packet_direction(
    options: &[PcapNgOption],
    endianness: Endianness,
) -> Result<Option<Direction>, Error> {
    let Some(flags) = unique_option(
        options,
        PCAPNG_OPTION_EPB_FLAGS,
        "packet flags option appears more than once",
    )?
    else {
        return Ok(None);
    };
    if flags.len() != 4 {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "epb_flags option must contain four bytes",
        });
    }
    Ok(Some(match decode_u32(endianness, flags)? & 0b11 {
        1 => Direction::Inbound,
        2 => Direction::Outbound,
        _ => Direction::Unknown,
    }))
}

/// Only a defined inbound/outbound `epb_flags` direction survives a rewrite; the rest is refused.
pub(in crate::capture_file) fn validate_rewritable_packet_flags(
    options: &[PcapNgOption],
    endianness: Endianness,
    malformed_reason: &'static str,
) -> Result<(), &'static str> {
    for option in options
        .iter()
        .filter(|option| option.code == PCAPNG_OPTION_EPB_FLAGS)
    {
        let bytes: [u8; 4] = option
            .value
            .as_ref()
            .try_into()
            .map_err(|_| malformed_reason)?;
        let flags = match endianness {
            Endianness::Little => u32::from_le_bytes(bytes),
            Endianness::Big => u32::from_be_bytes(bytes),
        };
        if flags & !3 != 0 {
            return Err("extended packet flags");
        }
        if flags == 3 {
            return Err("undefined packet direction");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture_file::wire::DEFAULT_TIMESTAMP_RESOLUTION;
    use crate::frame::LinkType;

    #[test]
    fn a_malformed_option_list_is_reported_before_a_malformed_flags_option() {
        let interface = Interface {
            link_type: LinkType(1),
            snap_len: 0,
            timestamp_resolution: DEFAULT_TIMESTAMP_RESOLUTION,
            timestamp_offset: 0,
        };
        let parse = |options: &[u8]| {
            let mut body = vec![0; 20];
            body.extend_from_slice(options);
            parse_enhanced_packet(
                &Bytes::from(body),
                Endianness::Little,
                std::slice::from_ref(&interface),
                0,
                1500,
                usize::MAX,
            )
        };
        let cases = [
            (
                vec![2, 0, 2, 0, 1, 0, 0, 0],
                "epb_flags option must contain four bytes",
            ),
            (
                [[2, 0, 4, 0, 1, 0, 0, 0]; 2].concat(),
                "packet flags option appears more than once",
            ),
        ];
        for (flags_error, expected) in cases {
            assert!(
                matches!(
                    parse(&flags_error),
                    Err(Error::InvalidData { reason, .. }) if reason == expected
                ),
                "{expected}"
            );
            assert!(matches!(
                parse(&[flags_error.as_slice(), &[1, 0]].concat()),
                Err(Error::Truncated {
                    context: "pcapng packet options",
                    ..
                })
            ));
            assert!(matches!(
                parse(&[flags_error.as_slice(), &[0, 0, 0, 0, 1, 0, 0, 0]].concat()),
                Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "non-zero bytes follow the end-of-options marker",
                })
            ));
        }
    }
}
