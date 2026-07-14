use std::io::Read;
use std::time::UNIX_EPOCH;

use bytes::Bytes;

use crate::capture::{Direction, Frame, LinkType};

use super::models::{Endianness, Error, Format, Interface, TimestampResolution};
use super::wire::{
    DEFAULT_TIMESTAMP_RESOLUTION, PCAPNG_OPTION_END, PCAPNG_OPTION_EPB_FLAGS,
    PCAPNG_OPTION_IF_TSOFFSET, PCAPNG_OPTION_IF_TSRESOL, align_to_usize, decode_i64, decode_u16,
    decode_u32, read_exact_counted, read_exact_or_eof, timestamp_from_ticks,
    validate_declared_lengths,
};

pub(super) fn read_pcapng_block_header<R: Read>(reader: &mut R) -> Result<Option<[u8; 8]>, Error> {
    let mut header = [0_u8; 8];
    if read_exact_or_eof(reader, &mut header, "pcapng block header")? {
        Ok(Some(header))
    } else {
        Ok(None)
    }
}

pub(super) fn read_section_header_after_type<R: Read>(
    reader: &mut R,
    max_size: usize,
) -> Result<Endianness, Error> {
    let mut length = [0_u8; 4];
    read_exact_counted(reader, &mut length, "pcapng section header length")?;
    read_section_header_with_length(reader, length, max_size)
}

pub(super) fn read_section_header_with_length<R: Read>(
    reader: &mut R,
    raw_length: [u8; 4],
    max_size: usize,
) -> Result<Endianness, Error> {
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
    let block_length = decode_u32(endianness, &raw_length);
    validate_pcapng_block_length(block_length, max_size)?;
    if block_length < 28 {
        return Err(Error::InvalidBlockLength {
            length: block_length,
        });
    }

    let remaining_length = block_length as usize - 12;
    let mut remaining = vec![0_u8; remaining_length];
    read_exact_counted(reader, &mut remaining, "pcapng section header")?;
    let footer_offset = remaining.len() - 4;
    let trailing_length = decode_u32(endianness, &remaining[footer_offset..]);
    if trailing_length != block_length {
        return Err(Error::BlockLengthMismatch {
            leading: block_length,
            trailing: trailing_length,
        });
    }

    let major = decode_u16(endianness, &remaining[0..2]);
    let minor = decode_u16(endianness, &remaining[2..4]);
    // Some established writers emitted 1.2 without an incompatible format
    // change. The pcapng specification requires readers to treat it as 1.0.
    if major != 1 || (minor != 0 && minor != 2) {
        return Err(Error::UnsupportedVersion {
            format: Format::PcapNg,
            major,
            minor,
        });
    }
    let section_length = decode_i64(endianness, &remaining[4..12]);
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
        &remaining[12..footer_offset],
        endianness,
        "pcapng section options",
        |_, _| Ok(()),
    )?;
    Ok(endianness)
}

pub(super) fn validate_pcapng_block_length(length: u32, max_size: usize) -> Result<(), Error> {
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

pub(super) fn parse_interface_description(
    body: &[u8],
    endianness: Endianness,
) -> Result<Interface, Error> {
    if body.len() < 8 {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "interface description block is shorter than 8 bytes",
        });
    }
    let link_type = LinkType(u32::from(decode_u16(endianness, &body[0..2])));
    let snap_len = decode_u32(endianness, &body[4..8]);
    let mut timestamp_resolution = DEFAULT_TIMESTAMP_RESOLUTION;
    let mut timestamp_offset = 0_i64;
    let mut saw_timestamp_resolution = false;
    let mut saw_timestamp_offset = false;
    visit_options(
        &body[8..],
        endianness,
        "pcapng interface options",
        |code, value| {
            match code {
                PCAPNG_OPTION_IF_TSRESOL => {
                    if saw_timestamp_resolution {
                        return Err(Error::InvalidData {
                            format: Format::PcapNg,
                            reason: "if_tsresol option appears more than once",
                        });
                    }
                    saw_timestamp_resolution = true;
                    if value.len() != 1 {
                        return Err(Error::InvalidData {
                            format: Format::PcapNg,
                            reason: "if_tsresol option must contain one byte",
                        });
                    }
                    let resolution = value[0];
                    timestamp_resolution = if resolution & 0x80 == 0 {
                        TimestampResolution::Decimal(resolution)
                    } else {
                        TimestampResolution::Binary(resolution & 0x7f)
                    };
                }
                PCAPNG_OPTION_IF_TSOFFSET => {
                    if saw_timestamp_offset {
                        return Err(Error::InvalidData {
                            format: Format::PcapNg,
                            reason: "if_tsoffset option appears more than once",
                        });
                    }
                    saw_timestamp_offset = true;
                    if value.len() != 8 {
                        return Err(Error::InvalidData {
                            format: Format::PcapNg,
                            reason: "if_tsoffset option must contain eight bytes",
                        });
                    }
                    timestamp_offset = decode_i64(endianness, value);
                }
                _ => {}
            }
            Ok(())
        },
    )?;
    Ok(Interface {
        link_type,
        snap_len,
        timestamp_resolution,
        timestamp_offset,
    })
}

pub(super) fn parse_enhanced_packet(
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
        interface_id: decode_u32(endianness, &body[0..4]),
        timestamp_ticks: (u64::from(decode_u32(endianness, &body[4..8])) << 32)
            | u64::from(decode_u32(endianness, &body[8..12])),
        captured_length: decode_u32(endianness, &body[12..16]),
        original_length: decode_u32(endianness, &body[16..20]),
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

pub(super) fn parse_obsolete_packet(
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
        interface_id: u32::from(decode_u16(endianness, &body[0..2])),
        timestamp_ticks: (u64::from(decode_u32(endianness, &body[4..8])) << 32)
            | u64::from(decode_u32(endianness, &body[8..12])),
        captured_length: decode_u32(endianness, &body[12..16]),
        original_length: decode_u32(endianness, &body[16..20]),
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
    if body[actual_data_end..data_end]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "packet data padding is non-zero",
        });
    }
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
        Bytes::copy_from_slice(&body[data_offset..actual_data_end]),
    )?;
    frame.interface = Some(global_interface);
    frame.direction = direction;
    Ok(frame)
}

pub(super) fn parse_simple_packet(
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
    let original_length = decode_u32(endianness, &body[0..4]);
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
    let actual_data_end = 4 + captured_length as usize;
    if body[actual_data_end..expected]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Error::InvalidData {
            format: Format::PcapNg,
            reason: "simple packet data padding is non-zero",
        });
    }
    // A Simple Packet Block has no timestamp field. UNIX_EPOCH is the
    // deterministic sentinel used by the raw capture record model.
    let mut frame = Frame::try_with_lengths(
        UNIX_EPOCH,
        interface.link_type,
        captured_length,
        original_length,
        Bytes::copy_from_slice(&body[4..4 + captured_length as usize]),
    )?;
    frame.interface = Some(interface_base);
    Ok(frame)
}

fn parse_packet_direction(
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
                direction = Some(match decode_u32(endianness, value) & 0b11 {
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

fn visit_options<F>(
    options: &[u8],
    endianness: Endianness,
    context: &'static str,
    mut visitor: F,
) -> Result<(), Error>
where
    F: FnMut(u16, &[u8]) -> Result<(), Error>,
{
    let mut offset = 0_usize;
    while offset < options.len() {
        if options.len() - offset < 4 {
            return Err(Error::Truncated {
                context,
                expected: offset + 4,
                actual: options.len(),
            });
        }
        let code = decode_u16(endianness, &options[offset..offset + 2]);
        let length = usize::from(decode_u16(endianness, &options[offset + 2..offset + 4]));
        offset += 4;
        if code == PCAPNG_OPTION_END {
            if length != 0 {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "end-of-options marker has a non-zero length",
                });
            }
            if options[offset..].iter().any(|byte| *byte != 0) {
                return Err(Error::InvalidData {
                    format: Format::PcapNg,
                    reason: "non-zero bytes follow the end-of-options marker",
                });
            }
            return Ok(());
        }
        let padded_length = align_to_usize(length)?;
        let end = offset
            .checked_add(padded_length)
            .ok_or(Error::InvalidData {
                format: Format::PcapNg,
                reason: "option length overflow",
            })?;
        if end > options.len() {
            return Err(Error::Truncated {
                context,
                expected: end,
                actual: options.len(),
            });
        }
        visitor(code, &options[offset..offset + length])?;
        if options[offset + length..end].iter().any(|byte| *byte != 0) {
            return Err(Error::InvalidData {
                format: Format::PcapNg,
                reason: "option padding is non-zero",
            });
        }
        offset = end;
    }
    Ok(())
}
