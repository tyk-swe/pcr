// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;

use crate::{Frame, LinkType};

use super::models::{Endianness, Error, Format, TimestampPrecision};
use super::reader::ReaderState;
use super::wire::{
    PCAP_GLOBAL_HEADER_LEN, PCAP_RECORD_HEADER_LEN, decode_u16, decode_u32, read_exact_counted,
    read_exact_or_eof, read_exact_vec, validate_declared_lengths, write_u16, write_u32,
};

pub(super) fn read_pcap_header<R: Read>(
    reader: &mut R,
    endianness: Endianness,
    precision: TimestampPrecision,
) -> Result<ReaderState, Error> {
    let mut remaining = [0_u8; PCAP_GLOBAL_HEADER_LEN - 4];
    read_exact_counted(reader, &mut remaining, "pcap global header")?;
    let major = decode_u16(endianness, &remaining[0..2]);
    let minor = decode_u16(endianness, &remaining[2..4]);
    if (major, minor) != (2, 4) {
        return Err(Error::UnsupportedVersion {
            format: Format::Pcap,
            major,
            minor,
        });
    }
    let snap_len = decode_u32(endianness, &remaining[12..16]);
    if snap_len == 0 {
        return Err(Error::InvalidData {
            format: Format::Pcap,
            reason: "snapshot length must be non-zero",
        });
    }
    // The classic-PCAP network word uses its low 16 bits for LINKTYPE and may
    // carry standardized FCS metadata in the high bits. Do not misclassify a
    // flagged Ethernet capture as an unknown 32-bit DLT.
    let network_word = decode_u32(endianness, &remaining[16..20]);
    let link_type = LinkType(network_word & 0xffff);
    Ok(ReaderState::Pcap {
        endianness,
        precision,
        snap_len,
        link_type,
    })
}

pub(super) fn read_next_pcap_frame<R: Read>(
    reader: &mut R,
    endianness: Endianness,
    precision: TimestampPrecision,
    snap_len: u32,
    link_type: LinkType,
    max_size: usize,
) -> Result<Option<Frame>, Error> {
    let mut header = [0_u8; PCAP_RECORD_HEADER_LEN];
    if !read_exact_or_eof(reader, &mut header, "pcap packet header")? {
        return Ok(None);
    }

    let seconds = decode_u32(endianness, &header[0..4]);
    let fraction = decode_u32(endianness, &header[4..8]);
    let captured_length = decode_u32(endianness, &header[8..12]);
    let original_length = decode_u32(endianness, &header[12..16]);
    let denominator = match precision {
        TimestampPrecision::Microseconds => 1_000_000,
        TimestampPrecision::Nanoseconds => 1_000_000_000,
    };
    if fraction >= denominator {
        return Err(Error::InvalidTimestampFraction {
            fraction,
            denominator,
        });
    }
    validate_declared_lengths(captured_length, original_length, max_size, "pcap packet")?;
    if snap_len != 0 && captured_length > snap_len {
        return Err(Error::InvalidData {
            format: Format::Pcap,
            reason: "captured packet exceeds the file snap length",
        });
    }

    let mut bytes = Vec::new();
    read_exact_vec(
        reader,
        &mut bytes,
        captured_length as usize,
        "pcap packet data",
    )?;
    let nanoseconds = match precision {
        TimestampPrecision::Microseconds => fraction * 1_000,
        TimestampPrecision::Nanoseconds => fraction,
    };
    let timestamp = UNIX_EPOCH
        .checked_add(Duration::new(u64::from(seconds), nanoseconds))
        .ok_or(Error::TimestampOutOfRange {
            format: Format::Pcap,
        })?;

    Ok(Some(Frame::try_with_lengths(
        timestamp,
        link_type,
        captured_length,
        original_length,
        Bytes::from(bytes),
    )?))
}

/// Copies one capture stream into a bounded writer without retaining packet
/// payloads between records.
///
/// PCAPNG output normalizes multiple source sections into one section while
/// preserving the open link type, snap length, timestamp resolution/offset,
/// globalized interface identity, direction, captured length, original wire
/// length, and complete captured bytes. Classic PCAP can only be copied from
/// classic PCAP because its container cannot represent PCAPNG interfaces or
/// packet directions.
pub(super) fn write_pcap_header<W: Write>(
    writer: &mut W,
    endianness: Endianness,
    precision: TimestampPrecision,
    snap_len: u32,
    link_type: LinkType,
) -> Result<(), Error> {
    let magic = match (endianness, precision) {
        (Endianness::Little, TimestampPrecision::Microseconds) => [0xd4, 0xc3, 0xb2, 0xa1],
        (Endianness::Big, TimestampPrecision::Microseconds) => [0xa1, 0xb2, 0xc3, 0xd4],
        (Endianness::Little, TimestampPrecision::Nanoseconds) => [0x4d, 0x3c, 0xb2, 0xa1],
        (Endianness::Big, TimestampPrecision::Nanoseconds) => [0xa1, 0xb2, 0x3c, 0x4d],
    };
    writer.write_all(&magic)?;
    write_u16(writer, endianness, 2)?;
    write_u16(writer, endianness, 4)?;
    write_u32(writer, endianness, 0)?;
    write_u32(writer, endianness, 0)?;
    write_u32(writer, endianness, snap_len)?;
    write_u32(writer, endianness, link_type.0)?;
    Ok(())
}

pub(super) fn write_pcap_record<W: Write>(
    writer: &mut W,
    endianness: Endianness,
    seconds: u32,
    fraction: u32,
    frame: &Frame,
) -> Result<(), Error> {
    write_u32(writer, endianness, seconds)?;
    write_u32(writer, endianness, fraction)?;
    write_u32(writer, endianness, frame.captured_length())?;
    write_u32(writer, endianness, frame.original_length())?;
    writer.write_all(frame.bytes())?;
    Ok(())
}
