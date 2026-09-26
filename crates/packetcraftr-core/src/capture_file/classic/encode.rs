// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;

use crate::frame::{Frame, LinkType};

use crate::capture_file::error::Error;
use crate::capture_file::model::{Endianness, TimestampPrecision};
use crate::capture_file::wire::{PCAP_RECORD_HEADER_LEN, write_u16, write_u32};

pub(in crate::capture_file) fn write_pcap_header<W: Write>(
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

// Timestamp and representability checks are shared by preview and output in Writer.
pub(in crate::capture_file) fn write_pcap_frame<W: Write>(
    writer: &mut W,
    endianness: Endianness,
    seconds: u32,
    fraction: u32,
    frame: &Frame,
) -> Result<(), Error> {
    let mut header = [0; PCAP_RECORD_HEADER_LEN];
    let mut fields = header.as_mut_slice();
    for value in [
        seconds,
        fraction,
        frame.captured_length(),
        frame.original_length(),
    ] {
        write_u32(&mut fields, endianness, value)?;
    }
    writer.write_all(&header)?;
    writer.write_all(frame.bytes())?;
    Ok(())
}
