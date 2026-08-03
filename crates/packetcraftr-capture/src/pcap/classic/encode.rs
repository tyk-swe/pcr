// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::time::UNIX_EPOCH;

use crate::{Frame, LinkType};

use super::super::error::Error;
use super::super::model::{Endianness, Format, TimestampPrecision};
use super::super::wire::{write_u16, write_u32};

pub(in crate::pcap) fn write_pcap_header<W: Write>(
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

pub(in crate::pcap) fn write_pcap_record<W: Write>(
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

pub(in crate::pcap) fn write_pcap_frame<W: Write>(
    writer: &mut W,
    endianness: Endianness,
    precision: TimestampPrecision,
    snap_len: u32,
    link_type: LinkType,
    frame: &Frame,
) -> Result<(), Error> {
    if frame.interface.is_some() {
        return Err(Error::MetadataNotRepresentable {
            format: Format::Pcap,
            field: "interface",
        });
    }
    if frame.direction.is_some() {
        return Err(Error::MetadataNotRepresentable {
            format: Format::Pcap,
            field: "direction",
        });
    }
    if frame.link_type != link_type {
        return Err(Error::InterfaceLinkTypeMismatch {
            interface: 0,
            expected: link_type.0,
            actual: frame.link_type.0,
        });
    }
    if frame.captured_length() > snap_len {
        return Err(Error::SizeLimitExceeded {
            kind: "pcap captured packet",
            declared: u64::from(frame.captured_length()),
            limit: snap_len as usize,
        });
    }

    let elapsed =
        frame
            .timestamp
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::TimestampOutOfRange {
                format: Format::Pcap,
            })?;
    let seconds = u32::try_from(elapsed.as_secs()).map_err(|_| Error::TimestampOutOfRange {
        format: Format::Pcap,
    })?;

    let fraction = match precision {
        TimestampPrecision::Microseconds if !elapsed.subsec_nanos().is_multiple_of(1_000) => {
            return Err(Error::MetadataNotRepresentable {
                format: Format::Pcap,
                field: "microsecond timestamp precision",
            });
        }
        TimestampPrecision::Microseconds => elapsed.subsec_micros(),
        TimestampPrecision::Nanoseconds => elapsed.subsec_nanos(),
    };

    write_pcap_record(writer, endianness, seconds, fraction, frame)
}
