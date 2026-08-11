// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Read;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;

use crate::frame::{Frame, LinkType};

use super::super::error::Error;
use super::super::model::{
    CaptureRecord, Endianness, Format, PacketBlockKind, PcapHeader, RecordKind, TimestampPrecision,
    TimestampResolution,
};
use super::super::reader::ReaderState;
use super::super::wire::{
    PCAP_GLOBAL_HEADER_LEN, PCAP_RECORD_HEADER_LEN, decode_u16, decode_u32, read_exact_counted,
    read_exact_or_eof, read_exact_vec, validate_declared_lengths,
};

pub(in crate::analysis::pcap) fn read_pcap_header<R: Read>(
    reader: &mut R,
    magic: [u8; 4],
    endianness: Endianness,
    precision: TimestampPrecision,
) -> Result<(ReaderState, PcapHeader), Error> {
    let mut remaining = [0_u8; PCAP_GLOBAL_HEADER_LEN - 4];
    read_exact_counted(reader, &mut remaining, "pcap global header")?;
    let major = decode_u16(endianness, &remaining[0..2])?;
    let minor = decode_u16(endianness, &remaining[2..4])?;
    if (major, minor) != (2, 4) {
        return Err(Error::UnsupportedVersion {
            format: Format::Pcap,
            major,
            minor,
        });
    }
    let snap_len = decode_u32(endianness, &remaining[12..16])?;
    if snap_len == 0 {
        return Err(Error::InvalidData {
            format: Format::Pcap,
            reason: "snapshot length must be non-zero",
        });
    }
    // The classic-PCAP network word uses its low 16 bits for LINKTYPE and may
    // carry standardized FCS metadata in the high bits. Do not misclassify a
    // flagged Ethernet capture as an unknown 32-bit DLT.
    let network_word = decode_u32(endianness, &remaining[16..20])?;
    let link_type = LinkType(network_word & 0xffff);
    let mut raw = Vec::with_capacity(PCAP_GLOBAL_HEADER_LEN);
    raw.extend_from_slice(&magic);
    raw.extend_from_slice(&remaining);
    Ok((
        ReaderState::Pcap {
            endianness,
            precision,
            snap_len,
            link_type,
        },
        PcapHeader {
            endianness,
            timestamp_resolution: match precision {
                TimestampPrecision::Microseconds => TimestampResolution::Decimal(6),
                TimestampPrecision::Nanoseconds => TimestampResolution::Decimal(9),
            },
            snap_len,
            network: network_word,
            raw: Bytes::from(raw),
        },
    ))
}

pub(in crate::analysis::pcap) fn read_next_pcap_record<R: Read>(
    reader: &mut R,
    endianness: Endianness,
    precision: TimestampPrecision,
    snap_len: u32,
    link_type: LinkType,
    max_size: usize,
) -> Result<Option<CaptureRecord>, Error> {
    let mut header = [0_u8; PCAP_RECORD_HEADER_LEN];
    if !read_exact_or_eof(reader, &mut header, "pcap packet header")? {
        return Ok(None);
    }

    let seconds = decode_u32(endianness, &header[0..4])?;
    let fraction = decode_u32(endianness, &header[4..8])?;
    let captured_length = decode_u32(endianness, &header[8..12])?;
    let original_length = decode_u32(endianness, &header[12..16])?;
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
    if captured_length > snap_len {
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

    let frame = Frame::try_with_lengths(
        timestamp,
        link_type,
        captured_length,
        original_length,
        Bytes::copy_from_slice(&bytes),
    )?;
    let mut raw = Vec::with_capacity(PCAP_RECORD_HEADER_LEN + bytes.len());
    raw.extend_from_slice(&header);
    raw.extend_from_slice(&bytes);
    Ok(Some(CaptureRecord {
        kind: RecordKind::Packet {
            block: PacketBlockKind::Classic,
            section: None,
            interface_id: None,
            options: Vec::new(),
        },
        frame: Some(frame),
        format: Format::Pcap,
        raw: Bytes::from(raw),
    }))
}
