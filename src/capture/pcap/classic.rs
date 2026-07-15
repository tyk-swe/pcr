use std::io::Read;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;

use crate::capture::{Frame, LinkType};

use super::models::{Endianness, Error, Format, TimestampPrecision};
use super::reader::ReaderState;
use super::wire::{
    PCAP_GLOBAL_HEADER_LEN, PCAP_RECORD_HEADER_LEN, decode_u16, decode_u32, read_exact_counted,
    read_exact_or_eof, validate_declared_lengths,
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
    total_wire_bytes: &mut u64,
    options: PcapFrameOptions,
) -> Result<Option<Frame>, Error> {
    let mut header = [0_u8; PCAP_RECORD_HEADER_LEN];
    if !read_exact_or_eof(reader, &mut header, "pcap packet header")? {
        return Ok(None);
    }
    *total_wire_bytes = checked_wire_total(
        *total_wire_bytes,
        PCAP_RECORD_HEADER_LEN as u64,
        options.max_total_wire_bytes,
    )?;

    let seconds = decode_u32(options.endianness, &header[0..4]);
    let fraction = decode_u32(options.endianness, &header[4..8]);
    let captured_length = decode_u32(options.endianness, &header[8..12]);
    let original_length = decode_u32(options.endianness, &header[12..16]);
    let denominator = match options.precision {
        TimestampPrecision::Microseconds => 1_000_000,
        TimestampPrecision::Nanoseconds => 1_000_000_000,
    };
    if fraction >= denominator {
        return Err(Error::InvalidTimestampFraction {
            fraction,
            denominator,
        });
    }
    validate_declared_lengths(
        captured_length,
        original_length,
        options.max_size,
        "pcap packet",
    )?;
    if options.snap_len != 0 && captured_length > options.snap_len {
        return Err(Error::InvalidData {
            format: Format::Pcap,
            reason: "captured packet exceeds the file snap length",
        });
    }

    *total_wire_bytes = checked_wire_total(
        *total_wire_bytes,
        u64::from(captured_length),
        options.max_total_wire_bytes,
    )?;

    let mut bytes = vec![0_u8; captured_length as usize];
    read_exact_counted(reader, &mut bytes, "pcap packet data")?;
    let nanoseconds = match options.precision {
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
        options.link_type,
        captured_length,
        original_length,
        Bytes::from(bytes),
    )?))
}

#[derive(Clone, Copy)]
pub(super) struct PcapFrameOptions {
    pub(super) endianness: Endianness,
    pub(super) precision: TimestampPrecision,
    pub(super) snap_len: u32,
    pub(super) link_type: LinkType,
    pub(super) max_size: usize,
    pub(super) max_total_wire_bytes: u64,
}

fn checked_wire_total(current: u64, addition: u64, limit: u64) -> Result<u64, Error> {
    let actual = current
        .checked_add(addition)
        .ok_or(Error::AccountingOverflow {
            resource: "total wire bytes",
        })?;
    if actual > limit {
        return Err(Error::TotalWireByteLimit { actual, limit });
    }
    Ok(actual)
}
