// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Read, Write};

use crate::frame::{Error as FrameError, Frame};

use super::super::error::Error;
use super::super::model::{Endianness, Format, TimestampResolution};

pub(in crate::analysis::pcap) const PCAP_GLOBAL_HEADER_LEN: usize = 24;
pub(in crate::analysis::pcap) const PCAP_RECORD_HEADER_LEN: usize = 16;
pub(in crate::analysis::pcap) const PCAPNG_SECTION_HEADER: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];
pub(in crate::analysis::pcap) const PCAPNG_BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;
pub(in crate::analysis::pcap) const PCAPNG_SECTION_HEADER_BLOCK: u32 = 0x0a0d_0d0a;
pub(in crate::analysis::pcap) const PCAPNG_INTERFACE_DESCRIPTION_BLOCK: u32 = 0x0000_0001;
pub(in crate::analysis::pcap) const PCAPNG_PACKET_BLOCK: u32 = 0x0000_0002;
pub(in crate::analysis::pcap) const PCAPNG_SIMPLE_PACKET_BLOCK: u32 = 0x0000_0003;
pub(in crate::analysis::pcap) const PCAPNG_NAME_RESOLUTION_BLOCK: u32 = 0x0000_0004;
pub(in crate::analysis::pcap) const PCAPNG_INTERFACE_STATISTICS_BLOCK: u32 = 0x0000_0005;
pub(in crate::analysis::pcap) const PCAPNG_ENHANCED_PACKET_BLOCK: u32 = 0x0000_0006;
pub(in crate::analysis::pcap) const PCAPNG_CUSTOM_BLOCK: u32 = 0x0000_0bad;
pub(in crate::analysis::pcap) const PCAPNG_CUSTOM_BLOCK_NO_COPY: u32 = 0x4000_0bad;
pub(in crate::analysis::pcap) const PCAPNG_OPTION_END: u16 = 0;
pub(in crate::analysis::pcap) const PCAPNG_OPTION_EPB_FLAGS: u16 = 2;
pub(in crate::analysis::pcap) const PCAPNG_OPTION_IF_TSRESOL: u16 = 9;
pub(in crate::analysis::pcap) const PCAPNG_OPTION_IF_TSOFFSET: u16 = 14;
pub(in crate::analysis::pcap) const DEFAULT_TIMESTAMP_RESOLUTION: TimestampResolution =
    TimestampResolution::Decimal(6);
pub(in crate::analysis::pcap) const WRITER_TIMESTAMP_RESOLUTION: TimestampResolution =
    TimestampResolution::Decimal(9);

pub(in crate::analysis::pcap) fn validate_frame_size(
    frame: &Frame,
    max_size: usize,
) -> Result<(), Error> {
    if frame.captured_length() as usize > max_size {
        return Err(Error::SizeLimitExceeded {
            kind: "captured packet",
            declared: u64::from(frame.captured_length()),
            limit: max_size,
        });
    }
    Ok(())
}

pub(in crate::analysis::pcap) fn validate_declared_lengths(
    captured_length: u32,
    original_length: u32,
    max_size: usize,
    kind: &'static str,
) -> Result<(), Error> {
    if original_length < captured_length {
        return Err(FrameError::OriginalLengthTooSmall {
            captured: captured_length,
            original: original_length,
        }
        .into());
    }
    if captured_length as usize > max_size {
        return Err(Error::SizeLimitExceeded {
            kind,
            declared: u64::from(captured_length),
            limit: max_size,
        });
    }
    Ok(())
}

pub(in crate::analysis::pcap) fn read_exact_or_eof<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    context: &'static str,
) -> Result<bool, Error> {
    let mut offset = 0;
    while offset < buffer.len() {
        match reader.read(&mut buffer[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => {
                return Err(Error::Truncated {
                    context,
                    expected: buffer.len(),
                    actual: offset,
                });
            }
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(Error::Io(error)),
        }
    }
    Ok(true)
}

pub(in crate::analysis::pcap) fn read_exact_counted<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
    context: &'static str,
) -> Result<(), Error> {
    if read_exact_or_eof(reader, buffer, context)? {
        Ok(())
    } else {
        Err(Error::Truncated {
            context,
            expected: buffer.len(),
            actual: 0,
        })
    }
}

pub(in crate::analysis::pcap) fn read_exact_vec<R: Read>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    length: usize,
    context: &'static str,
) -> Result<(), Error> {
    buffer.clear();
    buffer
        .try_reserve_exact(length)
        .map_err(|_| Error::Io(io::ErrorKind::OutOfMemory.into()))?;
    let actual = reader
        .take(length as u64)
        .read_to_end(buffer)
        .map_err(Error::Io)?;
    if actual == length {
        Ok(())
    } else {
        Err(Error::Truncated {
            context,
            expected: length,
            actual,
        })
    }
}

pub(in crate::analysis::pcap) fn copy_bytes_fallibly(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Io(io::ErrorKind::OutOfMemory.into()))?;
    copy.extend_from_slice(bytes);
    Ok(copy)
}

pub(in crate::analysis::pcap) fn usize_to_u32_limit(value: usize) -> Result<u32, Error> {
    u32::try_from(value).map_err(|_| Error::SizeLimitExceeded {
        kind: "capture size",
        declared: value as u64,
        limit: u32::MAX as usize,
    })
}

pub(in crate::analysis::pcap) fn align_to_usize(value: usize) -> Result<usize, Error> {
    value
        .checked_add(3)
        .map(|padded| padded & !3)
        .ok_or(Error::InvalidData {
            format: Format::PcapNg,
            reason: "aligned length overflow",
        })
}

pub(in crate::analysis::pcap) fn align_to_u32(value: u32) -> Result<u32, Error> {
    value
        .checked_add(3)
        .map(|padded| padded & !3)
        .ok_or(Error::InvalidBlockLength { length: value })
}

pub(in crate::analysis::pcap) fn write_padding<W: Write>(
    writer: &mut W,
    unpadded_length: u32,
) -> Result<(), Error> {
    let padding = (4 - (unpadded_length % 4)) % 4;
    writer.write_all(&[0_u8; 3][..padding as usize])?;
    Ok(())
}

pub(in crate::analysis::pcap) fn decode_u16(
    endianness: Endianness,
    bytes: &[u8],
) -> Result<u16, Error> {
    let word = decode_array::<2>(bytes, "two-byte field")?;
    Ok(match endianness {
        Endianness::Little => u16::from_le_bytes(word),
        Endianness::Big => u16::from_be_bytes(word),
    })
}

pub(in crate::analysis::pcap) fn decode_u32(
    endianness: Endianness,
    bytes: &[u8],
) -> Result<u32, Error> {
    let word = decode_array::<4>(bytes, "four-byte field")?;
    Ok(match endianness {
        Endianness::Little => u32::from_le_bytes(word),
        Endianness::Big => u32::from_be_bytes(word),
    })
}

pub(in crate::analysis::pcap) fn decode_i64(
    endianness: Endianness,
    bytes: &[u8],
) -> Result<i64, Error> {
    let word = decode_array::<8>(bytes, "eight-byte field")?;
    Ok(match endianness {
        Endianness::Little => i64::from_le_bytes(word),
        Endianness::Big => i64::from_be_bytes(word),
    })
}

fn decode_array<const LENGTH: usize>(
    bytes: &[u8],
    context: &'static str,
) -> Result<[u8; LENGTH], Error> {
    Ok(bytes
        .get(..LENGTH)
        .ok_or(Error::Truncated {
            context,
            expected: LENGTH,
            actual: bytes.len(),
        })?
        .try_into()
        .expect("length-checked byte slice"))
}

pub(in crate::analysis::pcap) fn write_u16<W: Write>(
    writer: &mut W,
    endianness: Endianness,
    value: u16,
) -> Result<(), Error> {
    let bytes = match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    };
    writer.write_all(&bytes)?;
    Ok(())
}

pub(in crate::analysis::pcap) fn write_u32<W: Write>(
    writer: &mut W,
    endianness: Endianness,
    value: u32,
) -> Result<(), Error> {
    let bytes = match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    };
    writer.write_all(&bytes)?;
    Ok(())
}

pub(in crate::analysis::pcap) fn write_i64<W: Write>(
    writer: &mut W,
    endianness: Endianness,
    value: i64,
) -> Result<(), Error> {
    let bytes = match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    };
    writer.write_all(&bytes)?;
    Ok(())
}
