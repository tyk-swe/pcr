const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;
const PCAPNG_SECTION_HEADER: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];
const PCAPNG_BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;
const PCAPNG_SECTION_HEADER_BLOCK: u32 = 0x0a0d_0d0a;
const PCAPNG_INTERFACE_DESCRIPTION_BLOCK: u32 = 0x0000_0001;
const PCAPNG_PACKET_BLOCK: u32 = 0x0000_0002;
const PCAPNG_SIMPLE_PACKET_BLOCK: u32 = 0x0000_0003;
const PCAPNG_ENHANCED_PACKET_BLOCK: u32 = 0x0000_0006;
const PCAPNG_OPTION_END: u16 = 0;
const PCAPNG_OPTION_EPB_FLAGS: u16 = 2;
const PCAPNG_OPTION_IF_TSRESOL: u16 = 9;
const PCAPNG_OPTION_IF_TSOFFSET: u16 = 14;
const DEFAULT_TIMESTAMP_RESOLUTION: TimestampResolution = TimestampResolution::Decimal(6);
const WRITER_TIMESTAMP_RESOLUTION: TimestampResolution = TimestampResolution::Decimal(9);
fn validate_timestamp_resolution(resolution: TimestampResolution) -> Result<(), Error> {
    match resolution {
        TimestampResolution::Decimal(exponent) if exponent <= 0x7f => Ok(()),
        TimestampResolution::Binary(exponent) if exponent <= 0x7f => Ok(()),
        TimestampResolution::Decimal(exponent) => {
            Err(Error::InvalidTimestampResolution { base: 10, exponent })
        }
        TimestampResolution::Binary(exponent) => {
            Err(Error::InvalidTimestampResolution { base: 2, exponent })
        }
    }
}

fn validate_frame_lengths(frame: &Frame, max_size: usize) -> Result<(), Error> {
    if frame.bytes.len() != frame.captured_length as usize {
        return Err(Error::CapturedLengthMismatch {
            declared: frame.captured_length,
            actual: frame.bytes.len(),
        });
    }
    validate_declared_lengths(
        frame.captured_length,
        frame.original_length,
        max_size,
        "captured packet",
    )
}

fn validate_declared_lengths(
    captured_length: u32,
    original_length: u32,
    max_size: usize,
    kind: &'static str,
) -> Result<(), Error> {
    if original_length < captured_length {
        return Err(Error::OriginalLengthTooSmall {
            captured: captured_length,
            original: original_length,
        });
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

fn timestamp_from_ticks(
    ticks: u64,
    resolution: TimestampResolution,
    offset_seconds: i64,
) -> Result<SystemTime, Error> {
    let ticks_per_second = match resolution {
        TimestampResolution::Decimal(exponent) => 10_u128.checked_pow(u32::from(exponent)),
        TimestampResolution::Binary(exponent) => 1_u128.checked_shl(u32::from(exponent)),
    };
    let (whole_seconds, nanoseconds) = match ticks_per_second {
        Some(exact_ticks_per_second) => {
            let wide_ticks = u128::from(ticks);
            let whole_seconds = wide_ticks / exact_ticks_per_second;
            let remainder = wide_ticks % exact_ticks_per_second;
            let scaled = remainder
                .checked_mul(1_000_000_000)
                .expect("u64 ticks multiplied by one billion fit in u128");
            if !scaled.is_multiple_of(exact_ticks_per_second) {
                return Err(Error::MetadataNotRepresentable {
                    format: Format::PcapNg,
                    field: "sub-nanosecond timestamp",
                });
            }
            let nanoseconds = scaled / exact_ticks_per_second;
            (whole_seconds, nanoseconds as u32)
        }
        None => {
            // Any denominator too large for u128 is also much larger than a
            // u64 timestamp. Only zero ticks are exactly representable.
            if ticks != 0 {
                return Err(Error::MetadataNotRepresentable {
                    format: Format::PcapNg,
                    field: "sub-nanosecond timestamp",
                });
            }
            (0, 0)
        }
    };
    let unix_seconds = i128::try_from(whole_seconds)
        .ok()
        .and_then(|seconds| seconds.checked_add(i128::from(offset_seconds)))
        .ok_or(Error::TimestampOutOfRange {
            format: Format::PcapNg,
        })?;
    system_time_from_signed_unix(unix_seconds, nanoseconds)
}

fn timestamp_to_ticks(
    timestamp: SystemTime,
    resolution: TimestampResolution,
    offset_seconds: i64,
) -> Result<u64, Error> {
    let (unix_seconds, nanoseconds) = match timestamp.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (i128::from(elapsed.as_secs()), elapsed.subsec_nanos()),
        Err(error) => {
            let elapsed = error.duration();
            if elapsed.subsec_nanos() == 0 {
                (-i128::from(elapsed.as_secs()), 0)
            } else {
                (
                    -i128::from(elapsed.as_secs()) - 1,
                    1_000_000_000 - elapsed.subsec_nanos(),
                )
            }
        }
    };
    let relative_seconds =
        unix_seconds
            .checked_sub(i128::from(offset_seconds))
            .ok_or(Error::TimestampOutOfRange {
                format: Format::PcapNg,
            })?;
    if relative_seconds < 0 {
        return Err(Error::TimestampOutOfRange {
            format: Format::PcapNg,
        });
    }
    // Zero ticks are representable independently of the resolution's
    // denominator. This also keeps writing symmetric with
    // `timestamp_from_ticks`, which accepts zero for decimal exponents whose
    // denominator is too large for u128.
    if relative_seconds == 0 && nanoseconds == 0 {
        return Ok(0);
    }
    let ticks_per_second = match resolution {
        TimestampResolution::Decimal(exponent) => 10_u128.checked_pow(u32::from(exponent)),
        TimestampResolution::Binary(exponent) => 1_u128.checked_shl(u32::from(exponent)),
    }
    .ok_or(Error::TimestampOutOfRange {
        format: Format::PcapNg,
    })?;
    let whole_seconds =
        u128::try_from(relative_seconds).map_err(|_| Error::TimestampOutOfRange {
            format: Format::PcapNg,
        })?;
    let fractional_numerator = u128::from(nanoseconds)
        .checked_mul(ticks_per_second)
        .ok_or(Error::TimestampOutOfRange {
            format: Format::PcapNg,
        })?;
    if !fractional_numerator.is_multiple_of(1_000_000_000) {
        return Err(Error::MetadataNotRepresentable {
            format: Format::PcapNg,
            field: "timestamp resolution",
        });
    }
    let fractional = fractional_numerator / 1_000_000_000;
    let ticks = whole_seconds
        .checked_mul(ticks_per_second)
        .and_then(|whole_ticks| whole_ticks.checked_add(fractional))
        .ok_or(Error::TimestampOutOfRange {
            format: Format::PcapNg,
        })?;
    u64::try_from(ticks).map_err(|_| Error::TimestampOutOfRange {
        format: Format::PcapNg,
    })
}

fn system_time_from_signed_unix(seconds: i128, nanoseconds: u32) -> Result<SystemTime, Error> {
    let out_of_range = || Error::TimestampOutOfRange {
        format: Format::PcapNg,
    };
    if seconds >= 0 {
        let seconds_since_epoch = u64::try_from(seconds).map_err(|_| out_of_range())?;
        UNIX_EPOCH
            .checked_add(Duration::new(seconds_since_epoch, nanoseconds))
            .ok_or_else(out_of_range)
    } else if nanoseconds == 0 {
        let magnitude = seconds
            .checked_neg()
            .and_then(|magnitude| u64::try_from(magnitude).ok())
            .ok_or_else(out_of_range)?;
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(magnitude))
            .ok_or_else(out_of_range)
    } else {
        let whole_seconds = seconds
            .checked_neg()
            .and_then(|magnitude| magnitude.checked_sub(1))
            .and_then(|magnitude| u64::try_from(magnitude).ok())
            .ok_or_else(out_of_range)?;
        UNIX_EPOCH
            .checked_sub(Duration::new(whole_seconds, 1_000_000_000 - nanoseconds))
            .ok_or_else(out_of_range)
    }
}

fn read_exact_or_eof<R: Read>(
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

fn read_exact_counted<R: Read>(
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

fn usize_to_u32_limit(value: usize) -> Result<u32, Error> {
    u32::try_from(value).map_err(|_| Error::SizeLimitExceeded {
        kind: "capture size",
        declared: value as u64,
        limit: u32::MAX as usize,
    })
}

fn align_to_usize(value: usize) -> Result<usize, Error> {
    value
        .checked_add(3)
        .map(|padded| padded & !3)
        .ok_or(Error::InvalidData {
            format: Format::PcapNg,
            reason: "aligned length overflow",
        })
}

fn align_to_u32(value: u32) -> Result<u32, Error> {
    value
        .checked_add(3)
        .map(|padded| padded & !3)
        .ok_or(Error::InvalidBlockLength { length: value })
}

fn write_padding<W: Write>(writer: &mut W, unpadded_length: u32) -> Result<(), Error> {
    let padding = (4 - (unpadded_length % 4)) % 4;
    writer.write_all(&[0_u8; 3][..padding as usize])?;
    Ok(())
}

fn decode_u16(endianness: Endianness, bytes: &[u8]) -> u16 {
    let word: [u8; 2] = bytes[..2].try_into().expect("two-byte slice");
    match endianness {
        Endianness::Little => u16::from_le_bytes(word),
        Endianness::Big => u16::from_be_bytes(word),
    }
}

fn decode_u32(endianness: Endianness, bytes: &[u8]) -> u32 {
    let word: [u8; 4] = bytes[..4].try_into().expect("four-byte slice");
    match endianness {
        Endianness::Little => u32::from_le_bytes(word),
        Endianness::Big => u32::from_be_bytes(word),
    }
}

fn decode_i64(endianness: Endianness, bytes: &[u8]) -> i64 {
    let word: [u8; 8] = bytes[..8].try_into().expect("eight-byte slice");
    match endianness {
        Endianness::Little => i64::from_le_bytes(word),
        Endianness::Big => i64::from_be_bytes(word),
    }
}

fn write_u16<W: Write>(writer: &mut W, endianness: Endianness, value: u16) -> Result<(), Error> {
    let bytes = match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    };
    writer.write_all(&bytes)?;
    Ok(())
}

fn write_u32<W: Write>(writer: &mut W, endianness: Endianness, value: u32) -> Result<(), Error> {
    let bytes = match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    };
    writer.write_all(&bytes)?;
    Ok(())
}

fn write_i64<W: Write>(writer: &mut W, endianness: Endianness, value: i64) -> Result<(), Error> {
    let bytes = match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    };
    writer.write_all(&bytes)?;
    Ok(())
}
