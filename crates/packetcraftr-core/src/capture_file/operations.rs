// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Record-preserving, bounded offline capture operations.

use super::{
    Budget, CaptureHeader, Endianness, Error, Format, Limits, MetadataBlockKind, PacketBlockKind,
    Reader, RecordKind, SelectionReport, TimestampResolution,
};
use crate::frame::Frame;
use serde::Serialize;
use std::{
    collections::VecDeque,
    io::{Read, Write},
    str::FromStr,
    time::{Duration, SystemTime},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DedupLimits {
    pub window_frames: usize,
    pub max_retained_bytes: usize,
}
impl Default for DedupLimits {
    fn default() -> Self {
        Self {
            window_frames: 1024,
            max_retained_bytes: 64 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DedupReport {
    pub selection: SelectionReport,
    pub duplicates: u64,
}

/// Compare exact captured bytes, lengths, link type, interface, and direction against
/// the preceding input frames. Timestamps do not affect duplicate identity.
pub fn dedup<R: Read, W: Write>(
    reader: &mut Reader<R>,
    output: W,
    limits: Limits,
    dedup_limits: DedupLimits,
) -> Result<(W, DedupReport), Error> {
    if dedup_limits.window_frames == 0 || dedup_limits.max_retained_bytes == 0 {
        return Err(Error::InvalidLimit {
            field: "dedup_window",
            value: 0,
        });
    }
    let mut recent = VecDeque::<Frame>::new();
    let mut retained = 0_usize;
    let mut duplicates = 0_u64;
    let (output, selection) = super::select(reader, output, limits, |_, frame| {
        let duplicate = recent.iter().any(|previous| {
            previous.link_type == frame.link_type
                && previous.interface == frame.interface
                && previous.direction == frame.direction
                && previous.original_length() == frame.original_length()
                && previous.bytes() == frame.bytes()
        });
        if recent.len() == dedup_limits.window_frames {
            retained -= size_of::<Frame>() + recent.pop_front().expect("full window").bytes().len();
        }
        let next = retained
            .checked_add(size_of::<Frame>())
            .and_then(|bytes| bytes.checked_add(frame.bytes().len()))
            .filter(|n| *n <= dedup_limits.max_retained_bytes)
            .ok_or_else(|| {
                crate::error::BoundaryError::new(
                    "deduplication retained-byte limit exceeded",
                    crate::error::Classification::new(
                        "policy.capture_stream_limit",
                        crate::error::Kind::Policy,
                        None,
                    ),
                    Vec::new(),
                )
            })?;
        recent.try_reserve(1).map_err(|_| {
            crate::error::BoundaryError::from_error(Error::AllocationFailed {
                kind: "deduplication window",
                requested: next,
            })
        })?;
        recent.push_back(frame.clone());
        retained = next;
        if duplicate {
            duplicates += 1;
        }
        Ok(!duplicate)
    })?;
    Ok((
        output,
        DedupReport {
            selection,
            duplicates,
        },
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitSelector {
    Packets(u64),
    Bytes(u64),
    Interval(Duration),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitLimits {
    pub max_files: usize,
}
impl Default for SplitLimits {
    fn default() -> Self {
        Self { max_files: 64 }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SplitReport {
    pub format: Format,
    pub files: usize,
    pub frames: u64,
    pub captured_bytes: u64,
    pub frames_per_file: Vec<u64>,
}

/// Split at packet boundaries, retaining raw packet records and all source metadata.
/// `create` receives a zero-based file index. Each result has its own source header
/// and the current section's interface declarations, making it independently readable.
pub fn split<R: Read, W: Write>(
    reader: &mut Reader<R>,
    limits: Limits,
    selector: SplitSelector,
    split_limits: SplitLimits,
    mut create: impl FnMut(usize) -> std::io::Result<W>,
) -> Result<(Vec<W>, SplitReport), Error> {
    let valid = match selector {
        SplitSelector::Packets(n) | SplitSelector::Bytes(n) => n != 0,
        SplitSelector::Interval(d) => !d.is_zero(),
    };
    if !valid || split_limits.max_files == 0 || split_limits.max_files > 64 {
        return Err(Error::InvalidLimit {
            field: "split_limit",
            value: 0,
        });
    }
    let mut budget = Budget::new(limits)?;
    let mut prefix = vec![reader.header().raw().to_vec()];
    let mut prefix_bytes = prefix[0].len();
    let mut outputs = vec![create(0)?];
    write_prefix(
        outputs.last_mut().expect("initial output"),
        &prefix,
        reader.format(),
    )?;
    let mut report = SplitReport {
        format: reader.format(),
        files: 1,
        frames: 0,
        captured_bytes: 0,
        frames_per_file: vec![0],
    };
    let mut file_bytes = 0_u64;
    let mut origin: Option<SystemTime> = None;
    while let Some(record) = reader.next_record()? {
        if let Some(frame) = &record.frame {
            budget.charge(frame.captured_length())?;
            let count = *report.frames_per_file.last().expect("initial counter");
            let boundary = match selector {
                SplitSelector::Packets(n) => count >= n,
                SplitSelector::Bytes(n) => {
                    count != 0 && file_bytes.saturating_add(u64::from(frame.captured_length())) > n
                }
                SplitSelector::Interval(interval) => {
                    let time = frame.timestamp.ok_or(Error::TimestampUnavailable {
                        format: reader.format(),
                    })?;
                    let first = *origin.get_or_insert(time);
                    count != 0
                        && time
                            .duration_since(first)
                            .is_ok_and(|elapsed| elapsed >= interval)
                }
            };
            if boundary {
                if outputs.len() >= split_limits.max_files {
                    return Err(Error::SizeLimitExceeded {
                        kind: "split files",
                        declared: (outputs.len() + 1) as u64,
                        limit: split_limits.max_files,
                    });
                }
                outputs.last_mut().expect("current output").flush()?;
                let mut output = create(outputs.len())?;
                write_prefix(&mut output, &prefix, reader.format())?;
                outputs.push(output);
                report.frames_per_file.push(0);
                file_bytes = 0;
                origin = frame.timestamp;
            }
            *report.frames_per_file.last_mut().expect("current counter") += 1;
            file_bytes += u64::from(frame.captured_length());
        } else {
            match &record.kind {
                RecordKind::Metadata(MetadataBlockKind::Section(_)) => {
                    prefix.clear();
                    prefix_bytes = record.raw_bytes().len();
                    prefix.push(record.raw_bytes().to_vec());
                }
                RecordKind::Metadata(MetadataBlockKind::InterfaceDescription { .. }) => {
                    prefix_bytes = prefix_bytes
                        .checked_add(record.raw_bytes().len())
                        .filter(|size| *size <= 64 * 1024 * 1024)
                        .ok_or(Error::MetadataByteLimit {
                            limit: 64 * 1024 * 1024,
                        })?;
                    prefix.push(record.raw_bytes().to_vec());
                }
                _ => {}
            }
        }
        let output = outputs.last_mut().expect("current output");
        if matches!(
            record.kind,
            RecordKind::Metadata(MetadataBlockKind::Section(_))
        ) {
            super::pcapng::write_selected_section(output, record.raw_bytes())?;
        } else {
            output.write_all(record.raw_bytes())?;
        }
    }
    for output in &mut outputs {
        output.flush()?;
    }
    report.files = outputs.len();
    report.frames = budget.frames();
    report.captured_bytes = budget.captured_bytes();
    Ok((outputs, report))
}
fn write_prefix(output: &mut impl Write, prefix: &[Vec<u8>], format: Format) -> Result<(), Error> {
    for (index, raw) in prefix.iter().enumerate() {
        if index == 0 && format == Format::PcapNg {
            super::pcapng::write_selected_section(output, raw)?;
        } else {
            output.write_all(raw)?;
        }
    }
    Ok(())
}

/// An exact decimal number of seconds. The rational value is preserved until it
/// is converted into the source interface's timestamp ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeShift {
    numerator: i128,
    denominator: i128,
}
impl FromStr for TimeShift {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self, Error> {
        let invalid = || Error::InvalidData {
            format: Format::PcapNg,
            reason: "timestamp shift must be a bounded signed decimal",
        };
        let (negative, value) = if let Some(v) = value.strip_prefix('-') {
            (true, v)
        } else {
            (false, value.strip_prefix('+').unwrap_or(value))
        };
        let mut parts = value.split('.');
        let whole = parts.next().ok_or_else(invalid)?;
        let fraction = parts.next().unwrap_or("");
        if parts.next().is_some()
            || whole.is_empty()
            || !whole.bytes().all(|b| b.is_ascii_digit())
            || !fraction.bytes().all(|b| b.is_ascii_digit())
            || fraction.len() > 38
        {
            return Err(invalid());
        }
        let denominator = 10_i128
            .checked_pow(fraction.len() as u32)
            .ok_or_else(invalid)?;
        let whole = whole.parse::<i128>().map_err(|_| invalid())?;
        let fractional = if fraction.is_empty() {
            0
        } else {
            fraction.parse::<i128>().map_err(|_| invalid())?
        };
        let numerator = whole
            .checked_mul(denominator)
            .and_then(|n| n.checked_add(fractional))
            .ok_or_else(invalid)?;
        Ok(Self {
            numerator: if negative { -numerator } else { numerator },
            denominator,
        })
    }
}
impl TimeShift {
    fn ticks(self, resolution: TimestampResolution, format: Format) -> Result<i128, Error> {
        if self.numerator == 0 {
            return Ok(0);
        }
        let rate = resolution
            .ticks_per_second()
            .and_then(|n| i128::try_from(n).ok())
            .ok_or(Error::TimestampOutOfRange { format })?;
        // Reduce before multiplication to preserve representable large whole-second shifts.
        let divisor = gcd(rate, self.denominator);
        let denominator = self.denominator / divisor;
        if self.numerator % denominator != 0 {
            return Err(Error::MetadataNotRepresentable {
                format,
                field: "timestamp shift at source precision",
            });
        }
        (self.numerator / denominator)
            .checked_mul(rate / divisor)
            .ok_or(Error::TimestampOutOfRange { format })
    }
}
fn gcd(mut a: i128, mut b: i128) -> i128 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ShiftReport {
    pub format: Format,
    pub frames: u64,
    pub shifted_packets: u64,
    pub shifted_statistics: u64,
    pub captured_bytes: u64,
}

/// Shift raw timestamp fields exactly, preserving unknown records, all options,
/// source precision, and timestamp-less Simple Packet Blocks.
pub fn shift_time<R: Read, W: Write>(
    reader: &mut Reader<R>,
    mut output: W,
    limits: Limits,
    shift: TimeShift,
) -> Result<(W, ShiftReport), Error> {
    let mut budget = Budget::new(limits)?;
    output.write_all(reader.header().raw())?;
    let mut section_base = 0_usize;
    let mut report = ShiftReport {
        format: reader.format(),
        frames: 0,
        shifted_packets: 0,
        shifted_statistics: 0,
        captured_bytes: 0,
    };
    while let Some(record) = reader.next_record()? {
        let endian = reader.endianness();
        let mut raw = record.raw_bytes().to_vec();
        if let Some(frame) = &record.frame {
            budget.charge(frame.captured_length())?;
        }
        match &record.kind {
            RecordKind::Packet {
                block: PacketBlockKind::Classic,
                ..
            } => {
                let CaptureHeader::Pcap(header) = reader.header() else {
                    unreachable!("classic record header")
                };
                let rate = header
                    .timestamp_resolution
                    .ticks_per_second()
                    .expect("classic precision") as u64;
                let current = u64::from(read32(&raw[..4], endian)) * rate
                    + u64::from(read32(&raw[4..8], endian));
                let ticks = shifted(
                    current,
                    shift.ticks(header.timestamp_resolution, Format::Pcap)?,
                    Format::Pcap,
                )?;
                let seconds =
                    u32::try_from(ticks / rate).map_err(|_| Error::TimestampOutOfRange {
                        format: Format::Pcap,
                    })?;
                put32(&mut raw[..4], seconds, endian);
                put32(&mut raw[4..8], (ticks % rate) as u32, endian);
                report.shifted_packets += 1;
            }
            RecordKind::Packet {
                block: PacketBlockKind::Enhanced | PacketBlockKind::Obsolete,
                ..
            } => {
                let interface = record
                    .frame
                    .as_ref()
                    .and_then(|f| f.interface)
                    .expect("pcapng interface") as usize;
                let interface = &reader.interfaces()[interface];
                let amount = shift.ticks(interface.timestamp_resolution, Format::PcapNg)?;
                shift_field(&mut raw[12..20], endian, amount, interface)?;
                report.shifted_packets += 1;
            }
            RecordKind::Metadata(MetadataBlockKind::Section(_)) => {
                section_base = reader.interfaces().len();
            }
            RecordKind::Metadata(MetadataBlockKind::InterfaceStatistics {
                interface_id, ..
            }) => {
                if raw.len() < 24 {
                    return Err(Error::InvalidData {
                        format: Format::PcapNg,
                        reason: "interface statistics block is missing its timestamp",
                    });
                }
                let interface = &reader.interfaces()[section_base + *interface_id as usize];
                let amount = shift.ticks(interface.timestamp_resolution, Format::PcapNg)?;
                shift_field(&mut raw[12..20], endian, amount, interface)?;
                let end = raw.len() - 4;
                let mut offset = 20;
                while offset < end {
                    if offset + 4 > end {
                        return Err(Error::InvalidData {
                            format: Format::PcapNg,
                            reason: "truncated statistics option",
                        });
                    }
                    let code = read16(&raw[offset..offset + 2], endian);
                    let size = usize::from(read16(&raw[offset + 2..offset + 4], endian));
                    offset += 4;
                    if code == 0 {
                        if size != 0 || raw[offset..end].iter().any(|b| *b != 0) {
                            return Err(Error::InvalidData {
                                format: Format::PcapNg,
                                reason: "invalid statistics end option",
                            });
                        }
                        break;
                    }
                    let padded = (size + 3) & !3;
                    if offset + padded > end {
                        return Err(Error::InvalidData {
                            format: Format::PcapNg,
                            reason: "truncated statistics option value",
                        });
                    }
                    if matches!(code, 2 | 3) {
                        if size != 8 {
                            return Err(Error::InvalidData {
                                format: Format::PcapNg,
                                reason: "invalid statistics timestamp option",
                            });
                        }
                        shift_field(&mut raw[offset..offset + 8], endian, amount, interface)?;
                    }
                    offset += padded;
                }
                report.shifted_statistics += 1;
            }
            _ => {}
        }
        output.write_all(&raw)?;
    }
    output.flush()?;
    report.frames = budget.frames();
    report.captured_bytes = budget.captured_bytes();
    Ok((output, report))
}
fn shifted(current: u64, amount: i128, format: Format) -> Result<u64, Error> {
    i128::from(current)
        .checked_add(amount)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(Error::TimestampOutOfRange { format })
}
fn shift_field(
    raw: &mut [u8],
    endian: Endianness,
    amount: i128,
    interface: &super::Interface,
) -> Result<(), Error> {
    let current =
        (u64::from(read32(&raw[..4], endian)) << 32) | u64::from(read32(&raw[4..8], endian));
    let ticks = shifted(current, amount, Format::PcapNg)?;
    super::wire::timestamp_from_ticks(
        ticks,
        interface.timestamp_resolution,
        interface.timestamp_offset,
    )?;
    put32(&mut raw[..4], (ticks >> 32) as u32, endian);
    put32(&mut raw[4..8], ticks as u32, endian);
    Ok(())
}
fn read16(raw: &[u8], endian: Endianness) -> u16 {
    let value = [raw[0], raw[1]];
    match endian {
        Endianness::Little => u16::from_le_bytes(value),
        Endianness::Big => u16::from_be_bytes(value),
    }
}
fn read32(raw: &[u8], endian: Endianness) -> u32 {
    let value = [raw[0], raw[1], raw[2], raw[3]];
    match endian {
        Endianness::Little => u32::from_le_bytes(value),
        Endianness::Big => u32::from_be_bytes(value),
    }
}
fn put32(raw: &mut [u8], value: u32, endian: Endianness) {
    raw.copy_from_slice(&match endian {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{capture_file::Writer, frame::LinkType};
    use std::{io::Cursor, time::UNIX_EPOCH};
    fn capture(format: Format) -> Vec<u8> {
        let mut writer = Writer::new(Vec::new(), format, LinkType::IPV4).unwrap();
        for (index, bytes) in [vec![1; 20], vec![1; 20], vec![2; 20]]
            .into_iter()
            .enumerate()
        {
            writer
                .write_frame(
                    &Frame::new(
                        UNIX_EPOCH + Duration::from_secs(index as u64 + 2),
                        LinkType::IPV4,
                        bytes,
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        writer.into_inner()
    }
    #[test]
    fn duplicates_and_splits_remain_readable() {
        for format in [Format::Pcap, Format::PcapNg] {
            let original = capture(format);
            let (output, report) = dedup(
                &mut Reader::new(Cursor::new(&original)).unwrap(),
                Vec::new(),
                Limits::default(),
                DedupLimits::default(),
            )
            .unwrap();
            assert_eq!(report.duplicates, 1);
            assert_eq!(Reader::new(Cursor::new(output)).unwrap().count(), 2);
            let (outputs, report) = split(
                &mut Reader::new(Cursor::new(original)).unwrap(),
                Limits::default(),
                SplitSelector::Packets(1),
                SplitLimits::default(),
                |_| Ok(Vec::new()),
            )
            .unwrap();
            assert_eq!(report.frames_per_file, vec![1, 1, 1]);
            for output in outputs {
                assert_eq!(Reader::new(Cursor::new(output)).unwrap().count(), 1);
            }
        }
    }
    #[test]
    fn zero_shift_remains_representable_at_extreme_source_resolutions() {
        assert_eq!(
            TimeShift::from_str("0")
                .unwrap()
                .ticks(TimestampResolution::Decimal(127), Format::PcapNg)
                .unwrap(),
            0
        );
        assert_eq!(
            TimeShift::from_str("0")
                .unwrap()
                .ticks(TimestampResolution::Binary(127), Format::PcapNg)
                .unwrap(),
            0
        );
    }

    #[test]
    fn shifts_exact_ticks_and_refuses_rounding_or_underflow() {
        for format in [Format::Pcap, Format::PcapNg] {
            let original = capture(format);
            let (output, report) = shift_time(
                &mut Reader::new(Cursor::new(&original)).unwrap(),
                Vec::new(),
                Limits::default(),
                "-1.000001".parse().unwrap(),
            )
            .unwrap();
            assert_eq!(report.shifted_packets, 3);
            assert_eq!(
                Reader::new(Cursor::new(output))
                    .unwrap()
                    .next_frame()
                    .unwrap()
                    .unwrap()
                    .timestamp,
                Some(UNIX_EPOCH + Duration::new(0, 999_999_000))
            );
            assert!(
                shift_time(
                    &mut Reader::new(Cursor::new(&original)).unwrap(),
                    Vec::new(),
                    Limits::default(),
                    "-3".parse().unwrap()
                )
                .is_err()
            );
        }
        assert!(
            TimeShift::from_str("0.0000001")
                .unwrap()
                .ticks(TimestampResolution::Decimal(6), Format::Pcap)
                .is_err()
        );
        assert_eq!(
            TimeShift::from_str("0.125")
                .unwrap()
                .ticks(TimestampResolution::Binary(3), Format::PcapNg)
                .unwrap(),
            1
        );
    }
}
