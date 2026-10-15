// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One-pass capture metadata: what a capture is, before analyzing it.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::SystemTime;

use serde::Serialize;

use super::error::Error;
use super::format::{Endianness, Format, TimestampResolution};
use super::header::{CaptureHeader, PcapNgOption};
use super::limits::{Budget, Limits};
use super::reader::Reader;
use super::record::{MetadataBlockKind, PacketBlockKind, RecordKind};
use crate::frame::LinkType;

/// PCAPNG interface-description options carrying display metadata.
const PCAPNG_OPTION_IF_NAME: u16 = 2;
const PCAPNG_OPTION_IF_DESCRIPTION: u16 = 3;

/// Distinct unknown-block types retained before later types are only counted.
pub const MAX_RETAINED_BLOCK_TYPES: usize = 16;

/// Metadata for one capture interface: the reader's global entry joined with
/// the interface-description block that declared it, when the capture has any.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InterfaceInfo {
    /// Global interface index; the identity frame metadata refers to.
    pub global_id: u32,
    /// PCAPNG section that declared it; `None` for classic PCAP.
    pub section: Option<u64>,
    /// Section-local interface identifier; `None` for classic PCAP.
    pub local_id: Option<u32>,
    pub link_type: LinkType,
    pub snap_len: u32,
    pub timestamp_resolution: TimestampResolution,
    pub timestamp_offset: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Packet-block counts by representation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PacketBlocks {
    pub classic: u64,
    pub enhanced: u64,
    pub simple: u64,
    pub obsolete: u64,
}

impl PacketBlocks {
    /// Total frames across every block representation.
    pub fn total(&self) -> u64 {
        self.classic
            .saturating_add(self.enhanced)
            .saturating_add(self.simple)
            .saturating_add(self.obsolete)
    }
}

/// File-level capture metadata assembled by one bounded pass.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct InfoReport {
    pub format: Format,
    pub endianness: Endianness,
    /// PCAPNG section-header version; `None` for classic PCAP.
    pub pcapng_version: Option<(u16, u16)>,
    /// PCAPNG sections, counting the one the reader consumed at construction.
    pub sections: u64,
    pub frames: u64,
    pub captured_bytes: u64,
    pub original_bytes: u64,
    /// Frames whose captured bytes are shorter than their original wire bytes.
    pub truncated_frames: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_timestamp: Option<SystemTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_timestamp: Option<SystemTime>,
    pub interfaces: Vec<InterfaceInfo>,
    pub packets: PacketBlocks,
    pub name_resolution_blocks: u64,
    pub interface_statistics_blocks: u64,
    pub custom_blocks: u64,
    /// Counts by unknown-block type, up to [`MAX_RETAINED_BLOCK_TYPES`] entries.
    pub unknown_blocks: BTreeMap<u32, u64>,
    /// Distinct unknown-block types beyond the retained list.
    pub unknown_block_types_omitted: u64,
    /// Whether the header or an interface declared a frame check sequence
    /// that frames still carry.
    pub declares_fcs: bool,
}

/// Source coordinates of one PCAPNG interface-description block.
#[derive(Clone, Debug, Default)]
struct InterfaceOrigin {
    section: Option<u64>,
    local_id: Option<u32>,
    name: Option<String>,
    description: Option<String>,
}

/// Reads `reader` to its end, charging every packet record against `limits`,
/// and reports the capture's structure without decoding any packet.
pub fn inspect<R: Read>(reader: &mut Reader<R>, limits: Limits) -> Result<InfoReport, Error> {
    let mut budget = Budget::new(limits)?;
    let mut origins: BTreeMap<u32, InterfaceOrigin> = BTreeMap::new();
    let mut packets = PacketBlocks::default();
    let mut report = InfoReport {
        format: reader.format(),
        endianness: reader.endianness(),
        pcapng_version: None,
        sections: 1,
        frames: 0,
        captured_bytes: 0,
        original_bytes: 0,
        truncated_frames: 0,
        first_timestamp: None,
        last_timestamp: None,
        interfaces: Vec::new(),
        packets,
        name_resolution_blocks: 0,
        interface_statistics_blocks: 0,
        custom_blocks: 0,
        unknown_blocks: BTreeMap::new(),
        unknown_block_types_omitted: 0,
        declares_fcs: reader.declares_fcs(),
    };
    if let CaptureHeader::PcapNg(section) = reader.header() {
        report.pcapng_version = Some((section.major, section.minor));
    }
    while let Some(record) = reader.next_record()? {
        match record.kind {
            RecordKind::Packet { block, .. } => {
                let Some(frame) = record.frame else {
                    continue;
                };
                budget.charge(frame.captured_length())?;
                match block {
                    PacketBlockKind::Classic => packets.classic += 1,
                    PacketBlockKind::Enhanced => packets.enhanced += 1,
                    PacketBlockKind::Simple => packets.simple += 1,
                    PacketBlockKind::Obsolete => packets.obsolete += 1,
                }
                report.frames += 1;
                report.captured_bytes = report
                    .captured_bytes
                    .saturating_add(u64::from(frame.captured_length()));
                report.original_bytes = report
                    .original_bytes
                    .saturating_add(u64::from(frame.original_length()));
                report.truncated_frames += u64::from(frame.is_truncated());
                if let Some(timestamp) = frame.timestamp {
                    report.first_timestamp = Some(
                        report
                            .first_timestamp
                            .map_or(timestamp, |first| first.min(timestamp)),
                    );
                    report.last_timestamp = Some(
                        report
                            .last_timestamp
                            .map_or(timestamp, |last| last.max(timestamp)),
                    );
                }
            }
            RecordKind::Metadata(kind) => match kind {
                MetadataBlockKind::Section(_) => report.sections += 1,
                MetadataBlockKind::InterfaceDescription {
                    section,
                    local_id,
                    global_id,
                    options,
                    ..
                } => {
                    let origin = origins.entry(global_id).or_default();
                    origin.section = Some(section);
                    origin.local_id = Some(local_id);
                    let (name, description) = interface_display(&options);
                    origin.name = origin.name.take().or(name);
                    origin.description = origin.description.take().or(description);
                }
                MetadataBlockKind::NameResolution { .. } => {
                    report.name_resolution_blocks += 1;
                }
                MetadataBlockKind::InterfaceStatistics { .. } => {
                    report.interface_statistics_blocks += 1;
                }
                MetadataBlockKind::Custom { .. } => {
                    report.custom_blocks += 1;
                }
                MetadataBlockKind::Unknown { block_type, .. } => {
                    if report.unknown_blocks.len() < MAX_RETAINED_BLOCK_TYPES
                        || report.unknown_blocks.contains_key(&block_type)
                    {
                        *report.unknown_blocks.entry(block_type).or_default() += 1;
                    } else {
                        report.unknown_block_types_omitted += 1;
                    }
                }
            },
        }
    }
    report.packets = packets;
    let pcapng = report.format == Format::PcapNg;
    report.interfaces = reader
        .interfaces()
        .iter()
        .enumerate()
        .map(|(index, interface)| {
            let origin = origins.get(&(u32::try_from(index).unwrap_or(u32::MAX)));
            InterfaceInfo {
                global_id: u32::try_from(index).unwrap_or(u32::MAX),
                section: origin.and_then(|origin| origin.section).filter(|_| pcapng),
                local_id: origin.and_then(|origin| origin.local_id).filter(|_| pcapng),
                link_type: interface.link_type,
                snap_len: interface.snap_len,
                timestamp_resolution: interface.timestamp_resolution,
                timestamp_offset: interface.timestamp_offset,
                name: origin.and_then(|origin| origin.name.clone()),
                description: origin.and_then(|origin| origin.description.clone()),
            }
        })
        .collect();
    Ok(report)
}

fn interface_display(options: &[PcapNgOption]) -> (Option<String>, Option<String>) {
    let text = |code: u16| {
        options
            .iter()
            .find(|option| option.code == code)
            .map(|option| String::from_utf8_lossy(&option.value).into_owned())
            .filter(|text| !text.is_empty())
    };
    (
        text(PCAPNG_OPTION_IF_NAME),
        text(PCAPNG_OPTION_IF_DESCRIPTION),
    )
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::UNIX_EPOCH;

    use super::super::{Format, Interface, Reader, TimestampResolution, Writer};
    use super::{PacketBlocks, inspect};

    use crate::budget::Cancellation;
    use crate::capture_file::{Error, Limits};
    use crate::frame::{Frame, LinkType};

    fn frame(seconds: u64, bytes: &[u8]) -> Frame {
        Frame::new(
            UNIX_EPOCH + std::time::Duration::from_secs(seconds),
            LinkType::IPV4,
            bytes.to_vec(),
        )
        .expect("fixture frame")
    }

    #[test]
    fn classic_pcap_reports_one_header_interface() {
        let mut bytes = Vec::new();
        let mut writer = Writer::pcap(&mut bytes, LinkType::IPV4).expect("writer");
        writer.write_frame(&frame(1, &[0; 8])).expect("frame");
        writer.write_frame(&frame(3, &[0; 8])).expect("frame");
        writer.flush().expect("flush");
        drop(writer);
        let mut reader = Reader::new(Cursor::new(bytes)).expect("reader");
        let report = inspect(&mut reader, Limits::default()).expect("info");
        assert_eq!(report.format, Format::Pcap);
        assert_eq!(report.sections, 1);
        assert_eq!(report.pcapng_version, None);
        assert_eq!(
            report.packets,
            PacketBlocks {
                classic: 2,
                ..PacketBlocks::default()
            }
        );
        assert_eq!(report.frames, 2);
        assert_eq!(report.captured_bytes, 16);
        assert_eq!(report.interfaces.len(), 1);
        assert_eq!(report.interfaces[0].link_type, LinkType::IPV4);
        assert_eq!(report.interfaces[0].section, None);
        assert_eq!(report.interfaces[0].local_id, None);
        assert_eq!(report.interfaces[0].name, None);
        // The frames are stamped at distinct seconds, so the bounds differ.
        assert_ne!(report.first_timestamp, report.last_timestamp);
    }

    #[test]
    fn pcapng_interfaces_join_their_description_blocks() {
        let mut writer = Writer::pcapng(Vec::new()).expect("writer");
        writer
            .add_interface_description(Interface {
                // Matches the frames this fixture writes, so the writer adds
                // no automatic interface of its own.
                link_type: LinkType::IPV4,
                snap_len: 65_535,
                timestamp_resolution: TimestampResolution::Decimal(6),
                timestamp_offset: 0,
            })
            .expect("interface");
        writer.write_frame(&frame(2, &[0; 4])).expect("frame");
        writer.flush().expect("flush");
        let mut reader = Reader::new(Cursor::new(writer.into_inner())).expect("reader");
        let report = inspect(&mut reader, Limits::default()).expect("info");
        assert_eq!(report.format, Format::PcapNg);
        assert_eq!(report.pcapng_version, Some((1, 0)));
        assert_eq!(
            report.packets,
            PacketBlocks {
                enhanced: 1,
                ..PacketBlocks::default()
            }
        );
        assert_eq!(report.interfaces.len(), 1);
        assert_eq!(report.interfaces[0].section, Some(0));
        assert_eq!(report.interfaces[0].local_id, Some(0));
        assert_eq!(report.interfaces[0].snap_len, 65_535);
    }

    #[test]
    fn frame_ceilings_fail_the_pass_rather_than_truncating_it() {
        let mut bytes = Vec::new();
        let mut writer = Writer::pcap(&mut bytes, LinkType::IPV4).expect("writer");
        writer.write_frame(&frame(1, &[0; 8])).expect("frame");
        writer.write_frame(&frame(2, &[0; 8])).expect("frame");
        drop(writer);
        let mut reader = Reader::new(Cursor::new(bytes)).expect("reader");
        let error = inspect(
            &mut reader,
            Limits {
                max_frames: 1,
                max_bytes: u64::MAX,
            },
        )
        .expect_err("the second frame exceeds the ceiling");
        assert!(matches!(error, Error::FrameLimitExceeded { .. }));
    }

    #[test]
    fn cancelled_reads_never_report_partial_metadata() {
        let mut bytes = Vec::new();
        let mut writer = Writer::pcap(&mut bytes, LinkType::IPV4).expect("writer");
        writer.write_frame(&frame(1, &[0; 8])).expect("frame");
        drop(writer);
        let signal = Cancellation::default();
        let mut reader = Reader::new(Cursor::new(bytes))
            .expect("reader")
            .with_cancellation(signal.clone());
        signal.cancel();
        assert!(inspect(&mut reader, Limits::default()).is_err());
    }
}
