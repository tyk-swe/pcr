// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Timestamp-ordered streaming merge with distinct source interface identities.

use super::pcapng::validate_rewritable_packet_flags;
use super::wire::{PCAPNG_OPTION_COMMENT, PCAPNG_OPTION_IF_FCSLEN};
use super::{
    CaptureHeader, Endianness, Error, Format, Interface, Limits, MetadataBlockKind, PcapNgOption,
    Reader, RecordKind, Writer,
};
use crate::frame::Frame;
use serde::Serialize;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    io::{Read, Write},
    time::SystemTime,
};

pub struct MergeSource<R> {
    pub name: String,
    pub reader: Reader<R>,
}
#[derive(Clone, Copy, Debug)]
pub struct MergeLimits {
    pub streams: Limits,
    pub max_sources: usize,
    pub max_interfaces: usize,
}
impl Default for MergeLimits {
    fn default() -> Self {
        Self {
            streams: Limits::default(),
            max_sources: 64,
            max_interfaces: super::DEFAULT_TOTAL_INTERFACE_LIMIT,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct MergedInterface {
    pub source: usize,
    pub source_name: String,
    pub section: Option<u64>,
    pub local_interface: Option<u32>,
    pub global_interface: u32,
    pub output_interface: u32,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct MergeReport {
    pub frames: u64,
    pub captured_bytes: u64,
    pub source_frames: Vec<u64>,
    pub interfaces: Vec<MergedInterface>,
    pub source_metadata_records: u64,
}
struct Pending {
    frame: Frame,
    description: Interface,
    section: Option<u64>,
    local: Option<u32>,
    global: u32,
}
struct State {
    previous: Option<SystemTime>,
    interfaces: usize,
    endianness: Endianness,
}

/// Merges complete inputs into PCAPNG. Ties retain source argument order and
/// physical frame order. Each input must have nondecreasing, present times.
/// Packet bytes/lengths, direction and interface timestamp metadata are retained;
/// source sections, comments, unknown blocks and statistics are normalized away.
/// Semantic metadata this writer cannot preserve (FCS overrides and extended
/// packet flags) is rejected explicitly. Errors may leave partial output.
pub fn merge<R: Read, W: Write>(
    sources: &mut [MergeSource<R>],
    output: &mut Writer<W>,
    limits: MergeLimits,
) -> Result<MergeReport, Error> {
    if limits.max_sources == 0
        || limits.max_sources > 64
        || sources.is_empty()
        || sources.len() > limits.max_sources
        || sources.iter().any(|source| source.name.len() > 4096)
    {
        return Err(Error::MergeSources {
            maximum: limits.max_sources.min(64),
        });
    }
    if output.format() != Format::PcapNg {
        return Err(Error::WrongWriterFormat {
            expected: Format::PcapNg,
            actual: output.format(),
        });
    }
    let mut states = Vec::new();
    let mut interface_count = 0usize;
    for (index, source) in sources.iter().enumerate() {
        let endianness = match source.reader.header() {
            CaptureHeader::Pcap(header) => {
                if header.network & 0xffff0000 != 0 {
                    return Err(Error::MergeMetadata {
                        input: index,
                        field: "classic PCAP extended link/FCS metadata",
                    });
                }
                header.endianness
            }
            CaptureHeader::PcapNg(section) => section.endianness,
        };
        interface_count = interface_count
            .checked_add(source.reader.interfaces().len())
            .ok_or(Error::TotalInterfaceLimit {
                limit: limits.max_interfaces,
            })?;
        states.push(State {
            previous: None,
            interfaces: source.reader.interfaces().len(),
            endianness,
        });
    }
    if interface_count > limits.max_interfaces {
        return Err(Error::TotalInterfaceLimit {
            limit: limits.max_interfaces,
        });
    }
    let mut report = MergeReport {
        source_frames: vec![0; sources.len()],
        ..Default::default()
    };
    let mut pending: Vec<Option<Pending>> = (0..sources.len()).map(|_| None).collect();
    let mut heap = BinaryHeap::new();
    let mut mappings = HashMap::new();
    for index in 0..sources.len() {
        if let Some(frame) = advance(
            index,
            &mut sources[index],
            &mut states[index],
            &mut interface_count,
            &mut report,
            limits,
        )? {
            heap.push(Reverse((
                frame.frame.timestamp.expect("checked timestamp"),
                index,
                report.source_frames[index],
            )));
            pending[index] = Some(frame);
        }
    }
    while let Some(Reverse((_, index, _))) = heap.pop() {
        let mut current = pending[index]
            .take()
            .expect("one heap entry per pending source");
        let key = (index, current.global);
        let id = if let Some(id) = mappings.get(&key) {
            *id
        } else {
            let mapping = MergedInterface {
                source: index,
                source_name: sources[index].name.clone(),
                section: current.section,
                local_interface: current.local,
                global_interface: current.global,
                output_interface: 0,
            };
            let provenance = serde_json::to_vec(&serde_json::json!({
                "schema": "packetcraftr.capture-source/v1", "source": mapping.source,
                "source_name": mapping.source_name, "section": mapping.section,
                "local_interface": mapping.local_interface, "global_interface": mapping.global_interface,
            })).map_err(|_| Error::InvalidData {
                format: Format::PcapNg,
                reason: "interface provenance serialization failed",
            })?;
            let id = output.add_interface_description_with_options(
                current.description,
                &[PcapNgOption {
                    code: PCAPNG_OPTION_COMMENT,
                    value: provenance.into(),
                }],
            )?;
            report.interfaces.push(MergedInterface {
                output_interface: id,
                ..mapping
            });
            mappings.insert(key, id);
            id
        };
        current.frame.interface = Some(id);
        output.write_frame(&current.frame)?;
        if let Some(frame) = advance(
            index,
            &mut sources[index],
            &mut states[index],
            &mut interface_count,
            &mut report,
            limits,
        )? {
            heap.push(Reverse((
                frame.frame.timestamp.expect("checked timestamp"),
                index,
                report.source_frames[index],
            )));
            pending[index] = Some(frame);
        }
    }
    output.flush()?;
    Ok(report)
}

fn advance<R: Read>(
    index: usize,
    source: &mut MergeSource<R>,
    state: &mut State,
    interfaces: &mut usize,
    report: &mut MergeReport,
    limits: MergeLimits,
) -> Result<Option<Pending>, Error> {
    let next = report.source_frames[index]
        .checked_add(1)
        .ok_or(Error::FrameLimitExceeded {
            actual: u64::MAX,
            limit: limits.streams.max_frames,
        })?;
    loop {
        let record = source
            .reader
            .next_record()
            .map_err(|source| Error::MergeSource {
                input: index,
                frame: next,
                source: Box::new(source),
            })?;
        let Some(record) = record else {
            return Ok(None);
        };
        let count = source.reader.interfaces().len();
        *interfaces = interfaces
            .checked_add(count.saturating_sub(state.interfaces))
            .filter(|count| *count <= limits.max_interfaces)
            .ok_or(Error::TotalInterfaceLimit {
                limit: limits.max_interfaces,
            })?;
        state.interfaces = count;
        let (section, local, options) = match record.kind {
            RecordKind::Packet {
                section,
                interface_id,
                options,
                ..
            } => (section, interface_id, options),
            RecordKind::Metadata(metadata) => {
                report.source_metadata_records = report
                    .source_metadata_records
                    .checked_add(1)
                    .ok_or(Error::MetadataBlockLimit { limit: usize::MAX })?;
                match metadata {
                    MetadataBlockKind::Section(section) => state.endianness = section.endianness,
                    MetadataBlockKind::InterfaceDescription { options, .. }
                        if options
                            .iter()
                            .any(|option| option.code == PCAPNG_OPTION_IF_FCSLEN) =>
                    {
                        return Err(Error::MergeMetadata {
                            input: index,
                            field: "interface FCS length",
                        });
                    }
                    _ => {}
                }
                continue;
            }
        };
        validate_rewritable_packet_flags(&options, state.endianness, "packet flags").map_err(
            |field| Error::MergeMetadata {
                input: index,
                field,
            },
        )?;
        let frame = record.frame.ok_or(Error::InvalidData {
            format: source.reader.format(),
            reason: "packet record has no frame",
        })?;
        let time = frame.timestamp.ok_or_else(|| Error::MergeSource {
            input: index,
            frame: next,
            source: Box::new(Error::TimestampUnavailable {
                format: Format::PcapNg,
            }),
        })?;
        if state.previous.is_some_and(|previous| time < previous) {
            return Err(Error::MergeClockRegression {
                input: index,
                frame: next,
            });
        }
        state.previous = Some(time);
        (report.frames, report.captured_bytes) = limits.streams.advance(
            report.frames,
            report.captured_bytes,
            frame.captured_length(),
        )?;
        report.source_frames[index] = next;
        let global = frame.interface.unwrap_or(0);
        let description = source
            .reader
            .interfaces()
            .get(global as usize)
            .ok_or(Error::UndefinedInterface {
                interface: global,
                available: source.reader.interfaces().len(),
            })?
            .clone();
        return Ok(Some(Pending {
            frame,
            description,
            section,
            local,
            global,
        }));
    }
}
