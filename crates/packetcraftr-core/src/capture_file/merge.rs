// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::pcapng::validate_rewritable_packet_flags;
use super::reader::DECLARED_FCS;
use super::wire::PCAPNG_OPTION_COMMENT;
use super::{
    Budget, CaptureHeader, Endianness, Error, Format, Interface, Limits, MetadataBlockKind,
    PcapNgOption, Reader, RecordKind, Writer,
};
use crate::frame::Frame;
use serde::Serialize;
use std::{
    collections::HashMap,
    io::{Read, Write},
    time::SystemTime,
};

pub struct MergeSource<R> {
    pub name: String,
    pub reader: Reader<R>,
}
pub const MAX_MERGE_SOURCES: usize = 64;
pub(super) const MAX_SOURCE_NAME_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeLimits {
    pub streams: Limits,
    pub max_sources: usize,
    /// Interfaces declared across every source; zero accepts only sources that declare none.
    pub max_interfaces: usize,
}
impl Default for MergeLimits {
    fn default() -> Self {
        Self {
            streams: Limits::default(),
            max_sources: MAX_MERGE_SOURCES,
            max_interfaces: super::DEFAULT_MAX_TOTAL_INTERFACES,
        }
    }
}
impl MergeLimits {
    pub fn validate(&self) -> Result<(), Error> {
        self.streams.validate()?;
        if !(1..=MAX_MERGE_SOURCES).contains(&self.max_sources) {
            return Err(Error::MergeSources {
                maximum: MAX_MERGE_SOURCES,
            });
        }
        Ok(())
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
    time: SystemTime,
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

/// Merges complete inputs into PCAPNG; ties retain source argument order and physical frame order.
pub fn merge<R: Read, W: Write>(
    sources: &mut [MergeSource<R>],
    output: &mut Writer<W>,
    limits: MergeLimits,
) -> Result<MergeReport, Error> {
    limits.validate()?;
    let mut budget = Budget::new(limits.streams)?;
    if sources.is_empty()
        || sources.len() > limits.max_sources
        || sources
            .iter()
            .any(|source| source.name.len() > MAX_SOURCE_NAME_BYTES)
    {
        return Err(Error::MergeSources {
            maximum: limits.max_sources,
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
        if source.reader.declares_fcs() {
            return Err(Error::MergeMetadata {
                input: index,
                field: DECLARED_FCS,
            });
        }
        let endianness = match source.reader.header() {
            CaptureHeader::Pcap(header) => header.endianness,
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
    let mut pending = Vec::with_capacity(sources.len());
    for index in 0..sources.len() {
        pending.push(advance(
            index,
            &mut sources[index],
            &mut states[index],
            &mut interface_count,
            &mut report,
            &mut budget,
            limits,
        )?);
    }
    let mut mappings = HashMap::new();
    while let Some((index, mut current)) = take_earliest(&mut pending) {
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
            let provenance = serde_json::json!({
                "schema": "packetcraftr.capture-source/v1", "source": mapping.source,
                "source_name": mapping.source_name, "section": mapping.section,
                "local_interface": mapping.local_interface, "global_interface": mapping.global_interface,
            })
            .to_string();
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
        pending[index] = advance(
            index,
            &mut sources[index],
            &mut states[index],
            &mut interface_count,
            &mut report,
            &mut budget,
            limits,
        )?;
    }
    output.flush()?;
    Ok(report)
}

fn take_earliest(pending: &mut [Option<Pending>]) -> Option<(usize, Pending)> {
    let (_, index) = pending
        .iter()
        .enumerate()
        .filter_map(|(index, slot)| slot.as_ref().map(|pending| (pending.time, index)))
        .min()?;
    pending[index].take().map(|pending| (index, pending))
}

fn advance<R: Read>(
    index: usize,
    source: &mut MergeSource<R>,
    state: &mut State,
    interfaces: &mut usize,
    report: &mut MergeReport,
    budget: &mut Budget,
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
                    MetadataBlockKind::InterfaceDescription { .. }
                        if source.reader.declares_fcs() =>
                    {
                        return Err(Error::MergeMetadata {
                            input: index,
                            field: DECLARED_FCS,
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
        budget.charge(frame.captured_length())?;
        (report.frames, report.captured_bytes) = (budget.frames(), budget.captured_bytes());
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
            time,
            description,
            section,
            local,
            global,
        }));
    }
}
