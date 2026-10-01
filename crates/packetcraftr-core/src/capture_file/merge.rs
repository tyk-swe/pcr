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
    cmp::Ordering,
    collections::{BinaryHeap, HashMap},
    io::{Read, Write},
    time::SystemTime,
};

pub struct MergeSource<R> {
    pub name: String,
    pub reader: Reader<R>,
}
pub const MAX_MERGE_SOURCES: usize = 64;
pub(super) const MAX_SOURCE_NAME_BYTES: usize = 4096;
/// Largest per-source look-ahead window accepted for repairing timestamp inversions.
pub const MAX_REORDER_FRAMES: usize = 65_536;

/// How merged frames are sequenced across sources.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MergeOrder {
    /// Interleave by timestamp; each source must already be ordered unless a reorder window is set.
    #[default]
    Chronological,
    /// Write every frame of source 0, then source 1, and so on, keeping timestamps verbatim; the
    /// output may be non-monotonic.
    Append,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergeLimits {
    pub streams: Limits,
    pub max_sources: usize,
    /// Interfaces declared across every source; zero accepts only sources that declare none.
    pub max_interfaces: usize,
    pub order: MergeOrder,
    /// Per-source look-ahead window that repairs small timestamp inversions; zero disables it,
    /// so the first frame older than its predecessor is refused. Only chronological merges use it.
    pub max_reorder_frames: usize,
}
impl Default for MergeLimits {
    fn default() -> Self {
        Self {
            streams: Limits::default(),
            max_sources: MAX_MERGE_SOURCES,
            max_interfaces: super::DEFAULT_MAX_TOTAL_INTERFACES,
            order: MergeOrder::default(),
            max_reorder_frames: 0,
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
        if self.max_reorder_frames > MAX_REORDER_FRAMES {
            return Err(Error::MergeOption(
                "the reorder window exceeds the supported maximum",
            ));
        }
        if self.order == MergeOrder::Append && self.max_reorder_frames > 0 {
            return Err(Error::MergeOption(
                "append order keeps timestamps verbatim and cannot reorder frames",
            ));
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
    /// One-based physical position within its source.
    number: u64,
    time: SystemTime,
    description: Interface,
    section: Option<u64>,
    local: Option<u32>,
    global: u32,
}
/// Orders a source's look-ahead window so the heap pops its earliest frame, oldest position first.
struct Windowed(Pending);
impl PartialEq for Windowed {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Windowed {}
impl PartialOrd for Windowed {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Windowed {
    fn cmp(&self, other: &Self) -> Ordering {
        (other.0.time, other.0.number).cmp(&(self.0.time, self.0.number))
    }
}
struct State {
    /// Timestamp of the last frame this source emitted.
    previous: Option<SystemTime>,
    window: BinaryHeap<Windowed>,
    exhausted: bool,
    interfaces: usize,
    endianness: Endianness,
}

/// Merges complete inputs into PCAPNG. Chronological merges retain source argument order and
/// physical frame order for equal timestamps; append merges write each source whole in argument
/// order.
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
            window: BinaryHeap::new(),
            exhausted: false,
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
    while let Some((index, mut current)) = take_next(&mut pending, limits.order) {
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

fn take_next(pending: &mut [Option<Pending>], order: MergeOrder) -> Option<(usize, Pending)> {
    let index = match order {
        MergeOrder::Chronological => {
            pending
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| slot.as_ref().map(|pending| (pending.time, index)))
                .min()?
                .1
        }
        MergeOrder::Append => pending.iter().position(Option::is_some)?,
    };
    pending[index].take().map(|pending| (index, pending))
}

/// The next frame this source emits: the earliest of its look-ahead window, refilled first.
fn advance<R: Read>(
    index: usize,
    source: &mut MergeSource<R>,
    state: &mut State,
    interfaces: &mut usize,
    report: &mut MergeReport,
    budget: &mut Budget,
    limits: MergeLimits,
) -> Result<Option<Pending>, Error> {
    let window = limits.max_reorder_frames.max(1);
    while !state.exhausted && state.window.len() < window {
        match read_frame(index, source, state, interfaces, report, budget, limits)? {
            Some(frame) => state.window.push(Windowed(frame)),
            None => state.exhausted = true,
        }
    }
    let Some(Windowed(next)) = state.window.pop() else {
        return Ok(None);
    };
    if limits.order == MergeOrder::Chronological
        && state.previous.is_some_and(|previous| next.time < previous)
    {
        return Err(Error::MergeClockRegression {
            input: index,
            frame: next.number,
        });
    }
    state.previous = Some(next.time);
    Ok(Some(next))
}

fn read_frame<R: Read>(
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
            number: next,
            time,
            description,
            section,
            local,
            global,
        }));
    }
}
