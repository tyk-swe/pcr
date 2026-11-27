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
    cmp::{Ordering, Reverse},
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
    description: Interface,
    section: Option<u64>,
    local: Option<u32>,
    global: u32,
}
/// Orders a source's look-ahead window so the heap pops its earliest frame, oldest position first.
struct Windowed(SystemTime, Pending);
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
        (other.0, other.1.number).cmp(&(self.0, self.1.number))
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
    let mut mappings = HashMap::new();
    if limits.order == MergeOrder::Append {
        for (index, (source, state)) in sources.iter_mut().zip(&mut states).enumerate() {
            while let Some(current) = read_frame(
                index,
                source,
                state,
                &mut interface_count,
                &mut report,
                &mut budget,
                limits,
            )? {
                write_pending(
                    output,
                    &mut mappings,
                    &mut report,
                    index,
                    &source.name,
                    current,
                )?;
            }
        }
    } else {
        let mut pending = Vec::with_capacity(sources.len());
        let mut heads = BinaryHeap::with_capacity(sources.len());
        for (index, (source, state)) in sources.iter_mut().zip(&mut states).enumerate() {
            let next = advance(
                index,
                source,
                state,
                &mut interface_count,
                &mut report,
                &mut budget,
                limits,
            )?;
            if let Some(next) = &next {
                heads.push(Reverse((next.0, index)));
            }
            pending.push(next);
        }
        while let Some(Reverse((_, index))) = heads.pop() {
            let Windowed(_, current) = pending[index].take().expect("heap tracks pending frames");
            let source = &mut sources[index];
            write_pending(
                output,
                &mut mappings,
                &mut report,
                index,
                &source.name,
                current,
            )?;
            let next = advance(
                index,
                source,
                &mut states[index],
                &mut interface_count,
                &mut report,
                &mut budget,
                limits,
            )?;
            if let Some(next) = &next {
                heads.push(Reverse((next.0, index)));
            }
            pending[index] = next;
        }
    }
    output.flush()?;
    Ok(report)
}

fn write_pending<W: Write>(
    output: &mut Writer<W>,
    mappings: &mut HashMap<(usize, u32), u32>,
    report: &mut MergeReport,
    index: usize,
    source_name: &str,
    mut current: Pending,
) -> Result<(), Error> {
    let key = (index, current.global);
    let simple = current.frame.timestamp.is_none();
    let existing = mappings.get(&key).copied();
    let (base, section) = output.pcapng_section()?;
    let full = existing.is_none() && section.len() >= output.section_interface_limit();
    let needs_first_interface = simple && !section.is_empty() && existing != Some(base);
    if full || needs_first_interface {
        output.start_section()?;
        mappings.clear();
    }

    let id = if let Some(id) = mappings.get(&key) {
        *id
    } else {
        let mapping = MergedInterface {
            source: index,
            source_name: source_name.to_owned(),
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
    if simple {
        output.write_simple_frame(&current.frame)
    } else {
        output.write_frame(&current.frame)
    }
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
) -> Result<Option<Windowed>, Error> {
    let window = limits.max_reorder_frames.max(1);
    while !state.exhausted && state.window.len() < window {
        let Some(frame) = read_frame(index, source, state, interfaces, report, budget, limits)?
        else {
            state.exhausted = true;
            break;
        };
        let time = frame.frame.timestamp.ok_or_else(|| Error::MergeSource {
            input: index,
            frame: frame.number,
            source: Box::new(Error::TimestampUnavailable {
                format: Format::PcapNg,
            }),
        })?;
        state.window.push(Windowed(time, frame));
    }
    let Some(next) = state.window.pop() else {
        return Ok(None);
    };
    if state.previous.is_some_and(|previous| next.0 < previous) {
        return Err(Error::MergeClockRegression {
            input: index,
            frame: next.1.number,
        });
    }
    state.previous = Some(next.0);
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
            description,
            section,
            local,
            global,
        }));
    }
}
