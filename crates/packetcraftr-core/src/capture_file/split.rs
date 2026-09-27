// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Faithful bounded splitting of a seekable capture into contiguous
//! physical-frame parts.
//!
//! [`plan`] consumes a rewound source once and returns a validated [`Plan`];
//! [`write`] replays it to a caller [`Sink`] as one same-format capture per
//! part. Every part carries one contiguous frame range and every source
//! metadata record, so a part's decoded bytes equal [`super::select`] applied
//! to that range. Planning hashes the source's raw header and records with
//! SHA-256 and writing rehashes them, so a source that changed between passes
//! is rejected before a successful report is returned.

use std::io::{Read, Seek};

use bytes::Bytes;
use sha2::{Digest, Sha256};

use super::{
    Budget, Error as CaptureError, Format, Limits as StreamLimits, MetadataBlockKind, Reader,
    RecordKind,
};
use crate::error::{BoundaryError, Classification, Classified, Coordinate, Kind};

/// Largest accepted `max_files`/`max_metadata_records` ceilings: the bounded
/// size of a plan's part descriptors and retained metadata cache.
const MAX_SPLIT_FILES: usize = 4_096;
const MAX_SPLIT_METADATA_RECORDS: usize = 4_096;
const MAX_SPLIT_METADATA_BYTES: usize = 64 * 1024 * 1024;
/// Per-entry bookkeeping charged against `max_metadata_bytes`.
const METADATA_ENTRY_OVERHEAD: u64 = 128;

/// Options for one split: the positive per-part frame boundary and its bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// Maximum physical frames one part holds, within `1..=u64::MAX`.
    pub frames_per_file: u64,
    pub limits: Limits,
}

/// Resource ceilings for one split.
///
/// The metadata ceilings are cumulative over the retained cache — the initial
/// header plus every non-packet record, charged its raw length plus 128 bytes
/// of bookkeeping per entry — so they still bound a source whose metadata
/// becomes adjacent when packets are removed. `input` is charged once per
/// source pass, never multiplied by the number of passes or parts.
/// `max_output_bytes` bounds the exact sum of decoded part lengths; bounding
/// encoded files is the caller's own accounting below any compressor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Physical frame and captured-payload ceilings applied to each pass.
    pub input: StreamLimits,
    /// Most parts produced, within `1..=4096`; a metadata-only part counts.
    pub max_files: usize,
    /// Most retained metadata records, within `1..=4096`, counting the header.
    pub max_metadata_records: usize,
    /// Most retained metadata bytes, within `1..=67108864`, charging each
    /// entry its raw length plus 128 bytes of bookkeeping.
    pub max_metadata_bytes: usize,
    /// Most decoded container bytes across every part, within `1..=u64::MAX`.
    pub max_output_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            input: StreamLimits::default(),
            max_files: 256,
            max_metadata_records: MAX_SPLIT_METADATA_RECORDS,
            max_metadata_bytes: 16 * 1024 * 1024,
            max_output_bytes: 256 * 1024 * 1024,
        }
    }
}

impl Limits {
    /// Rejects any field outside its valid range before the source is used.
    pub fn validate(&self) -> Result<(), Error> {
        self.input.validate()?;
        for (field, value, maximum) in [
            ("max_files", self.max_files, MAX_SPLIT_FILES),
            (
                "max_metadata_records",
                self.max_metadata_records,
                MAX_SPLIT_METADATA_RECORDS,
            ),
            (
                "max_metadata_bytes",
                self.max_metadata_bytes,
                MAX_SPLIT_METADATA_BYTES,
            ),
        ] {
            if value == 0 {
                return Err(Error::InvalidOption {
                    field,
                    value: 0,
                    reason: "must be non-zero",
                });
            }
            if value > maximum {
                return Err(Error::InvalidOption {
                    field,
                    value: u64_of(value),
                    reason: "exceeds the supported maximum",
                });
            }
        }
        if self.max_output_bytes == 0 {
            return Err(Error::InvalidOption {
                field: "max_output_bytes",
                value: 0,
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// One contiguous physical-frame range and its byte accounting.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Part {
    /// One-based part index in source order.
    pub index: u64,
    /// First source frame in the part; [`None`] only for an empty source's
    /// single metadata-only part.
    pub first_frame: Option<u64>,
    /// Last source frame in the part, inclusive; [`None`] like `first_frame`.
    pub last_frame: Option<u64>,
    /// Physical frames in the range.
    pub frames: u64,
    /// Captured payload bytes of the range.
    pub captured_bytes: u64,
    /// Decoded container bytes the part occupies: header, metadata, packets.
    pub decoded_bytes: u64,
}

/// Source totals and the ordered part list one split produces.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Report {
    /// Detected container format shared by the source and every part.
    pub format: Format,
    /// Requested positive frame boundary.
    pub frames_per_file: u64,
    /// Physical source packets.
    pub frames_read: u64,
    /// Source captured payload bytes.
    pub captured_bytes_read: u64,
    /// Initial header plus retained non-packet records.
    pub metadata_records: u64,
    /// Raw header/metadata bytes, excluding in-memory bookkeeping charges.
    pub metadata_bytes: u64,
    /// Sum of complete decoded part lengths.
    pub decoded_bytes_written: u64,
    /// Ordered part descriptions, one contiguous range each.
    pub parts: Vec<Part>,
}

/// A validated split: the immutable report plus the bounded state [`write`]
/// needs to replay source metadata without rescanning the input per part.
#[derive(Debug)]
pub struct Plan {
    report: Report,
    limits: Limits,
    /// Emitted initial header: verbatim except a PCAPNG section length, which
    /// becomes unknown exactly as [`super::select`] emits it.
    header: Bytes,
    metadata: Vec<RetainedMetadata>,
    /// SHA-256 over the source's raw header and every raw record in order.
    digest: [u8; 32],
}

impl Plan {
    /// The immutable result of planning, including every part's range.
    pub fn report(&self) -> &Report {
        &self.report
    }
}

/// One cached non-packet record and the number of physical packet records
/// that preceded it in the source.
#[derive(Debug)]
struct RetainedMetadata {
    after_frame: u64,
    /// Emitted bytes: verbatim except PCAPNG section headers, patched exactly
    /// once like the initial header.
    bytes: Bytes,
}

/// Receives each generated part as an ordered decoded byte stream.
///
/// Every successfully generated part produces exactly one `begin`, ordered
/// `write` calls, and one `finish`. The first failed callback aborts the
/// split; a failed sink receives no later callbacks, and the caller owns any
/// staged-output cleanup.
pub trait Sink {
    /// Starts part `index` (one-based) in container `format`.
    fn begin(&mut self, index: u64, format: Format) -> Result<(), BoundaryError>;
    /// Appends the next chunk of the part's decoded container bytes.
    fn write(&mut self, bytes: &[u8]) -> Result<(), BoundaryError>;
    /// Seals the part after all of its bytes were written.
    fn finish(&mut self, part: &Part) -> Result<(), BoundaryError>;
}

/// A split planning or writing failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An option or ceiling is outside its valid range.
    #[error("invalid capture split option {field}={value}: {reason}")]
    InvalidOption {
        field: &'static str,
        value: u64,
        reason: &'static str,
    },
    /// A finite split bound was exceeded.
    #[error("capture split {bound} of {attempted} exceeds the configured limit of {limit}")]
    LimitExceeded {
        bound: &'static str,
        attempted: u64,
        limit: u64,
    },
    /// The source capture changed between the planning and writing passes.
    #[error("capture source changed between planning and writing: {detail}")]
    SourceChanged { detail: &'static str },
    /// A sink callback refused the part stream.
    #[error("capture split sink failed")]
    Sink {
        #[source]
        source: BoundaryError,
    },
    /// The underlying capture pass failed; the original error is retained.
    #[error("{source}")]
    Capture {
        #[source]
        source: CaptureError,
    },
}

impl From<CaptureError> for Error {
    fn from(source: CaptureError) -> Self {
        Self::Capture { source }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidOption { .. } => Classification::new(
                "cli.capture_split",
                Kind::Usage,
                Some("use split options within their documented ranges"),
            ),
            Self::LimitExceeded { .. } => Classification::new(
                "policy.capture_split_limit",
                Kind::Policy,
                Some(
                    "reduce the split input or raise its finite file, metadata, and output ceilings",
                ),
            ),
            Self::SourceChanged { .. } => Classification::new(
                "packet.capture_split_source_changed",
                Kind::Packet,
                Some("plan and write must read one unchanged source capture"),
            ),
            Self::Sink { source } => source.classification(),
            Self::Capture { source } => source.classification(),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Sink { source } => source.context(),
            Self::Capture { source } => source.context(),
            _ => None,
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Sink { source } => source.as_causes(),
            Self::Capture { source } => source.causes(),
            error => crate::error::source_chain(error),
        }
    }
}

/// Plans a split from `reader`, consumed once from its initial header to EOF.
///
/// `reader` is rewound first, so it may already be positioned anywhere.
/// Options are validated before any source consumption. The plan keeps the
/// part descriptors, the patched initial header, and the bounded metadata
/// cache — never packet record bytes.
pub fn plan<R: Read + Seek>(reader: &mut Reader<R>, options: Options) -> Result<Plan, Error> {
    options.limits.validate()?;
    if options.frames_per_file == 0 {
        return Err(Error::InvalidOption {
            field: "frames_per_file",
            value: 0,
            reason: "must be non-zero",
        });
    }
    let limits = options.limits;
    reader.rewind()?;
    let format = reader.format();

    let mut hasher = Sha256::new();
    hasher.update(reader.header().raw());

    // The initial header is the first retained metadata entry: it is charged
    // and bounded exactly like every later non-packet record.
    let mut metadata_records = 0_u64;
    let mut metadata_charge = 0_u64;
    charge_metadata(
        &mut metadata_records,
        &mut metadata_charge,
        reader.header().raw().len(),
        limits,
    )?;
    let header = emitted_record(reader.header().raw(), format == Format::PcapNg)?;
    let mut metadata_bytes = u64_of(reader.header().raw().len());

    let mut budget = Budget::new(limits.input)?;
    let mut packet_record_bytes = 0_u64;
    // Per-part (packet-record bytes, captured payload bytes) buckets. A new
    // bucket starts at every frame count divisible by the boundary, so the
    // bucket count is the part count and is bounded by `max_files`.
    let mut part_bytes: Vec<[u64; 2]> = Vec::new();
    let mut metadata = Vec::new();
    while let Some(record) = reader.next_record()? {
        hasher.update(record.raw_bytes());
        let raw_len = u64_of(record.raw_bytes().len());
        if let Some(frame) = record.frame.as_ref() {
            budget.charge(frame.captured_length())?;
            if (budget.frames() - 1).is_multiple_of(options.frames_per_file) {
                if part_bytes.len() >= limits.max_files {
                    return Err(Error::LimitExceeded {
                        bound: "max_files",
                        attempted: u64_of(part_bytes.len() + 1),
                        limit: u64_of(limits.max_files),
                    });
                }
                part_bytes
                    .try_reserve(1)
                    .map_err(|_| allocation_failed("split part descriptors"))?;
                part_bytes.push([0, 0]);
            }
            let part = part_bytes.last_mut().expect("one bucket per frame");
            part[0] = bounded_add(
                part[0],
                raw_len,
                "max_output_bytes",
                limits.max_output_bytes,
            )?;
            part[1] = bounded_add(
                part[1],
                u64::from(frame.captured_length()),
                "max_bytes",
                limits.input.max_bytes,
            )?;
            packet_record_bytes = bounded_add(
                packet_record_bytes,
                raw_len,
                "max_output_bytes",
                limits.max_output_bytes,
            )?;
        } else {
            charge_metadata(
                &mut metadata_records,
                &mut metadata_charge,
                record.raw_bytes().len(),
                limits,
            )?;
            let section = matches!(
                record.kind,
                RecordKind::Metadata(MetadataBlockKind::Section(_))
            );
            metadata
                .try_reserve(1)
                .map_err(|_| allocation_failed("split metadata records"))?;
            metadata.push(RetainedMetadata {
                after_frame: budget.frames(),
                bytes: emitted_record(record.raw_bytes(), section)?,
            });
            metadata_bytes = bounded_add(
                metadata_bytes,
                raw_len,
                "max_metadata_bytes",
                u64_of(limits.max_metadata_bytes),
            )?;
        }
    }

    let frames = budget.frames();
    let captured_bytes = budget.captured_bytes();
    let boundary = options.frames_per_file;
    let parts_count = if frames == 0 {
        1
    } else {
        (frames / boundary)
            .checked_add(u64::from(frames % boundary != 0))
            .ok_or(Error::LimitExceeded {
                bound: "max_files",
                attempted: u64::MAX,
                limit: u64_of(limits.max_files),
            })?
    };
    if parts_count > u64_of(limits.max_files) {
        return Err(Error::LimitExceeded {
            bound: "max_files",
            attempted: parts_count,
            limit: u64_of(limits.max_files),
        });
    }
    // Exact decoded output: every part repeats the header and the complete
    // metadata set; patching never changes a record's length.
    let per_part_overhead = metadata_bytes;
    let decoded_total =
        packet_record_bytes
            .checked_add(parts_count.checked_mul(per_part_overhead).ok_or(
                Error::LimitExceeded {
                    bound: "max_output_bytes",
                    attempted: u64::MAX,
                    limit: limits.max_output_bytes,
                },
            )?)
            .ok_or(Error::LimitExceeded {
                bound: "max_output_bytes",
                attempted: u64::MAX,
                limit: limits.max_output_bytes,
            })?;
    if decoded_total > limits.max_output_bytes {
        return Err(Error::LimitExceeded {
            bound: "max_output_bytes",
            attempted: decoded_total,
            limit: limits.max_output_bytes,
        });
    }

    let mut parts = Vec::new();
    parts
        .try_reserve(usize::try_from(parts_count).unwrap_or(usize::MAX))
        .map_err(|_| allocation_failed("split part descriptors"))?;
    if frames == 0 {
        parts.push(Part {
            index: 1,
            first_frame: None,
            last_frame: None,
            frames: 0,
            captured_bytes: 0,
            decoded_bytes: per_part_overhead,
        });
    } else {
        for (index, bytes) in part_bytes.iter().enumerate() {
            let index = u64_of(index);
            // Bucket `index` exists because frame `index * boundary + 1` was
            // seen, so the product stays below the total frame count.
            let first = index * boundary + 1;
            let last = index.saturating_add(1).saturating_mul(boundary).min(frames);
            parts.push(Part {
                index: index + 1,
                first_frame: Some(first),
                last_frame: Some(last),
                frames: last - first + 1,
                captured_bytes: bytes[1],
                decoded_bytes: per_part_overhead + bytes[0],
            });
        }
    }

    let report = Report {
        format,
        frames_per_file: boundary,
        frames_read: frames,
        captured_bytes_read: captured_bytes,
        metadata_records,
        metadata_bytes,
        decoded_bytes_written: decoded_total,
        parts,
    };
    Ok(Plan {
        report,
        limits,
        header,
        metadata,
        digest: hasher.finalize().into(),
    })
}

/// Replays a [`Plan`] against the same, unchanged, capture.
///
/// The reader is rewound once and its packet records are consumed once in
/// source order; the ordered cache controls metadata replay. Every raw source
/// record, including metadata skipped on this pass, is rehashed and compared
/// with the planned digest before the report is returned: a changed
/// header/count/record fails instead of publishing a stale result.
pub fn write<R: Read + Seek>(
    reader: &mut Reader<R>,
    plan: Plan,
    sink: &mut impl Sink,
) -> Result<Report, Error> {
    let Plan {
        report,
        limits,
        header,
        metadata,
        digest,
    } = plan;
    reader.rewind()?;
    let mut hasher = Sha256::new();
    hasher.update(reader.header().raw());
    let mut budget = Budget::new(limits.input)?;
    let mut frames_seen = 0_u64;
    let mut decoded_written = 0_u64;

    for part in &report.parts {
        reader.check_interrupted()?;
        sink.begin(part.index, report.format)
            .map_err(|source| Error::Sink { source })?;
        reader.check_interrupted()?;

        let part_start_decoded = decoded_written;
        let part_start_frames = frames_seen;
        emit(reader, sink, &header, &mut decoded_written, limits)?;

        let first = part.first_frame.unwrap_or(1);
        let last = part.last_frame.unwrap_or(0);
        // Anchors are nondecreasing, so one ordered pass emits the records
        // anchored before the range, per selected frame, and the remainder —
        // the same positions `select` would give them.
        let prefix = metadata.partition_point(|entry| entry.after_frame < first);
        let middle_end = metadata
            .partition_point(|entry| entry.after_frame < last)
            .max(prefix);
        let mut middle = prefix;
        for entry in &metadata[..prefix] {
            emit(reader, sink, &entry.bytes, &mut decoded_written, limits)?;
        }
        while frames_seen < last {
            let Some(record) = reader.next_record()? else {
                return Err(Error::SourceChanged {
                    detail: "frame count",
                });
            };
            hasher.update(record.raw_bytes());
            let Some(frame) = record.frame.as_ref() else {
                continue;
            };
            budget.charge(frame.captured_length())?;
            frames_seen += 1;
            emit(
                reader,
                sink,
                record.raw_bytes(),
                &mut decoded_written,
                limits,
            )?;
            if frames_seen < last {
                while middle < middle_end && metadata[middle].after_frame <= frames_seen {
                    emit(
                        reader,
                        sink,
                        &metadata[middle].bytes,
                        &mut decoded_written,
                        limits,
                    )?;
                    middle += 1;
                }
            }
        }
        for entry in &metadata[middle..] {
            emit(reader, sink, &entry.bytes, &mut decoded_written, limits)?;
        }

        if frames_seen - part_start_frames != part.frames
            || decoded_written - part_start_decoded != part.decoded_bytes
        {
            return Err(Error::SourceChanged {
                detail: "planned part shape",
            });
        }
        reader.check_interrupted()?;
        sink.finish(part).map_err(|source| Error::Sink { source })?;
        reader.check_interrupted()?;
    }

    // Metadata after the final packet, and EOF itself, are still read and
    // digest-checked before the run can succeed.
    while let Some(record) = reader.next_record()? {
        hasher.update(record.raw_bytes());
        if let Some(frame) = record.frame.as_ref() {
            budget.charge(frame.captured_length())?;
            frames_seen += 1;
        }
    }
    if frames_seen != report.frames_read {
        return Err(Error::SourceChanged {
            detail: "frame count",
        });
    }
    let rehashed: [u8; 32] = hasher.finalize().into();
    if rehashed != digest {
        return Err(Error::SourceChanged {
            detail: "record digest",
        });
    }
    if decoded_written != report.decoded_bytes_written {
        return Err(Error::SourceChanged {
            detail: "decoded output",
        });
    }
    Ok(report)
}

/// Charges the next retained cache entry — the initial header or one
/// non-packet record — before it is kept.
fn charge_metadata(
    records: &mut u64,
    charged: &mut u64,
    raw_len: usize,
    limits: Limits,
) -> Result<(), Error> {
    let next_records = records.checked_add(1).ok_or(Error::LimitExceeded {
        bound: "max_metadata_records",
        attempted: u64::MAX,
        limit: u64_of(limits.max_metadata_records),
    })?;
    if next_records > u64_of(limits.max_metadata_records) {
        return Err(Error::LimitExceeded {
            bound: "max_metadata_records",
            attempted: next_records,
            limit: u64_of(limits.max_metadata_records),
        });
    }
    let entry = u64_of(raw_len).saturating_add(METADATA_ENTRY_OVERHEAD);
    *charged = bounded_add(
        *charged,
        entry,
        "max_metadata_bytes",
        u64_of(limits.max_metadata_bytes),
    )?;
    *records = next_records;
    Ok(())
}

/// The bytes a part carries for one retained record: identical to the source
/// except a PCAPNG section header, whose section length becomes unknown
/// exactly as `select` emits it.
fn emitted_record(raw: &[u8], section: bool) -> Result<Bytes, Error> {
    if !section {
        return Ok(Bytes::copy_from_slice(raw));
    }
    let mut emitted = Vec::new();
    emitted
        .try_reserve_exact(raw.len())
        .map_err(|_| allocation_failed("pcapng selected section"))?;
    super::pcapng::write_selected_section(&mut emitted, raw)?;
    Ok(Bytes::from(emitted))
}

/// One sink write, charged against the decoded-output ceiling before the
/// bytes reach the sink and bracketed by interruption checks so a cached
/// metadata replay cannot run unchecked.
fn emit<R: Read + Seek>(
    reader: &Reader<R>,
    sink: &mut impl Sink,
    bytes: &[u8],
    decoded_written: &mut u64,
    limits: Limits,
) -> Result<(), Error> {
    reader.check_interrupted()?;
    *decoded_written = bounded_add(
        *decoded_written,
        u64_of(bytes.len()),
        "max_output_bytes",
        limits.max_output_bytes,
    )?;
    sink.write(bytes).map_err(|source| Error::Sink { source })?;
    reader.check_interrupted()?;
    Ok(())
}

/// Checked accumulation against a named ceiling; overflow and excess both
/// report the bound rather than concealing it.
fn bounded_add(
    current: u64,
    additional: u64,
    bound: &'static str,
    limit: u64,
) -> Result<u64, Error> {
    let total = current
        .checked_add(additional)
        .ok_or(Error::LimitExceeded {
            bound,
            attempted: u64::MAX,
            limit,
        })?;
    if total > limit {
        return Err(Error::LimitExceeded {
            bound,
            attempted: total,
            limit,
        });
    }
    Ok(total)
}

fn u64_of(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn allocation_failed(kind: &'static str) -> Error {
    CaptureError::AllocationFailed { kind, requested: 0 }.into()
}
