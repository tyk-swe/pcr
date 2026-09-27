// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;

use thiserror::Error;

use super::model::Format;
use crate::error::{BoundaryError, Classification, Classified, Coordinate, Kind};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("capture operation exceeded its duration budget: {actual:?} > {limit:?}")]
    DurationLimit {
        actual: std::time::Duration,
        limit: std::time::Duration,
    },
    #[error(transparent)]
    Cancelled(#[from] crate::budget::Cancelled),
    #[error("failed to allocate {requested} bytes for {kind}")]
    AllocationFailed {
        kind: &'static str,
        requested: usize,
    },
    #[error(transparent)]
    Frame(#[from] crate::frame::Error),
    #[error("capture I/O failed")]
    Io(#[from] io::Error),
    #[error("capture input is empty")]
    EmptyInput,
    #[error("unrecognized capture magic {magic:02x?}")]
    UnrecognizedFormat { magic: [u8; 4] },
    #[error("truncated {context}: expected {expected} bytes, found {actual}")]
    Truncated {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("unsupported {format} version {major}.{minor}")]
    UnsupportedVersion {
        format: Format,
        major: u16,
        minor: u16,
    },
    #[error("invalid {format} data: {reason}")]
    InvalidData {
        format: Format,
        reason: &'static str,
    },
    #[error("{kind} declares {declared} bytes, exceeding the configured limit of {limit}")]
    SizeLimitExceeded {
        kind: &'static str,
        declared: u64,
        limit: usize,
    },
    #[error("pcapng block has invalid length {length}")]
    InvalidBlockLength { length: u32 },
    #[error("pcapng block length footer {trailing} does not match header {leading}")]
    BlockLengthMismatch { leading: u32, trailing: u32 },
    #[error(
        "pcapng block of {block_length} bytes crosses the section boundary with {remaining} bytes remaining"
    )]
    BlockCrossesSectionBoundary { block_length: u32, remaining: u64 },
    #[error("pcapng section ended with {remaining} declared bytes remaining")]
    SectionEndedEarly { remaining: u64 },
    #[error("new pcapng section begins with {remaining} declared bytes remaining")]
    SectionHeaderBeforeBoundary { remaining: u64 },
    #[error("pcapng section has {remaining} bytes remaining, fewer than a complete block header")]
    SectionRemainderTooSmall { remaining: u64 },
    #[error("timestamp cannot be represented in {format}")]
    TimestampOutOfRange { format: Format },
    #[error("{format:?} output requires a timestamp, but this frame has none")]
    TimestampUnavailable { format: Format },
    #[error("timestamp fraction {fraction} is invalid for a denominator of {denominator}")]
    InvalidTimestampFraction { fraction: u32, denominator: u32 },
    #[error("link type {link_type} cannot be represented in a capture interface header")]
    LinkTypeOutOfRange { link_type: u32 },
    #[error("interface {interface} is not defined (the section has {available} interfaces)")]
    UndefinedInterface { interface: u32, available: usize },
    #[error("pcapng section exceeds the configured interface limit of {limit}")]
    InterfaceLimit { limit: usize },
    #[error("pcapng stream exceeds the configured retained-interface limit of {limit}")]
    TotalInterfaceLimit { limit: usize },
    #[error("pcapng stream exceeded {limit} metadata blocks before the next packet")]
    MetadataBlockLimit { limit: usize },
    #[error("pcapng stream exceeded {limit} metadata bytes before the next packet")]
    MetadataByteLimit { limit: usize },
    #[error("frame link type {actual} does not match interface {interface} link type {expected}")]
    InterfaceLinkTypeMismatch {
        interface: u32,
        expected: u32,
        actual: u32,
    },
    #[error("more than one pcapng interface uses link type {link_type}; select one explicitly")]
    AmbiguousInterface { link_type: u32 },
    #[error("{field} metadata cannot be represented in {format}")]
    MetadataNotRepresentable { format: Format, field: &'static str },
    #[error("this operation requires {expected}, but the writer is configured for {actual}")]
    WrongWriterFormat { expected: Format, actual: Format },
    #[error("capture stream frame count {actual} exceeds the configured limit of {limit}")]
    FrameLimitExceeded { actual: u64, limit: u64 },
    #[error("capture stream payload bytes {actual} exceed the configured limit of {limit}")]
    StreamByteLimitExceeded { actual: u64, limit: u64 },
    /// A stream ceiling that would refuse every frame.
    #[error("invalid capture stream limit {field}={value}: must be non-zero")]
    InvalidLimit { field: &'static str, value: u64 },
    #[error("capture timestamp resolution {base}^{exponent} cannot be represented")]
    InvalidTimestampResolution { base: u8, exponent: u8 },
    /// A [`select`](super::select) predicate failed on frame `number`.
    #[error("selection failed at frame {number}")]
    Predicate {
        number: u64,
        #[source]
        source: BoundaryError,
    },
    /// A [`map_frames`](super::map_frames) mapper failed on frame `number`.
    #[error("capture frame {number} transformation failed")]
    Transform {
        number: u64,
        #[source]
        source: BoundaryError,
    },
    #[error("capture transformation cannot retain {0}")]
    TransformMetadata(&'static str),
    #[error("capture transformation changed frame {number} identity or time")]
    TransformIdentity { number: u64 },
    #[error("capture merge requires 1..={maximum} sources with names of at most 4096 bytes")]
    MergeSources { maximum: usize },
    /// Reading merge input `input` failed at its frame `frame`.
    #[error("merge source {input}, frame {frame} failed")]
    MergeSource {
        input: usize,
        frame: u64,
        #[source]
        source: Box<Self>,
    },
    #[error("merge source {input}, frame {frame} has a timestamp before its preceding frame")]
    MergeClockRegression { input: usize, frame: u64 },
    #[error("merge source {input} has unsupported metadata: {field}")]
    MergeMetadata { input: usize, field: &'static str },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::DurationLimit { .. } => Classification::new(
                "policy.duration_limit",
                Kind::Policy,
                Some("reduce input or raise the finite invocation duration"),
            ),
            Self::Cancelled(source) => source.classification(),
            Self::Predicate { source, .. } | Self::Transform { source, .. } => {
                source.classification()
            }
            Self::MergeSource { source, .. } => source.classification(),
            Self::TransformMetadata(_) => {
                Classification::new("packet.capture_transform_metadata", Kind::Packet, None)
            }
            Self::TransformIdentity { .. } => {
                Classification::new("internal.capture_transform_identity", Kind::Internal, None)
            }
            Self::MergeSources { .. } => Classification::new(
                "cli.capture_merge_sources",
                Kind::Usage,
                Some("select a bounded set of named capture sources"),
            ),
            Self::MergeClockRegression { .. } => Classification::new(
                "packet.capture_merge_order",
                Kind::Packet,
                Some("each merge input must already be ordered by timestamp"),
            ),
            Self::MergeMetadata { .. } => Classification::new(
                "packet.capture_merge_metadata",
                Kind::Packet,
                Some(
                    "use faithful source-record export for metadata the normalized merge cannot preserve",
                ),
            ),
            Self::Io(source)
                if source
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<super::compression::Error>())
                    .is_some() =>
            {
                source
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<super::compression::Error>())
                    .expect("guarded compression error")
                    .classification()
            }
            Self::Io(_) => Classification::new(
                "io.capture_file",
                Kind::Io,
                Some(
                    "inspect the capture input/output stream and retry from a known record boundary",
                ),
            ),
            Self::InvalidLimit { .. } => Classification::new(
                "cli.capture_limit",
                Kind::Usage,
                Some("use finite non-zero capture frame and byte limits"),
            ),
            Self::InvalidTimestampResolution { .. } => Classification::new(
                "cli.capture_option",
                Kind::Usage,
                Some("use a supported finite capture timestamp or replay timing option"),
            ),
            Self::WrongWriterFormat { .. } => Classification::new(
                "cli.capture_option",
                Kind::Usage,
                Some("call the writer method that matches the writer's configured format"),
            ),
            Self::TimestampUnavailable { .. } => Classification::new(
                "packet.timestamp_unavailable",
                Kind::Packet,
                Some("use a timestamped frame with generated capture writers"),
            ),
            Self::SizeLimitExceeded { .. }
            | Self::InterfaceLimit { .. }
            | Self::TotalInterfaceLimit { .. }
            | Self::MetadataBlockLimit { .. }
            | Self::MetadataByteLimit { .. }
            | Self::FrameLimitExceeded { .. }
            | Self::StreamByteLimitExceeded { .. } => Classification::new(
                "policy.capture_stream_limit",
                Kind::Policy,
                Some(
                    "reduce the capture stream or deliberately raise its finite frame/byte budget",
                ),
            ),
            _ => Classification::new(
                "packet.capture_file",
                Kind::Packet,
                Some("repair the malformed or unrepresentable capture record before processing it"),
            ),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Predicate { number, .. } => Some(Coordinate::SourceFrame(*number)),
            Self::MergeSource { source, .. } => source.context(),
            _ => None,
        }
    }

    /// A caller's [`BoundaryError`] carries a captured `causes` snapshot that
    /// its own source chain no longer holds, so it leads the causes itself.
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Predicate { source, .. } | Self::Transform { source, .. } => source.as_causes(),
            error => crate::error::source_chain(error),
        }
    }
}

crate::budget::deadline_error_conversions!(Error);
