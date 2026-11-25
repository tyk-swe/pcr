// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ops::Range;

use bytes::Bytes;
use thiserror::Error;

use crate::analysis::{ScopedFlowKey, provenance::SourceSet};
use crate::error::{Classification, Classified};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub flow: ScopedFlowKey,
    pub sequence: u32,
    pub payload: Bytes,
    pub sources: Option<SourceSet>,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictionReason {
    Idle,
    Budget,
    Reuse,
    Reset,
    Flush,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataSources {
    Empty,
    Single(SourceSet),
    /// Contiguous byte lengths paired with the physical-frame provenance for each span.
    Spans(Vec<(usize, SourceSet)>),
}

impl DataSources {
    pub fn slices(&self, bytes: &Bytes) -> Vec<(Bytes, Option<SourceSet>)> {
        match self {
            Self::Empty => vec![(bytes.clone(), None)],
            Self::Single(sources) => vec![(bytes.clone(), Some(sources.clone()))],
            Self::Spans(spans) => {
                let mut start = 0_usize;
                let mut output = Vec::with_capacity(spans.len());
                for (length, sources) in spans {
                    let end = start.saturating_add(*length).min(bytes.len());
                    if end > start {
                        output.push((bytes.slice(start..end), Some(sources.clone())));
                    }
                    start = end;
                }
                if start < bytes.len() {
                    output.push((bytes.slice(start..), None));
                }
                output
            }
        }
    }

    pub fn sets(&self) -> Vec<&SourceSet> {
        match self {
            Self::Empty => Vec::new(),
            Self::Single(sources) => vec![sources],
            Self::Spans(spans) => spans.iter().map(|(_, sources)| sources).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Data {
        flow: ScopedFlowKey,
        sequence: u32,
        bytes: Bytes,
        sources: DataSources,
    },
    Retransmission {
        flow: ScopedFlowKey,
        sequence: u32,
        bytes: usize,
        conflicting: bool,
        /// Wire-sequence spans repeating held data, in stream order; each `end` may wrap at 2^32.
        ranges: Vec<Range<u32>>,
    },
    Gap {
        flow: ScopedFlowKey,
        expected_sequence: u32,
        next_sequence: u32,
    },
    Closed {
        flow: ScopedFlowKey,
        reset: bool,
    },
    Evicted {
        flow: ScopedFlowKey,
        pending_bytes: usize,
        reason: EvictionReason,
    },
}

/// Resource failures, all detected before mutating retained flow state.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Resource {
    #[error("TCP flow table reached flow limit {limit}")]
    FlowLimit { limit: usize },
    #[error("TCP flow reached pending segment limit {limit}")]
    SegmentLimit { limit: usize },
    #[error("TCP flow exceeds per-flow byte/window limit {limit}")]
    FlowByteLimit { limit: usize },
    #[error("TCP flow table would exceed aggregate byte limit {limit}")]
    AggregateByteLimit { limit: usize },
    #[error("could not allocate {requested} bytes for TCP reassembly")]
    AllocationFailed { requested: usize },
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Malformed {
    #[error(
        "TCP FIN sequence {new_offset} conflicts with established final offset {existing_offset}"
    )]
    ConflictingFinalSequence {
        existing_offset: u64,
        new_offset: u64,
    },
    #[error("TCP data extends beyond established final offset {final_offset}")]
    BeyondFinalSequence { final_offset: u64 },
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Resource(#[from] Resource),
    #[error(transparent)]
    Malformed(#[from] Malformed),
}

const RESOURCE_REMEDIATION: &str = "trim or pre-filter the capture, or deliberately raise the \
                                    relevant finite --max-tcp-* analysis budget";

impl Classified for Resource {
    fn classification(&self) -> Classification {
        crate::analysis::error::resource_limit(RESOURCE_REMEDIATION)
    }
}

impl Classified for Malformed {
    fn classification(&self) -> Classification {
        crate::analysis::error::malformed_reassembly()
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Resource(source) => source.classification(),
            Self::Malformed(source) => source.classification(),
        }
    }
}
