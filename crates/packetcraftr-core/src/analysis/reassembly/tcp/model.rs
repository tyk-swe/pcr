// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public types and events for TCP stream reassembly.

use std::net::IpAddr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::scope::ScopeId;

/// Directional four-tuple identifying a TCP flow.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}

impl FlowKey {
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            source: self.destination,
            source_port: self.destination_port,
            destination: self.source,
            destination_port: self.source_port,
        }
    }
}

/// Directional TCP flow qualified by its exact capture scope.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ScopedFlowKey {
    pub scope: ScopeId,
    pub flow: FlowKey,
}

impl ScopedFlowKey {
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            scope: self.scope,
            flow: self.flow.reverse(),
        }
    }
}

/// One TCP segment offered for reassembly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub flow: ScopedFlowKey,
    pub sequence: u32,
    pub payload: Bytes,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
}

/// Events produced by pushing segments or running expiry sweeps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Data {
        flow: ScopedFlowKey,
        sequence: u32,
        bytes: Bytes,
    },
    Retransmission {
        flow: ScopedFlowKey,
        sequence: u32,
        bytes: usize,
        conflicting: bool,
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
    },
}

/// Resource failures, all detected before mutating retained flow state.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResourceError {
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
    #[error("TCP per-flow window {limit} reaches or exceeds the serial-number half-space")]
    InvalidWindowLimit { limit: usize },
}

/// Mutually inconsistent stream input.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum MalformedError {
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

/// Typed TCP reassembly failure category.
///
/// The split mirrors [`ip::Error`](crate::analysis::reassembly::ip::Error)
/// because the operator's answer differs: a resource failure is answered by
/// raising a finite budget, a malformed one only by inspecting the flow. A
/// new variant has to choose a side, so it can never be misfiled by a
/// catch-all at a classification site.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Resource(#[from] ResourceError),
    #[error(transparent)]
    Malformed(#[from] MalformedError),
}
