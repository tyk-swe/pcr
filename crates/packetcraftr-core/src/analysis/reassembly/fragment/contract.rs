// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DatagramKey {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub identification: u32,
    pub next_header: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment {
    pub key: DatagramKey,
    /// Byte offset in the reassembled payload.
    pub offset: u32,
    pub more_fragments: bool,
    pub bytes: Bytes,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OverlapPolicy {
    #[default]
    RejectConflicting,
    KeepFirst,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub key: DatagramKey,
    pub bytes: Bytes,
    pub fragment_count: usize,
    pub had_conflicting_overlap: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Complete(Datagram),
    Expired {
        key: DatagramKey,
        received_bytes: usize,
        fragment_count: usize,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("zero-length fragments are not accepted for reassembly")]
    EmptyFragment,
    #[error("non-final fragment payload length {length} is not a multiple of eight bytes")]
    UnalignedNonFinalFragment { length: usize },
    #[error("fragment byte offset {offset} is not a multiple of eight")]
    UnalignedFragmentOffset { offset: u32 },
    #[error("fragment range overflows its 32-bit offset")]
    OffsetOverflow,
    #[error("fragment datagram exceeds per-flow limit {limit} bytes")]
    FlowByteLimit { limit: usize },
    #[error("fragment table reached flow limit {limit}")]
    FlowLimit { limit: usize },
    #[error("fragment table would exceed aggregate byte limit {limit}")]
    AggregateByteLimit { limit: usize },
    #[error("could not allocate {requested} bytes for fragment reassembly")]
    AllocationFailed { requested: usize },
    #[error("datagram reached fragment limit {limit}")]
    FragmentLimit { limit: usize },
    #[error("conflicting fragment overlap at byte offset {offset}")]
    ConflictingOverlap { offset: u32 },
    #[error(
        "fragment marked final at length {new_length}, conflicting with prior final length {existing_length}"
    )]
    ConflictingFinalLength {
        existing_length: u32,
        new_length: u32,
    },
    #[error("fragment extends beyond declared final datagram length {final_length}")]
    BeyondFinalLength { final_length: u32 },
}
