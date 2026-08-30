// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Public inputs, outcomes, and errors for IP fragment reassembly.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::scope::ScopeId;

/// Internet Protocol family of a physical fragment or derived datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Ipv4,
    Ipv6,
}

/// Exact IPv4 fragment association key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Ipv4DatagramKey {
    pub scope: ScopeId,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub identification: u16,
    pub protocol: u8,
}

/// Exact IPv6 fragment association key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Ipv6DatagramKey {
    pub scope: ScopeId,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub identification: u32,
}

/// Exact, capture-scoped fragment association key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum DatagramKey {
    Ipv4(Ipv4DatagramKey),
    Ipv6(Ipv6DatagramKey),
}

impl DatagramKey {
    #[must_use]
    pub const fn family(&self) -> Family {
        match self {
            Self::Ipv4(_) => Family::Ipv4,
            Self::Ipv6(_) => Family::Ipv6,
        }
    }
}

/// One decoded non-atomic IPv4 fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Fragment {
    pub key: Ipv4DatagramKey,
    /// Offset in eight-byte units, exactly as encoded on the wire.
    pub fragment_offset: u16,
    pub more_fragments: bool,
    /// Exact IPv4 header bytes for this physical fragment.
    pub header: Bytes,
    /// Exact fragment payload, excluding the IPv4 header and link padding.
    pub payload: Bytes,
}

/// One decoded non-atomic IPv6 fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Fragment {
    pub key: Ipv6DatagramKey,
    /// Offset in eight-byte units, exactly as encoded on the wire.
    pub fragment_offset: u16,
    pub more_fragments: bool,
    /// Next Header carried by the Fragment header.
    pub next_header: u8,
    /// Exact IPv6 base header and extension headers preceding the Fragment
    /// header. The Fragment header itself is excluded.
    pub unfragmentable_prefix: Bytes,
    /// Byte in `unfragmentable_prefix` whose Next Header value points at the
    /// removed Fragment header. This is byte 6 for a bare IPv6 header and byte
    /// 0 of the immediately preceding extension header otherwise.
    pub predecessor_next_header_offset: usize,
    /// Exact fragmentable payload, excluding the Fragment header.
    pub payload: Bytes,
}

/// One decoded non-atomic fragment offered to the reassembler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fragment {
    Ipv4(Ipv4Fragment),
    Ipv6(Ipv6Fragment),
}

impl Fragment {
    #[must_use]
    pub const fn family(&self) -> Family {
        match self {
            Self::Ipv4(_) => Family::Ipv4,
            Self::Ipv6(_) => Family::Ipv6,
        }
    }
}

/// Deterministic policy for conflicting fragment bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapPolicy {
    /// Reject a fragment carrying any byte that differs from retained data.
    #[default]
    Reject,
    /// Preserve the byte received first.
    First,
    /// Replace it with the byte received last.
    Last,
}

/// Classification of the physical fragment just admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum FragmentDisposition {
    Accepted {
        added_bytes: usize,
    },
    Duplicate {
        bytes: usize,
    },
    OverlapResolved {
        policy: OverlapPolicy,
        affected_bytes: usize,
        added_bytes: usize,
    },
}

/// Per-fragment evidence returned after a successful admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FragmentOutcome {
    pub key: DatagramKey,
    pub disposition: FragmentDisposition,
    pub fragment_count: usize,
    pub unique_bytes: usize,
    pub known_final_length: Option<usize>,
}

/// A complete raw IPv4 or IPv6 datagram derived from physical fragments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedDatagram {
    pub key: DatagramKey,
    /// Raw network-layer bytes, beginning with the IPv4 or IPv6 base header.
    pub bytes: Bytes,
    pub fragment_count: usize,
    pub unique_bytes: usize,
    pub final_payload_length: usize,
    pub duplicate_fragments: usize,
    pub overlap_bytes: usize,
}

/// Result of admitting one physical fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    Accepted(FragmentOutcome),
    Completed {
        fragment: FragmentOutcome,
        datagram: CompletedDatagram,
    },
}

/// Why a partial datagram was retired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteReason {
    IdleExpired,
    EndOfCapture,
}

/// Bounded evidence for a datagram that retired with gaps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IncompleteDatagram {
    pub key: DatagramKey,
    pub reason: IncompleteReason,
    pub fragment_count: usize,
    pub unique_bytes: usize,
    pub known_final_length: Option<usize>,
    pub duplicate_fragments: usize,
    pub overlap_bytes: usize,
}

impl IncompleteDatagram {
    #[must_use]
    pub const fn family(&self) -> Family {
        self.key.family()
    }
}

/// Bounded incomplete outcomes from one expiry or end-of-capture sweep.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetiredDatagrams {
    pub outcomes: Vec<IncompleteDatagram>,
    pub omitted_ipv4: u64,
    pub omitted_ipv6: u64,
}

/// Resource failures, all detected before mutating retained datagram state.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResourceError {
    #[error("IP reassembly reached concurrent datagram limit {limit}")]
    DatagramLimit { limit: usize },
    #[error("IP datagram reached physical fragment limit {limit}")]
    FragmentLimit { limit: usize },
    #[error("IP datagram exceeds payload byte limit {limit}")]
    DatagramByteLimit { limit: usize },
    #[error("IP reassembly would exceed aggregate memory limit {limit}")]
    AggregateMemoryLimit { limit: usize },
    #[error("could not allocate {requested} bytes for IP reassembly")]
    AllocationFailed { requested: usize },
    #[error("IP idle expiry {expiry:?} exceeds the platform monotonic-clock range")]
    IdleExpiryRange { expiry: Duration },
}

/// Malformed or mutually inconsistent fragment input.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum MalformedError {
    #[error("IP fragment offset {offset} exceeds the 13-bit wire field")]
    OffsetOutOfRange { offset: u16 },
    #[error("IP fragment offset or length overflows")]
    OffsetOverflow,
    #[error("IP fragment payload is empty")]
    EmptyPayload,
    #[error("atomic IP fragment is not reassembly input")]
    AtomicFragment,
    #[error("non-final IP fragment payload length {length} is not a multiple of eight")]
    UnalignedNonFinal { length: usize },
    #[error("invalid IPv4 fragment header: {reason}")]
    InvalidIpv4Header { reason: &'static str },
    #[error("offset-zero IPv4 fragments have inconsistent headers")]
    InconsistentIpv4Header,
    #[error("invalid IPv6 unfragmentable prefix: {reason}")]
    InvalidIpv6Prefix { reason: &'static str },
    #[error("IPv6 fragments have inconsistent unfragmentable prefixes")]
    InconsistentIpv6Prefix,
    #[error("IPv6 fragment Next Header changed from {expected} to {actual}")]
    InconsistentIpv6NextHeader { expected: u8, actual: u8 },
    #[error("IP final payload length changed from {existing} to {new}")]
    ConflictingFinalLength { existing: usize, new: usize },
    #[error("IP fragment data extends beyond known final payload length {final_length}")]
    BeyondFinalLength { final_length: usize },
    #[error("non-final IP fragment reaches known final payload length {final_length}")]
    NonFinalAtFinalLength { final_length: usize },
    #[error("IP fragment conflicts with {bytes} retained byte(s)")]
    ConflictingOverlap { bytes: usize },
    #[error("reconstructed {family:?} datagram exceeds its 16-bit length field")]
    ReconstructedLength { family: Family },
}

/// Typed IP reassembly failure category.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Resource(#[from] ResourceError),
    #[error(transparent)]
    Malformed(#[from] MalformedError),
}
