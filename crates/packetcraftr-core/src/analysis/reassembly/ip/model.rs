// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::scope::ScopeId;
use crate::error::{Classification, Classified, Kind};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Ipv4DatagramKey {
    pub scope: ScopeId,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub identification: u16,
    pub protocol: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Ipv6DatagramKey {
    pub scope: ScopeId,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub identification: u32,
}

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Fragment {
    pub key: Ipv4DatagramKey,
    /// Offset in eight-byte units, exactly as encoded on the wire.
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub header: Bytes,
    pub payload: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Fragment {
    pub key: Ipv6DatagramKey,
    /// Offset in eight-byte units, exactly as encoded on the wire.
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub next_header: u8,
    pub unfragmentable_prefix: Bytes,
    /// Byte in `unfragmentable_prefix` whose Next Header pointed at the removed Fragment header.
    pub predecessor_next_header_offset: usize,
    pub payload: Bytes,
}

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapPolicy {
    #[default]
    Reject,
    First,
    Last,
}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FragmentOutcome {
    pub key: DatagramKey,
    pub disposition: FragmentDisposition,
    pub fragment_count: usize,
    pub unique_bytes: usize,
    pub known_final_length: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedDatagram {
    pub key: DatagramKey,
    pub bytes: Bytes,
    pub fragment_count: usize,
    pub unique_bytes: usize,
    pub final_payload_length: usize,
    pub duplicate_fragments: usize,
    pub overlap_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    Accepted(FragmentOutcome),
    Completed {
        fragment: FragmentOutcome,
        datagram: CompletedDatagram,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteReason {
    IdleExpired,
    EndOfCapture,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IncompleteDatagram {
    pub key: DatagramKey,
    pub reason: IncompleteReason,
    pub fragment_count: usize,
    pub unique_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetiredDatagrams {
    pub outcomes: Vec<IncompleteDatagram>,
    pub omitted_ipv4: u64,
    pub omitted_ipv6: u64,
}

/// Resource failures, all detected before mutating retained datagram state.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Resource {
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

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Malformed {
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
    #[error("IP fragments mix CE with Not-ECT congestion markings")]
    InconsistentEcn,
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

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Resource(#[from] Resource),
    #[error(transparent)]
    Malformed(#[from] Malformed),
    /// Contradictory retained state; an internal defect, not malformed capture input.
    #[error("IP reassembly state is inconsistent: {reason}")]
    Inconsistent { reason: &'static str },
}

const RESOURCE_REMEDIATION: &str = "trim or pre-filter the capture, or deliberately raise the \
                                    relevant finite --max-ip-* analysis budget";

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
            Self::Inconsistent { .. } => Classification::new(
                "internal.ip_reassembly",
                Kind::Internal,
                Some("report the capture and command as an internal IP reassembly failure"),
            ),
        }
    }
}

impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        })
    }
}
impl std::fmt::Display for IncompleteReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::IdleExpired => "idle-expired",
            Self::EndOfCapture => "end-of-capture",
        })
    }
}
impl std::fmt::Display for DatagramKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4(key) => write!(
                f,
                "ipv4 scope {} {} -> {} identification {} protocol {}",
                key.scope.get(),
                key.source,
                key.destination,
                key.identification,
                key.protocol
            ),
            Self::Ipv6(key) => write!(
                f,
                "ipv6 scope {} {} -> {} identification {}",
                key.scope.get(),
                key.source,
                key.destination,
                key.identification
            ),
        }
    }
}
