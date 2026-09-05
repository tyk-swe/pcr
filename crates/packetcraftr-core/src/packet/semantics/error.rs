// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv6Addr;

use crate::layer::Id;

/// Why a packet's route interpretation is ambiguous or refused.
///
/// Every variant is a reason live transmission is denied, so the enum is the
/// authorization gate's own vocabulary: a new ambiguity gets a variant here,
/// never a prose string assembled at the throw site.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("field {field} on layer {protocol} {reason}")]
    Field {
        protocol: Id,
        field: &'static str,
        reason: &'static str,
    },
    #[error("non-atomic {protocol} fragment may hide a live destination")]
    NonAtomicFragment { protocol: Id },
    #[error("malformed {protocol} layer may hide a live destination: {reason}")]
    MalformedMayHideDestination { protocol: String, reason: String },
    #[error("unknown protocol {protocol} exposes route-bearing field {field}")]
    UnknownProtocolRouteField { protocol: Id, field: &'static str },
    #[error("IP layer index is outside the packet")]
    LayerIndexOutOfRange,
    #[error("an IPv6 extension chain contains more than one SRH")]
    DuplicateSegmentRoutingHeader,
    #[error("IPv6 SRH is not in a contiguous typed extension chain")]
    DetachedSegmentRoutingHeader,
    #[error("SRH requires 1..=127 IPv6 segments")]
    SegmentCount,
    #[error("SRH segment count cannot be represented")]
    SegmentCountUnrepresentable,
    #[error("SRH last_entry {last_entry} does not match segment-list index {expected}")]
    SegmentLastEntry { last_entry: u8, expected: u8 },
    #[error("SRH segments_left {segments_left} exceeds last_entry {last_entry} plus one")]
    SegmentsLeft { segments_left: u8, last_entry: u8 },
    #[error("unsupported SRH flags are non-zero")]
    SegmentFlags,
    #[error("reduced SRH requires an explicit outer IPv6 destination")]
    ReducedSegmentDestination,
    #[error("IPv6 header destination {header} does not match active SRH segment {active}")]
    SegmentDestinationMismatch { header: Ipv6Addr, active: Ipv6Addr },
    #[error("IPv4 option bytes exceed the 40-byte header limit")]
    Ipv4OptionsTooLong,
    #[error("IPv4 option is missing its length byte")]
    Ipv4OptionMissingLength,
    #[error("IPv4 option {option} has invalid length {length}")]
    Ipv4OptionLength { option: u8, length: usize },
    #[error("IPv4 option {option} is truncated")]
    Ipv4OptionTruncated { option: u8 },
    #[error("IPv4 source-route option {option} has invalid length {length}")]
    Ipv4SourceRouteLength { option: u8, length: usize },
    #[error("IPv4 source-route option {option} has invalid pointer {pointer}")]
    Ipv4SourceRoutePointer { option: u8, pointer: usize },
}

impl Error {
    pub(super) fn field(protocol: &Id, field: &'static str, reason: &'static str) -> Self {
        Self::Field {
            protocol: *protocol,
            field,
            reason,
        }
    }
}
