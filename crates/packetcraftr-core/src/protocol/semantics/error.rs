// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv6Addr;

use crate::layer::Id;

/// Why a packet's route interpretation is ambiguous or cannot be determined.
///
/// Each variant describes the packet, not what a caller does about it; a new
/// ambiguity gets a variant here, never a prose string assembled at the throw
/// site.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("field {field} on layer {protocol} {reason}")]
    Field {
        protocol: Id,
        field: &'static str,
        reason: Constraint,
    },
    #[error(
        "destination cannot be determined because the {protocol} layer is a non-atomic fragment"
    )]
    NonAtomicFragment { protocol: Id },
    #[error("destination cannot be determined because the {protocol} layer is malformed: {reason}")]
    MalformedMayHideDestination { protocol: String, reason: String },
    #[error(
        "destination cannot be determined because unknown protocol {protocol} carries route-bearing field {field}"
    )]
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

impl crate::error::Classified for Error {
    fn classification(&self) -> crate::error::Classification {
        crate::error::Classification::new(
            "packet.semantics",
            crate::error::Kind::Packet,
            Some("repair the malformed or ambiguous route-bearing packet fields"),
        )
    }
}

impl Error {
    pub(super) fn field(protocol: &Id, field: &'static str, reason: Constraint) -> Self {
        Self::Field {
            protocol: *protocol,
            field,
            reason,
        }
    }
}

/// The rule a route-bearing field breaks in an [`Error::Field`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Constraint {
    /// An SRH segment list holds at least one address.
    NonEmptySegments,
    /// An SRH segment list holds at most 256 addresses.
    AtMost256Segments,
    /// A derived one-byte field is `Auto`, an exact `u8`, or one raw byte.
    OneByte,
    /// A VLAN priority is within `0..=7`.
    PriorityAtMost7,
    /// A VLAN identifier is within `0..=4095`.
    VlanIdAtMost4095,
}

impl std::fmt::Display for Constraint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::NonEmptySegments => "must contain at least one address",
            Self::AtMost256Segments => "contains more than 256 addresses",
            Self::OneByte => "is not Auto, an unsigned u8, or one raw byte",
            Self::PriorityAtMost7 => "is outside 0..=7",
            Self::VlanIdAtMost4095 => "is outside 0..=4095",
        })
    }
}
