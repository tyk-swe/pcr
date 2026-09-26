// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The transform error and its typed reasons. Each reason renders the same
//! text the published error message carries.

use crate::error::{Classification, Classified, Kind};
use crate::protocol::headers;

/// Why a transform refused its input, grouped by published classification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is malformed or contradicts the requested transform.
    #[error("invalid packet transform input: {0}")]
    Invalid(InvalidInput),
    /// The input is well formed, but the transform deliberately does not
    /// handle it.
    #[error("unsupported packet transform: {0}")]
    Unsupported(Unsupported),
    /// The transform would exceed the ceiling `field`, configured at `limit`.
    #[error("packet transform exceeds {field}={limit}")]
    Limit { field: Limit, limit: usize },
    #[error(transparent)]
    Frame(#[from] crate::frame::Error),
    #[error(transparent)]
    Decode(#[from] crate::decode::Error),
    #[error("packet transform checksum failed")]
    Checksum(#[source] crate::codec::Error),
    /// The link, VLAN, or IP headers the transform edits could not be walked.
    #[error(transparent)]
    Header(#[from] headers::Error),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Frame(source) => source.classification(),
            Self::Decode(source) => source.classification(),
            Self::Header(source) => source.classification(),
            Self::Unsupported(_) => Classification::new(
                "packet.transform_unsupported",
                Kind::Packet,
                Some("inspect the documented transform boundaries"),
            ),
            Self::Limit { .. } => Classification::new(
                "policy.transform_limit",
                Kind::Policy,
                Some("raise a finite transform limit or reduce the input"),
            ),
            Self::Invalid(_) => Classification::new(
                "packet.transform_input",
                Kind::Packet,
                Some("supply a complete supported datagram"),
            ),
            Self::Checksum(_) => Classification::new(
                "packet.transform_checksum",
                Kind::Packet,
                Some("supply a complete datagram the checksum can cover"),
            ),
        }
    }
}

/// Why a transform refused its input as invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InvalidInput {
    /// A field assignment is not `<field>=<value>`.
    AssignmentSyntax,
    /// A field assignment names no field.
    AssignmentEmptyPath,
    /// A field assignment's path contains a space.
    AssignmentPathSpace,
    /// A field assignment's value is not an unsigned integer.
    AssignmentValueNotUnsigned,
    /// A field edit is not `<protocol>[#occurrence].<field>`.
    EditSyntax,
    /// A field edit's `#occurrence` is malformed.
    EditOccurrence,
    /// A field edit's occurrence is not a number.
    EditOccurrenceNotNumber,
    /// A field edit's occurrence is zero; occurrences start at 1.
    EditOccurrenceZero,
    /// A field edit names a protocol the registry does not know.
    EditUnknownProtocol,
    /// A field edit's field path does not parse.
    EditPath,
    /// A field edit names a field its protocol's schema does not declare.
    EditUnknownField,
    /// A field edit's value is not an unsigned integer.
    EditValueNotUnsigned,
    /// A field edit names a field whose declared kind is not unsigned.
    EditFieldNotUnsigned,
    /// A field edit's value does not fit the field's wire width.
    EditValueWidth,
    /// Two field edits name the same field of the same layer.
    DuplicateEdit,
    /// Field edits need the frame's complete original bytes.
    EditTruncatedCapture,
    /// Two field edits cover overlapping bytes.
    OverlappingEdits,
    /// A field edit lies outside the transport segment that encloses its layer.
    EditOutsideTransport,
    /// A transport checksum covers more bytes than the frame captured.
    TransportCoverage,
    /// A UDP length field is missing, shorter than the header, or longer than the segment.
    UdpLength,
    /// A UDP length computation overflows.
    UdpLengthOverflow,
    /// A UDP length field exceeds its IP payload.
    UdpLengthExceedsPayload,
    /// An IPv4 checksum field lies outside its header.
    Ipv4ChecksumPlacement,
    /// A transport checksum field lies outside its segment.
    TransportChecksumPlacement,
    /// An IPv6 source address is truncated.
    TruncatedIpv6Source,
    /// An IPv6 destination address is truncated.
    TruncatedIpv6Destination,
    /// An IPv4 source address is truncated.
    TruncatedIpv4Source,
    /// An IPv4 destination address is truncated.
    TruncatedIpv4Destination,
    /// An edited field's byte range exceeds the captured bytes.
    FieldRangeCaptured,
    /// An edited field's byte range is wider than eight bytes.
    FieldRangeWidth,
    /// Fragmentation needs the frame's complete original bytes.
    FragmentTruncatedCapture,
    /// The IPv4 header checksum does not verify.
    Ipv4HeaderChecksum,
    /// The IPv4 reserved flag is set.
    Ipv4ReservedFlag,
    /// The MTU cannot hold the IPv4 header.
    MtuBelowIpv4Header,
    /// The requested IPv4 identification does not fit 16 bits.
    Ipv4Identification,
    /// An IPv4 fragment length computation overflows.
    Ipv4FragmentLength,
    /// A TCP header is truncated.
    TruncatedTcpHeader,
    /// A TCP data offset is shorter than the fixed header or longer than the segment.
    TcpHeaderLength,
    /// An upper-layer header is truncated.
    TruncatedUpperLayer,
    /// The MTU cannot hold the IPv6 headers every fragment repeats.
    MtuBelowIpv6Headers,
    /// The first IPv6 fragment cannot hold every header up to the upper-layer header.
    Ipv6FirstFragment,
    /// IPv6 fragmentation needs an explicit identification.
    Ipv6Identification,
    /// An IPv6 fragment length computation overflows.
    Ipv6FragmentLength,
    /// The MTU leaves no room for an eight-byte-aligned fragment payload.
    MtuFragmentPayload,
    /// A VLAN rewrite's EtherType, identifier, or priority is out of range.
    VlanTag,
    /// A rewrite's source and destination use different IP families.
    MixedAddressFamilies,
    /// Header rewrites need the frame's complete original bytes.
    RewriteTruncatedCapture,
    /// A rewrite address's family differs from the datagram's.
    AddressFamilyChange,
    /// An ICMPv6 header is truncated.
    TruncatedIcmpv6,
}

impl InvalidInput {
    /// The reason as published in the error message.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AssignmentSyntax => "field assignments use <field>=<value>",
            Self::AssignmentEmptyPath => "field assignment has an empty field path",
            Self::AssignmentPathSpace => "field assignment path contains a space",
            Self::AssignmentValueNotUnsigned => "field assignment value is not unsigned",
            Self::EditSyntax => "field edits use <protocol>[#occurrence].<field>",
            Self::EditOccurrence => "invalid layer occurrence in field edit",
            Self::EditOccurrenceNotNumber => "layer occurrence is not a number",
            Self::EditOccurrenceZero => "layer occurrences start at 1",
            Self::EditUnknownProtocol => "field edit names an unknown protocol",
            Self::EditPath => "invalid field edit path",
            Self::EditUnknownField => "field edit names an unknown field",
            Self::EditValueNotUnsigned => "field edits require an unsigned value",
            Self::EditFieldNotUnsigned => "field edit value is not unsigned",
            Self::EditValueWidth => "field edit value exceeds the field width",
            Self::DuplicateEdit => "duplicate field edit",
            Self::EditTruncatedCapture => "cannot edit a truncated capture",
            Self::OverlappingEdits => "field edits overlap",
            Self::EditOutsideTransport => "field edit lies outside an enclosing transport span",
            Self::TransportCoverage => "transport coverage exceeds captured bytes",
            Self::UdpLength => "invalid UDP length",
            Self::UdpLengthOverflow => "UDP length overflows",
            Self::UdpLengthExceedsPayload => "UDP length exceeds its IP payload",
            Self::Ipv4ChecksumPlacement => "IPv4 checksum field is outside its header",
            Self::TransportChecksumPlacement => "transport checksum field is outside its segment",
            Self::TruncatedIpv6Source => "truncated IPv6 source",
            Self::TruncatedIpv6Destination => "truncated IPv6 destination",
            Self::TruncatedIpv4Source => "truncated IPv4 source",
            Self::TruncatedIpv4Destination => "truncated IPv4 destination",
            Self::FieldRangeCaptured => "field range exceeds captured bytes",
            Self::FieldRangeWidth => "field range exceeds eight bytes",
            Self::FragmentTruncatedCapture => "capture is truncated",
            Self::Ipv4HeaderChecksum => "invalid IPv4 header checksum",
            Self::Ipv4ReservedFlag => "IPv4 reserved flag is set",
            Self::MtuBelowIpv4Header => "MTU cannot contain the IPv4 header",
            Self::Ipv4Identification => "IPv4 identification exceeds 16 bits",
            Self::Ipv4FragmentLength => "IPv4 fragment length overflow",
            Self::TruncatedTcpHeader => "truncated TCP header",
            Self::TcpHeaderLength => "invalid TCP header length",
            Self::TruncatedUpperLayer => "truncated upper-layer header",
            Self::MtuBelowIpv6Headers => "MTU cannot contain IPv6 per-fragment headers",
            Self::Ipv6FirstFragment => "first IPv6 fragment cannot contain all headers",
            Self::Ipv6Identification => "IPv6 fragmentation requires an explicit identification",
            Self::Ipv6FragmentLength => "IPv6 fragment length overflow",
            Self::MtuFragmentPayload => "MTU leaves no aligned fragment payload",
            Self::VlanTag => "invalid VLAN rewrite tag",
            Self::MixedAddressFamilies => "rewrite addresses use different IP families",
            Self::RewriteTruncatedCapture => "cannot rewrite a truncated capture",
            Self::AddressFamilyChange => "cannot change IP address family",
            Self::TruncatedIcmpv6 => "truncated ICMPv6",
        }
    }
}

display_via_as_str!(InvalidInput);

/// Which input a transform deliberately does not handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Unsupported {
    /// A checksum-covered edit targets a fragment, which hides the rest of the segment.
    ChecksumOverFragment,
    /// IPv4 source routing changes the addresses a transport checksum covers.
    Ipv4SourceRoute,
    /// An IPv6 routing header changes the destination a transport checksum covers.
    Ipv6RoutingHeader,
    /// An IPv6 Home Address option changes the source a transport checksum covers.
    Ipv6HomeAddress,
    /// A field edit names a nested path; edits are limited to flat fixed-width fields.
    NestedEditPath,
    /// A field edit's protocol publishes no schema.
    EditProtocolSchema,
    /// A field edit names a field outside the supported edit set.
    EditField,
    /// A field edit selects a layer occurrence the frame does not contain.
    EditLayerMissing,
    /// A field edit crosses bytes a layer keeps opaque.
    EditOpaqueLayer,
    /// An edited field has no decoded byte layout.
    EditFieldLayout,
    /// An edited field's decoded layout does not match its fixed edit width.
    EditFieldWidth,
    /// Field edits refuse AH- or ESP-protected traffic.
    EditProtectedTraffic,
    /// A field edit is covered by a checksum the edit cannot repair.
    EditChecksumCoverage,
    /// A transport checksum to repair has no enclosing IPv4 or IPv6 header.
    TransportChecksumEnvelope,
    /// The transport's checksum cannot be repaired.
    TransportChecksum,
    /// A layer whose checksum needs repair has no decoded checksum layout.
    ChecksumLayout,
    /// The frame's link type is neither raw IP nor Ethernet.
    LinkType,
    /// The Ethernet payload is neither IPv4 nor IPv6.
    EthernetPayload,
    /// The IPv4 datagram is already a fragment.
    AlreadyFragmented,
    /// The IPv4 Don't Fragment flag is set.
    DontFragment,
    /// The IPv6 datagram is a jumbogram or carries no payload.
    Ipv6PayloadLength,
    /// The IPv6 datagram already carries a Fragment, AH, or ESP header.
    Ipv6FragmentOrIpsec,
    /// An IPv6 Hop-by-Hop header does not immediately follow the IPv6 header.
    MisorderedHopByHop,
    /// The IPv6 upper-layer header is not one fragmentation understands.
    Ipv6UpperLayer,
    /// A MAC or VLAN rewrite targets a frame that is not Ethernet.
    LinkEditWithoutEthernet,
    /// The frame's link type is neither Ethernet nor raw IP.
    RewriteLinkType,
    /// An address or port rewrite targets a frame without an outer IPv4 or IPv6 datagram.
    NetworkEditWithoutIp,
    /// A raw-IP frame carries bytes past its datagram.
    RawIpTrailer,
    /// The upper-layer checksum semantics are unknown or authenticated, so an address or port rewrite cannot repair them.
    UpperLayerChecksum,
    /// A port rewrite targets a datagram that is neither TCP nor UDP.
    PortEditTransport,
    /// A packet to transform does not begin with Ethernet, IPv4, or IPv6, so it has no link type the transforms accept.
    PacketRoot,
}

impl Unsupported {
    /// The reason as published in the error message.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChecksumOverFragment => "checksum-covered edits require a reassembled datagram",
            Self::Ipv4SourceRoute => "IPv4 source routing changes checksum destinations",
            Self::Ipv6RoutingHeader => "IPv6 routing header changes checksum destinations",
            Self::Ipv6HomeAddress => "IPv6 Home Address option changes checksum sources",
            Self::NestedEditPath => "field edits are limited to flat fixed-width fields",
            Self::EditProtocolSchema => "field edit protocol publishes no schema",
            Self::EditField => "field is outside the supported edit set",
            Self::EditLayerMissing => "field edit selects a layer the frame does not contain",
            Self::EditOpaqueLayer => "field edit crosses an opaque layer",
            Self::EditFieldLayout => "field has no byte layout to edit",
            Self::EditFieldWidth => "field layout does not match its fixed edit width",
            Self::EditProtectedTraffic => "field edits reject AH/ESP protected traffic",
            Self::EditChecksumCoverage => "field edit is covered by a checksum it cannot repair",
            Self::TransportChecksumEnvelope => "transport checksum needs an IPv4 or IPv6 envelope",
            Self::TransportChecksum => "unsupported transport checksum",
            Self::ChecksumLayout => "layer has no checksum byte layout",
            Self::LinkType => "capture link type is not raw IP or Ethernet/VLAN",
            Self::EthernetPayload => "Ethernet payload is not IPv4/IPv6",
            Self::AlreadyFragmented => "already fragmented IPv4",
            Self::DontFragment => "IPv4 DF prohibits fragmentation",
            Self::Ipv6PayloadLength => "IPv6 jumbogram or empty datagram",
            Self::Ipv6FragmentOrIpsec => "fragment, AH or ESP header",
            Self::MisorderedHopByHop => "misordered Hop-by-Hop header",
            Self::Ipv6UpperLayer => "unknown IPv6 upper-layer header",
            Self::LinkEditWithoutEthernet => "MAC/VLAN edits require Ethernet",
            Self::RewriteLinkType => "rewrite requires Ethernet or raw IP",
            Self::NetworkEditWithoutIp => "network edits require an outer IPv4/IPv6 datagram",
            Self::RawIpTrailer => "raw IP has uninterpreted trailing bytes",
            Self::UpperLayerChecksum => "unknown or authenticated upper-layer checksum semantics",
            Self::PortEditTransport => "port edits require TCP or UDP",
            Self::PacketRoot => "recipe must begin with Ethernet or IP",
        }
    }
}

display_via_as_str!(Unsupported);

/// The transform ceiling an input exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Limit {
    /// The fragment count ceiling.
    MaxFragments,
    /// The output byte ceiling.
    MaxOutputBytes,
    /// The field-assignment count ceiling.
    FieldAssignments,
    /// The VLAN tag depth ceiling.
    VlanDepth,
}

impl Limit {
    /// The reason as published in the error message.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaxFragments => "max_fragments",
            Self::MaxOutputBytes => "max_output_bytes",
            Self::FieldAssignments => "field assignments",
            Self::VlanDepth => "VLAN depth",
        }
    }
}

display_via_as_str!(Limit);
