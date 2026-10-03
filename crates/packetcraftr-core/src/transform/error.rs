// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{Classification, Classified, Kind};
use crate::protocol::headers;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid packet transform input: {0}")]
    Invalid(InvalidInput),
    #[error("unsupported packet transform: {0}")]
    Unsupported(Unsupported),
    #[error("packet transform exceeds {field}={limit}")]
    Limit { field: Limit, limit: usize },
    #[error("packet transform requires {field} in {min}..={max}")]
    LimitRange {
        field: Limit,
        min: usize,
        max: usize,
    },
    #[error(transparent)]
    Frame(#[from] crate::frame::Error),
    #[error(transparent)]
    Decode(#[from] crate::decode::Error),
    #[error("packet transform checksum failed")]
    Checksum(#[source] crate::codec::Error),
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
            Self::Limit { .. } | Self::LimitRange { .. } => Classification::new(
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InvalidInput {
    AssignmentSyntax,
    AssignmentEmptyPath,
    AssignmentPathSpace,
    AssignmentValueNotUnsigned,
    EditSyntax,
    EditOccurrence,
    EditOccurrenceNotNumber,
    EditOccurrenceZero,
    EditUnknownProtocol,
    EditPath,
    EditUnknownField,
    EditFieldNotUnsigned,
    EditValueWidth,
    DuplicateEdit,
    EditTruncatedCapture,
    OverlappingEdits,
    EditOutsideTransport,
    TransportCoverage,
    UdpLength,
    UdpLengthOverflow,
    UdpLengthExceedsPayload,
    Ipv4ChecksumPlacement,
    TransportChecksumPlacement,
    FieldRangeCaptured,
    FieldRangeWidth,
    FragmentTruncatedCapture,
    Ipv4HeaderChecksum,
    Ipv4ReservedFlag,
    MtuBelowIpv4Header,
    Ipv4Identification,
    Ipv4FragmentLength,
    TruncatedTcpHeader,
    TcpHeaderLength,
    TruncatedUpperLayer,
    MtuBelowIpv6Headers,
    Ipv6FirstFragment,
    Ipv6Identification,
    Ipv6FragmentLength,
    MtuFragmentPayload,
    VlanTag,
    MixedAddressFamilies,
    RewriteTruncatedCapture,
    AddressFamilyChange,
    TruncatedIcmpv6,
    AddressMapSyntax,
    AddressMapAddress,
    AddressMapFamilies,
    AddressMapPrefix,
    AddressMapHostBits,
    AddressMapOverlap,
}

impl InvalidInput {
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
            Self::EditFieldNotUnsigned => {
                "field edit targets a field that is not an unsigned integer"
            }
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
            Self::AddressMapSyntax => "address mappings use OLD=NEW",
            Self::AddressMapAddress => "address mapping holds an invalid address",
            Self::AddressMapFamilies => "address mapping mixes IPv4 and IPv6",
            Self::AddressMapPrefix => "address mapping prefix lengths are invalid or differ",
            Self::AddressMapHostBits => "address mapping prefix has host bits set",
            Self::AddressMapOverlap => "address mapping sources overlap",
        }
    }
}

display_via_as_str!(InvalidInput);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Unsupported {
    ChecksumOverFragment,
    Ipv4SourceRoute,
    Ipv6RoutingHeader,
    Ipv6HomeAddress,
    NestedEditPath,
    EditProtocolSchema,
    EditField,
    EditLayerMissing,
    EditOpaqueLayer,
    EditFieldLayout,
    EditFieldWidth,
    EditProtectedTraffic,
    EditChecksumCoverage,
    TransportChecksumEnvelope,
    TransportChecksum,
    ChecksumLayout,
    LinkType,
    EthernetPayload,
    AlreadyFragmented,
    DontFragment,
    Ipv6PayloadLength,
    Ipv6FragmentOrIpsec,
    MisorderedHopByHop,
    Ipv6UpperLayer,
    LinkEditWithoutEthernet,
    RewriteLinkType,
    NetworkEditWithoutIp,
    RawIpTrailer,
    UpperLayerChecksum,
    PortEditTransport,
    PacketRoot,
}

impl Unsupported {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Limit {
    MaxFragments,
    MaxOutputBytes,
    FieldAssignments,
    VlanDepth,
    AddressMapEntries,
}

impl Limit {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaxFragments => "max_fragments",
            Self::MaxOutputBytes => "max_output_bytes",
            Self::FieldAssignments => "field assignments",
            Self::VlanDepth => "VLAN depth",
            Self::AddressMapEntries => "address map entries",
        }
    }
}

display_via_as_str!(Limit);
