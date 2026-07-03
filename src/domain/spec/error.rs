// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv6Addr};
use std::num::ParseIntError;

use thiserror::Error;

use crate::domain::net::MacAddressParseError;
use crate::domain::request::Icmpv6ErrorCode;

pub(crate) type SpecResult<T> = std::result::Result<T, SpecError>;

#[derive(Debug, Error)]
pub(crate) enum SpecError {
    #[error("parse IP address failed: value='{value}'")]
    IpAddressParse {
        value: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("target address must not be empty")]
    EmptyTargetAddress,
    #[error("hex string must contain an even number of characters")]
    HexStringOddLength,
    #[error("hex string exceeds maximum supported length of {max_bytes} bytes")]
    HexStringTooLong { max_bytes: usize },
    #[error("invalid hex digit '{digit}'")]
    InvalidHexDigit { digit: char },
    #[error("empty --ipv6-ext descriptor")]
    EmptyIpv6ExtensionDescriptor,
    #[error("unknown IPv6 extension header '{header}' in --ipv6-ext")]
    UnknownIpv6ExtensionHeader { header: String },
    #[error("unknown parameter '{parameter}' in --ipv6-ext {descriptor} descriptor")]
    UnknownIpv6ExtensionParameter {
        parameter: String,
        descriptor: String,
    },
    #[error("parse IPv6 extension hex payload failed: kind={kind}: {source}")]
    Ipv6ExtensionPayloadParse {
        kind: String,
        #[source]
        source: Box<SpecError>,
    },
    #[error("routing header requires 'segments=' (e.g. --ipv6-ext routing:segments=2001:db8::1;2001:db8::2)")]
    MissingIpv6RoutingSegments,
    #[error("parse routing type failed: value='{value}', descriptor=--ipv6-ext routing")]
    Ipv6RoutingTypeParse {
        value: String,
        #[source]
        source: ParseIntError,
    },
    #[error("unknown parameter '{parameter}' in --ipv6-ext routing descriptor")]
    UnknownIpv6RoutingParameter { parameter: String },
    #[error("parse IPv6 address failed: segment='{segment}', context=routing_segments")]
    Ipv6RoutingSegmentParse {
        segment: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("routing segments cannot include special-purpose address {address} (multicast/loopback/unspecified/reserved)")]
    Ipv6RoutingSegmentSpecialAddress { address: Ipv6Addr },
    #[error("routing header requires at least one segment address")]
    Ipv6RoutingSegmentsEmpty,
    #[error("routing header supports at most {max_segments} segment addresses")]
    Ipv6RoutingSegmentsTooMany { max_segments: usize },
    #[error("IPv6 extension headers exceed maximum length")]
    Ipv6ExtensionLengthOverflow,
    #[error("only one Hop-by-Hop header may be specified via --ipv6-ext")]
    Ipv6HopByHopDuplicate,
    #[error("Hop-by-Hop header must be the first entry in --ipv6-ext")]
    Ipv6HopByHopNotFirst,
    #[error("Destination Options header may appear at most twice in --ipv6-ext")]
    Ipv6DestinationOptionsTooMany,
    #[error("only one Routing header may be specified via --ipv6-ext")]
    Ipv6RoutingDuplicate,
    #[error("IPv6 extension headers exceed maximum payload length")]
    Ipv6ExtensionPayloadTooLarge,
    #[error("--prefer-ipv6 and --prefer-ipv4 cannot be specified together")]
    PreferIpv4AndIpv6Conflict,
    #[error("multiple payload sources specified; please choose only one")]
    MultiplePayloadSources,
    #[error("--vlan-prio requires --vlan-id to be set")]
    VlanPriorityRequiresId,
    #[error("--vlan-dei requires --vlan-id to be set")]
    VlanDeiRequiresId,
    #[error("VLAN ID is invalid; must be between 1 and 4094, but got {value}")]
    VlanIdInvalid { value: u16 },
    #[error("VLAN priority is invalid; must be between 0 and 7, but got {value}")]
    VlanPriorityInvalid { value: u8 },
    #[error("parse MAC address failed: value='{value}'")]
    MacAddressParse {
        value: String,
        #[source]
        source: MacAddressParseError,
    },
    #[error("parse EtherType failed: value='{value}'")]
    EtherTypeParse {
        value: String,
        #[source]
        source: ParseIntError,
    },
    #[error("EtherType 0x{ethertype:04x} conflicts with IPv{target_version} packet")]
    EtherTypeIpVersionMismatch { ethertype: u16, target_version: u8 },
    #[error("--interval cannot be combined with --flood because flood mode ignores delays")]
    IntervalConflictsWithFlood,
    #[error("--loop cannot be combined with --count because loop mode runs indefinitely")]
    LoopConflictsWithCount,
    #[error("--count must be greater than zero")]
    CountMustBePositive,
    #[error("interval value must not be empty")]
    EmptyIntervalValue,
    #[error("failed to parse interval '{value}' (examples: '250ms', '1.5s', '2m')")]
    IntervalParse { value: String },
    #[error("ICMPv6 error code {code:?} does not match explicitly provided type {existing}")]
    Icmpv6ErrorCodeMismatch { code: Icmpv6ErrorCode, existing: u8 },
    #[error("--mtu can only be used with the packet-too-big message type")]
    Icmpv6MtuRequiresPacketTooBig,
    #[error("unsupported TCP flag character '{flag}'")]
    UnsupportedTcpFlag { flag: char },
    #[error("duplicate TCP flag character '{flag}'")]
    DuplicateTcpFlag { flag: char },
    #[error("window scale must be between 0 and 14")]
    TcpWindowScaleOutOfRange,
    #[error("timestamps must use format value:echo (e.g., 12345:0)")]
    TcpTimestampsFormat,
    #[error("parse timestamp value failed: input='{value}'")]
    TcpTimestampValueParse {
        value: String,
        #[source]
        source: ParseIntError,
    },
    #[error("parse timestamp echo value failed: input='{value}'")]
    TcpTimestampEchoParse {
        value: String,
        #[source]
        source: ParseIntError,
    },
    #[error("TCP total header length {length} exceeds maximum of {max} bytes")]
    TcpHeaderTooLong { length: usize, max: usize },
    #[error("TCP options length {length} must be 4-byte aligned")]
    TcpOptionsNotAligned { length: usize },
    #[error("IPv6 {header} options header length {length} exceeds maximum of {max} bytes")]
    Ipv6OptionsHeaderTooLong {
        header: &'static str,
        length: usize,
        max: usize,
    },
    #[error("HTTP method must be a non-empty token")]
    InvalidHttpMethod,
    #[error("HTTP path must start with '/' and contain no control characters")]
    InvalidHttpPath,
    #[error("HTTP host must not be empty or contain whitespace/control characters")]
    InvalidHttpHost,
    #[error("{field} must be a non-empty ASCII DNS hostname within DNS length limits")]
    InvalidDnsHostname { field: &'static str },
    #[cfg(not(feature = "pcap"))]
    #[error("--filter requires Packetcraft to be built with the 'pcap' feature")]
    FilterRequiresPcap,
    #[cfg(not(feature = "pcap"))]
    #[error("--listen-reply requires Packetcraft to be built with the 'pcap' feature")]
    ListenReplyRequiresPcap,
    #[cfg(not(feature = "pcap"))]
    #[error("--show-reply requires Packetcraft to be built with the 'pcap' feature")]
    ShowReplyRequiresPcap,
    #[cfg(not(feature = "pcap"))]
    #[error("--pcap-save requires Packetcraft to be built with the 'pcap' feature")]
    PcapSaveRequiresFeature,
    #[cfg(not(feature = "pcap"))]
    #[error("--pcap-write requires Packetcraft to be built with the 'pcap' feature")]
    PcapWriteRequiresFeature,
    #[cfg(not(feature = "metrics"))]
    #[error("metrics options require PacketcraftR to be built with the 'metrics' feature")]
    MetricsRequiresFeature,
    #[error("source IP address {src_ip} does not match target IP version (IPv{target_version})")]
    SourceIpVersionMismatch { src_ip: IpAddr, target_version: u8 },
    #[error("target address {target} conflicts with --prefer-ipv{prefer_version}")]
    TargetIpVersionPreferenceMismatch { target: IpAddr, prefer_version: u8 },
    #[error("option '{option}' is valid only for IPv4, but the target address is IPv6")]
    IpV4OptionWithIpV6Target { option: &'static str },
    #[error("option '{option}' is valid only for IPv6, but the target address is IPv4")]
    IpV6OptionWithIpV4Target { option: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn ip_address_parse_display_keeps_context_and_source() {
        let source = "not-an-ip".parse::<IpAddr>().unwrap_err();
        let err = SpecError::IpAddressParse {
            value: "not-an-ip".to_string(),
            source,
        };

        assert_eq!(
            err.to_string(),
            "parse IP address failed: value='not-an-ip'"
        );
        assert!(err.source().is_some());
    }

    #[test]
    fn ipv6_extension_payload_parse_preserves_nested_source() {
        let err = SpecError::Ipv6ExtensionPayloadParse {
            kind: "destination".to_string(),
            source: Box::new(SpecError::InvalidHexDigit { digit: 'z' }),
        };

        assert!(err.to_string().contains("kind=destination"));
        assert_eq!(
            err.source().map(ToString::to_string),
            Some("invalid hex digit 'z'".to_string())
        );
    }
}
