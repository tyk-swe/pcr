// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

//! Error types for the packet sender subsystem.
//!
//! This module defines the typed error hierarchy that powers the sender pipeline,
//! covering fragmentation, packet construction, transmission planning, and
//! execution. Each error variant captures the context required to surface clear
//! diagnostics while preserving the underlying error sources for inspection.

use std::net::IpAddr;
use std::path::PathBuf;

use pnet::packet::ip::IpNextHeaderProtocol;
use thiserror::Error;

use crate::network::checksum::ChecksumError;
use crate::util::net::ResolveHostnameError;

use super::control::SendControlError;
use super::transport::TransportBuildError;

pub(super) type Result<T> = std::result::Result<T, SenderError>;

#[derive(Debug, Error)]
pub(crate) enum SenderError {
    #[error(transparent)]
    Fragment(#[from] FragmentError),
    #[error(transparent)]
    Ipv4(#[from] Ipv4Error),
    #[error(transparent)]
    Ipv6(#[from] Ipv6Error),
    #[error(transparent)]
    Layer2(#[from] Layer2Error),
    #[error(transparent)]
    Header(#[from] HeaderError),
    #[error(transparent)]
    Checksum(#[from] ChecksumError),
    #[error(transparent)]
    Planner(#[from] PlannerError),
    #[error(transparent)]
    Executor(#[from] ExecutorError),
    #[error(transparent)]
    Payload(#[from] PayloadError),
    #[error(transparent)]
    Transport(#[from] TransportBuildError),
    #[error(transparent)]
    Interface(#[from] InterfaceError),
    #[error(transparent)]
    SendControl(#[from] SendControlError),
}

#[derive(Debug, Error)]
pub(crate) enum FragmentError {
    #[error("fragment offset {offset} is not aligned to 8-byte boundary")]
    Misaligned { offset: usize },
    #[error("MTU {mtu} too small to carry {context}")]
    MtuTooSmall { mtu: u16, context: &'static str },
    #[error("MTU {mtu} leaves no room for fragment payload")]
    MtuLeavesNoPayload { mtu: u16 },
    #[error("payload too small to generate overlapping fragments")]
    PayloadTooSmallForOverlap,
    #[error("payload must be at least 24 bytes for teardrop simulation")]
    PayloadTooSmallForTeardrop,
    #[error("fragmentation requested but 'don't fragment' flag is set")]
    FragmentationNotAllowed,
}

#[derive(Debug, Error)]
pub(crate) enum Ipv4Error {
    #[error("failed to generate any IPv4 fragments")]
    NoFragments,
    #[error("IPv4 fragment length {length} exceeds protocol maximum of {max} bytes; enable fragmentation or reduce the payload")]
    FragmentTooLarge { length: usize, max: usize },
    #[error("fragment offset overflow")]
    FragmentOffsetOverflow,
    #[error("fragment offset exceeds maximum value")]
    FragmentOffsetTooLarge,
}

#[derive(Debug, Error)]
pub(crate) enum Ipv6Error {
    #[error("IPv6 'dont_fragment' option cannot be combined with fragmentation directives")]
    DontFragmentConflict,
    #[error("failed to generate any IPv6 fragments")]
    NoFragments,
    #[error("buffer too small for IPv6 payload")]
    BufferTooSmall,
    #[error("IPv6 payload length exceeds maximum representable value")]
    PayloadTooLong,
    #[error("IPv6 payload length overflow")]
    PayloadLengthOverflow,
    #[error("IPv6 fragment payload exceeds maximum representable length")]
    FragmentPayloadTooLong,
    #[error("IPv6 fragment payload length overflow")]
    FragmentPayloadOverflow,
    #[error("fragment offset overflow")]
    FragmentOffsetOverflow,
    #[error("fragment offset exceeds maximum value")]
    FragmentOffsetTooLarge,
    #[error("IPv6 options header exceeds maximum permitted length")]
    OptionsTooLong,
    #[error("routing header requires at least one segment")]
    RoutingMissingSegment,
    #[error("routing header supports at most {max} segments (got {count})")]
    RoutingTooManySegments { max: usize, count: usize },
    #[error("routing header exceeds maximum permitted length")]
    RoutingTooLong,
    #[error("extension header length overflow")]
    ExtensionLengthOverflow,
}

#[derive(Debug, Error)]
pub(crate) enum Layer2Error {
    #[error("interface {interface} has no MAC address; specify --smac explicitly")]
    MissingInterfaceMac { interface: String },
    #[error("failed to allocate Ethernet frame")]
    EthernetAllocationFailed,
    #[error("failed to allocate VLAN header")]
    VlanAllocationFailed,
}

#[derive(Debug, Error)]
pub(crate) enum HeaderError {
    #[error("failed to allocate IPv4 packet")]
    Ipv4AllocationFailed,
    #[error("failed to allocate IPv6 packet")]
    Ipv6AllocationFailed,
}

#[derive(Debug, Error)]
pub(crate) enum PlannerError {
    #[cfg(not(feature = "pcap"))]
    #[error("--pcap-write requires Packetcraft to be built with the 'pcap' feature")]
    PcapFeatureRequired,
    #[error("source and destination IP versions must match")]
    IpVersionMismatch,
    #[error("failed to create metrics directory at {path}: {source}")]
    MetricsDirectory {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to serialize metrics snapshot: {0}")]
    MetricsSerialize(#[from] serde_json::Error),
    #[error("failed to write metrics snapshot at {path}: {source}")]
    MetricsWrite {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("IPv6 extension headers cannot be used with layer-3 transmission fallback; specify a destination MAC or ensure neighbor discovery succeeds")]
    Ipv6ExtensionHeaderLayer3Mismatch,
    #[error("transmission planner produced no frames")]
    EmptyFramePlan,
    #[error("transmission planner produced a frame that does not match link type {link_type}")]
    InvalidBuiltFrame { link_type: &'static str },
}

#[derive(Debug, Error)]
pub(crate) enum ExecutorError {
    #[cfg(not(feature = "pcap"))]
    #[error(
        "packet capture output ({path}) requires Packetcraft to be built with the 'pcap' feature"
    )]
    PcapFeatureRequired { path: PathBuf },
    #[error("opening datalink channel on interface {interface} failed: {source}")]
    OpenDatalinkChannel {
        interface: String,
        #[source]
        source: std::io::Error,
    },
    #[error("interface {interface} does not support Ethernet transmission")]
    UnsupportedDatalinkInterface { interface: String },
    #[error("datalink channel exhausted before frame was sent")]
    DatalinkChannelExhausted,
    #[error("failed to send frame via datalink on interface {interface}: {source}")]
    FrameSendFailed {
        interface: String,
        frame_len: usize,
        #[source]
        source: std::io::Error,
    },
    #[error("datalink receiver drain thread panicked on interface {interface}")]
    DatalinkDrainThreadPanicked { interface: String },
    #[error("failed to open raw transport channel for protocol {protocol:?}: {source}")]
    OpenTransportChannel {
        protocol: IpNextHeaderProtocol,
        #[source]
        source: std::io::Error,
    },
    #[error("unable to interpret IPv4 packet")]
    InvalidIpv4Packet,
    #[error("unable to interpret IPv6 packet")]
    InvalidIpv6Packet,
    #[error("failed to transmit IPv4 datagram toward {destination}: {source}")]
    SendIpv4 {
        destination: IpAddr,
        frame_len: usize,
        source: std::io::Error,
    },
    #[error("failed to transmit IPv6 datagram toward {destination}: {source}")]
    SendIpv6 {
        destination: IpAddr,
        frame_len: usize,
        source: std::io::Error,
    },
    #[cfg(feature = "pcap")]
    #[error("failed to create directory for pcap output at {path}: {source}")]
    CreatePcapDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[cfg(feature = "pcap")]
    #[error("failed to create pcap capture handle for link type {link_type:?}: {source}")]
    CreatePcapHandle {
        link_type: super::types::LinkType,
        source: pcap::Error,
    },
    #[cfg(feature = "pcap")]
    #[error("failed to open pcap output at {path}: {source}")]
    OpenPcapOutput { path: PathBuf, source: pcap::Error },
    #[cfg(feature = "pcap")]
    #[error("transmitted frame length {length} exceeds maximum recordable size")]
    FrameLengthTooLarge { length: usize },
    #[cfg(feature = "pcap")]
    #[error("failed to flush pcap output: {source}")]
    FlushPcap { source: pcap::Error },
    #[error("transmission task panicked")]
    TaskPanicked,
    #[error("transmission task cancelled")]
    TaskCancelled,
    #[error("execution blocked because plan was built in dry-run mode")]
    DryRunBlocked,
}

#[derive(Debug, Error)]
pub(crate) enum PayloadError {
    #[error("hex payload must contain an even number of hexadecimal characters")]
    HexLength,
    #[error("invalid hex byte '{byte:02x}'")]
    InvalidHexByte { byte: u8 },
    #[error("failed to read payload file at {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("payload file size {size} bytes exceeds limit of {limit} bytes")]
    PayloadTooLarge { size: u64, limit: u64 },
    #[error("invalid payload input: {0}")]
    InvalidInput(String),
}

#[derive(Debug, Error)]
pub(crate) enum InterfaceError {
    #[error("no suitable interface found using heuristics; specify --interface explicitly or provide a destination address")]
    InterfaceSelection,
    #[error("destination address is required for transmission planning")]
    DestinationRequired,
    #[error("failed to resolve hostname '{host}': {source}")]
    HostnameResolution {
        host: String,
        #[source]
        source: ResolveHostnameError,
    },
    #[error("interface resolution failed: {source}")]
    InterfaceLookup {
        #[source]
        source: crate::network::interface::InterfaceError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn planner_error_display_includes_link_type_for_invalid_frame() {
        assert_eq!(
            PlannerError::InvalidBuiltFrame { link_type: "ipv6" }.to_string(),
            "transmission planner produced a frame that does not match link type ipv6"
        );
    }

    #[test]
    fn executor_error_display_includes_interface_and_source() {
        let err = ExecutorError::OpenDatalinkChannel {
            interface: "eth0".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        };

        assert_eq!(
            err.to_string(),
            "opening datalink channel on interface eth0 failed: denied"
        );
        assert_eq!(err.source().unwrap().to_string(), "denied");
    }

    #[test]
    fn payload_error_display_includes_limits_and_paths() {
        assert_eq!(
            PayloadError::PayloadTooLarge {
                size: 1025,
                limit: 1024
            }
            .to_string(),
            "payload file size 1025 bytes exceeds limit of 1024 bytes"
        );
        assert_eq!(
            PayloadError::InvalidHexByte { byte: b'g' }.to_string(),
            "invalid hex byte '67'"
        );
    }

    #[test]
    fn interface_error_display_preserves_hostname_resolution_context() {
        let err = InterfaceError::HostnameResolution {
            host: "example.test".to_string(),
            source: ResolveHostnameError::NoAddresses {
                host: "example.test".to_string(),
            },
        };

        assert_eq!(
            err.to_string(),
            "failed to resolve hostname 'example.test': hostname 'example.test' did not resolve to any addresses"
        );
        assert!(err.source().is_some());
    }

    #[test]
    fn ipv4_error_display_mentions_protocol_limit() {
        assert_eq!(
            Ipv4Error::FragmentTooLarge {
                length: 70000,
                max: 65535
            }
            .to_string(),
            "IPv4 fragment length 70000 exceeds protocol maximum of 65535 bytes; enable fragmentation or reduce the payload"
        );
    }

    #[test]
    fn ipv6_error_display_includes_routing_segment_count() {
        assert_eq!(
            Ipv6Error::RoutingTooManySegments {
                max: 127,
                count: 128
            }
            .to_string(),
            "routing header supports at most 127 segments (got 128)"
        );
    }

    #[test]
    fn layer2_error_display_identifies_missing_interface_mac() {
        assert_eq!(
            Layer2Error::MissingInterfaceMac {
                interface: "eth-test".to_string()
            }
            .to_string(),
            "interface eth-test has no MAC address; specify --smac explicitly"
        );
    }

    #[test]
    fn sender_error_wraps_source_variant_without_losing_display() {
        let err = SenderError::from(PlannerError::IpVersionMismatch);

        assert_eq!(
            err.to_string(),
            "source and destination IP versions must match"
        );
    }
}
