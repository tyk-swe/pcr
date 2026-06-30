// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct PacketRequest {
    pub destination: DestinationRequest,
    pub layer2: Layer2Request,
    pub ip: IpRequest,
    pub ipv6: Ipv6Request,
    pub transport: TransportRequest,
    pub payload: PayloadRequest,
    pub transmit: TransmissionRequest,
    pub listener: ListenerRequest,
    pub rules_file: Option<String>,
    pub logging: LoggingRequest,
}

impl PacketRequest {
    pub(crate) fn prefer_ipv6_hint(&self) -> Option<bool> {
        infer_prefer_ipv6_hint(self)
    }
}

pub(crate) fn infer_prefer_ipv6_hint(request: &PacketRequest) -> Option<bool> {
    request
        .ip
        .prefer_ipv6_setting()
        .or_else(|| parse_ip_hint(request.ip.destination_ip.as_deref()).map(|addr| addr.is_ipv6()))
        .or_else(|| parse_ip_hint(request.ip.source_ip.as_deref()).map(|addr| addr.is_ipv6()))
        .or_else(|| {
            if !request.ipv6.extensions.is_empty() || request.ip.fragment.fragment_id.is_some() {
                Some(true)
            } else {
                None
            }
        })
        .or(match request.transport.command.as_ref() {
            Some(TransportProtocolRequest::Icmpv6(_)) => Some(true),
            Some(TransportProtocolRequest::Icmp(_)) => Some(false),
            _ => None,
        })
}

fn parse_ip_hint(raw: Option<&str>) -> Option<IpAddr> {
    raw.and_then(|value| value.trim().parse().ok())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct DestinationRequest {
    pub destination: Option<String>,
    pub destination_ip: Option<String>,
    pub interface: Option<String>,
    #[serde(skip)]
    pub resolved_destination: Option<IpAddr>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Layer2Request {
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub ethertype: Option<String>,
    pub vlan: VlanRequest,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct VlanRequest {
    pub id: Option<u16>,
    pub priority: Option<u8>,
    pub drop_eligible_indicator: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct IpRequest {
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub prefer_ipv6: Option<bool>,
    pub prefer_ipv4: Option<bool>,
    pub ttl: Option<u8>,
    pub tos: Option<u8>,
    pub identification: Option<u16>,
    pub fragment: FragmentRequest,
}

impl IpRequest {
    pub(crate) fn prefer_ipv6_setting(&self) -> Option<bool> {
        if let Some(value) = self.prefer_ipv6 {
            Some(value)
        } else if let Some(value) = self.prefer_ipv4 {
            if value {
                Some(false)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct FragmentRequest {
    pub mtu: Option<u16>,
    pub offset: Option<u16>,
    pub more_fragments: Option<bool>,
    pub dont_fragment: Option<bool>,
    pub overlap: Option<bool>,
    pub teardrop: Option<bool>,
    pub profile: Option<FragmentProfile>,
    pub fragment_id: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Ipv6Request {
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct TransportRequest {
    pub command: Option<TransportProtocolRequest>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransportProtocolRequest {
    Tcp(TcpRequest),
    Udp,
    Icmp(IcmpRequest),
    Icmpv6(Icmpv6Request),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct TcpRequest {
    pub flags: Option<String>,
    pub sequence: Option<u32>,
    pub acknowledgement: Option<u32>,
    pub window_size: Option<u16>,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: Option<bool>,
    pub timestamps: Option<String>,
    pub options_hex: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct IcmpRequest {
    pub kind: Option<u8>,
    pub code: Option<u8>,
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Icmpv6Request {
    pub kind: Option<u8>,
    pub code: Option<u8>,
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
    pub parameter: Option<u32>,
    pub error: Option<Icmpv6ErrorKind>,
    pub error_code: Option<Icmpv6ErrorCode>,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct PayloadRequest {
    pub data: Option<String>,
    pub data_hex: Option<String>,
    pub data_file: Option<String>,
    pub random_payload_size: Option<usize>,
    pub dns_query: Option<String>,
    pub dns_type: Option<String>,
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub http_host: Option<String>,
    pub tls_client_hello: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct TransmissionRequest {
    pub count: Option<u64>,
    pub interval: Option<String>,
    pub flood: Option<bool>,
    pub loop_forever: Option<bool>,
    pub force_layer3: Option<bool>,
    pub ipv6_nd: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct ListenerRequest {
    pub listen: Option<bool>,
    pub filter: Option<String>,
    pub promiscuous: Option<bool>,
    pub show_reply: Option<bool>,
    pub timeout: Option<u64>,
    pub capture_file: Option<String>,
    pub queue_capacity: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct LoggingRequest {
    pub log_file: Option<String>,
    pub pcap_write: Option<String>,
    pub metrics_json: Option<String>,
    pub log_level: Option<LogLevel>,
    pub structured: Option<bool>,
    pub prometheus_bind: Option<String>,
    pub allow_public_metrics: Option<bool>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FragmentProfile {
    Overlap,
    Teardrop,
    TinyOverlap,
}

impl fmt::Display for FragmentProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            FragmentProfile::Overlap => "overlap",
            FragmentProfile::Teardrop => "teardrop",
            FragmentProfile::TinyOverlap => "tiny-overlap",
        };
        f.write_str(label)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Icmpv6ErrorKind {
    DestinationUnreachable,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Icmpv6ErrorCode {
    DestinationUnreachableNoRoute,
    DestinationUnreachableAdminProhibited,
    DestinationUnreachableBeyondScope,
    DestinationUnreachableAddressUnreachable,
    DestinationUnreachablePortUnreachable,
    DestinationUnreachableSourcePolicy,
    DestinationUnreachableRejectRoute,
    DestinationUnreachableSourceRoutingError,
    TimeExceededHopLimit,
    TimeExceededReassembly,
    ParameterProblemErroneousHeader,
    ParameterProblemUnrecognizedNextHeader,
    ParameterProblemUnrecognizedOption,
}
