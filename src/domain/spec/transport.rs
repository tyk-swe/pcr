// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use super::error::{SpecError, SpecResult};

use crate::domain::request::{
    IcmpRequest, Icmpv6ErrorCode, Icmpv6ErrorKind, Icmpv6Request, TcpRequest,
    TransportProtocolRequest, TransportRequest,
};

use super::utils::parse_hex_bytes;

const TCP_BASE_HEADER_LEN: usize = 20;
const TCP_MAX_HEADER_LEN: usize = 60;

#[derive(Debug, Clone, Default)]
pub struct Icmpv6Spec {
    pub kind: Option<u8>,
    pub code: Option<u8>,
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
    pub parameter: Option<u32>,
}

impl Icmpv6Spec {
    pub(crate) fn from_request(icmp: &Icmpv6Request) -> SpecResult<Self> {
        let mut kind = icmp.kind;
        let mut code = icmp.code;
        let mut parameter = icmp.parameter;

        if let Some(selected) = icmp.error {
            let derived = icmpv6_error_kind_to_type(selected);
            kind.get_or_insert(derived);
            if code.is_none() {
                code = Some(default_error_code_for(selected));
            }
        }

        if let Some(selected_code) = icmp.error_code {
            let (expected_type, resolved_code) = icmpv6_error_code_to_type_and_value(selected_code);
            match kind {
                Some(existing) if existing != expected_type => {
                    return Err(SpecError::Icmpv6ErrorCodeMismatch {
                        code: selected_code,
                        existing,
                    });
                }
                _ => {
                    kind = Some(expected_type);
                }
            }
            code = Some(resolved_code);
        }

        if let Some(mtu) = icmp.mtu {
            let packet_too_big = ICMPV6_PACKET_TOO_BIG;
            match kind {
                Some(existing) if existing != packet_too_big => {
                    return Err(SpecError::Icmpv6MtuRequiresPacketTooBig);
                }
                _ => {
                    kind = Some(packet_too_big);
                    if code.is_none() {
                        code = Some(0);
                    }
                    parameter = Some(mtu);
                }
            }
        }

        Ok(Self {
            kind,
            code,
            identifier: icmp.identifier,
            sequence: icmp.sequence,
            parameter,
        })
    }
}

const ICMPV6_DESTINATION_UNREACHABLE: u8 = 1;
const ICMPV6_PACKET_TOO_BIG: u8 = 2;
const ICMPV6_TIME_EXCEEDED: u8 = 3;
const ICMPV6_PARAMETER_PROBLEM: u8 = 4;

fn icmpv6_error_kind_to_type(kind: Icmpv6ErrorKind) -> u8 {
    match kind {
        Icmpv6ErrorKind::DestinationUnreachable => ICMPV6_DESTINATION_UNREACHABLE,
        Icmpv6ErrorKind::PacketTooBig => ICMPV6_PACKET_TOO_BIG,
        Icmpv6ErrorKind::TimeExceeded => ICMPV6_TIME_EXCEEDED,
        Icmpv6ErrorKind::ParameterProblem => ICMPV6_PARAMETER_PROBLEM,
    }
}

fn default_error_code_for(kind: Icmpv6ErrorKind) -> u8 {
    match kind {
        Icmpv6ErrorKind::DestinationUnreachable
        | Icmpv6ErrorKind::PacketTooBig
        | Icmpv6ErrorKind::TimeExceeded
        | Icmpv6ErrorKind::ParameterProblem => 0,
    }
}

fn icmpv6_error_code_to_type_and_value(code: Icmpv6ErrorCode) -> (u8, u8) {
    match code {
        Icmpv6ErrorCode::DestinationUnreachableNoRoute => (ICMPV6_DESTINATION_UNREACHABLE, 0),
        Icmpv6ErrorCode::DestinationUnreachableAdminProhibited => {
            (ICMPV6_DESTINATION_UNREACHABLE, 1)
        }
        Icmpv6ErrorCode::DestinationUnreachableBeyondScope => (ICMPV6_DESTINATION_UNREACHABLE, 2),
        Icmpv6ErrorCode::DestinationUnreachableAddressUnreachable => {
            (ICMPV6_DESTINATION_UNREACHABLE, 3)
        }
        Icmpv6ErrorCode::DestinationUnreachablePortUnreachable => {
            (ICMPV6_DESTINATION_UNREACHABLE, 4)
        }
        Icmpv6ErrorCode::DestinationUnreachableSourcePolicy => (ICMPV6_DESTINATION_UNREACHABLE, 5),
        Icmpv6ErrorCode::DestinationUnreachableRejectRoute => (ICMPV6_DESTINATION_UNREACHABLE, 6),
        Icmpv6ErrorCode::DestinationUnreachableSourceRoutingError => {
            (ICMPV6_DESTINATION_UNREACHABLE, 7)
        }
        Icmpv6ErrorCode::TimeExceededHopLimit => (ICMPV6_TIME_EXCEEDED, 0),
        Icmpv6ErrorCode::TimeExceededReassembly => (ICMPV6_TIME_EXCEEDED, 1),
        Icmpv6ErrorCode::ParameterProblemErroneousHeader => (ICMPV6_PARAMETER_PROBLEM, 0),
        Icmpv6ErrorCode::ParameterProblemUnrecognizedNextHeader => (ICMPV6_PARAMETER_PROBLEM, 1),
        Icmpv6ErrorCode::ParameterProblemUnrecognizedOption => (ICMPV6_PARAMETER_PROBLEM, 2),
    }
}

#[derive(Debug, Clone, Default)]
pub enum TransportSpec {
    #[default]
    Auto,
    Tcp(TcpSpec),
    Udp(UdpSpec),
    Icmp(IcmpSpec),
    Icmpv6(Icmpv6Spec),
}

impl TransportSpec {
    pub(crate) fn from_request(
        request: &TransportRequest,
        destination: Option<IpAddr>,
        prefer_ipv6: bool,
    ) -> SpecResult<Self> {
        if let Some(command) = &request.command {
            match command {
                TransportProtocolRequest::Tcp(tcp_request) => {
                    return Ok(TransportSpec::Tcp(TcpSpec::from_request(
                        request,
                        tcp_request,
                    )?));
                }
                TransportProtocolRequest::Udp => {
                    return Ok(TransportSpec::Udp(UdpSpec::from_request(request)?));
                }
                TransportProtocolRequest::Icmp(icmp_request) => {
                    return Ok(TransportSpec::Icmp(IcmpSpec::from_request(icmp_request)?));
                }
                TransportProtocolRequest::Icmpv6(icmpv6_request) => {
                    return Ok(TransportSpec::Icmpv6(Icmpv6Spec::from_request(
                        icmpv6_request,
                    )?));
                }
            }
        }

        Self::infer_default(request, destination, prefer_ipv6)
    }

    pub fn label(&self) -> &'static str {
        match self {
            TransportSpec::Auto => "AUTO",
            TransportSpec::Tcp(_) => "TCP",
            TransportSpec::Udp(_) => "UDP",
            TransportSpec::Icmp(_) => "ICMP",
            TransportSpec::Icmpv6(_) => "ICMPv6",
        }
    }

    fn infer_default(
        request: &TransportRequest,
        destination: Option<IpAddr>,
        prefer_ipv6: bool,
    ) -> SpecResult<Self> {
        if request.source_port.is_some() || request.destination_port.is_some() {
            return Ok(TransportSpec::Udp(UdpSpec {
                source_port: request.source_port,
                destination_port: request.destination_port,
            }));
        }

        match destination {
            Some(IpAddr::V6(_)) => Ok(TransportSpec::Icmpv6(Icmpv6Spec::default())),
            Some(IpAddr::V4(_)) => Ok(TransportSpec::Icmp(IcmpSpec::default())),
            None => {
                if prefer_ipv6 {
                    Ok(TransportSpec::Icmpv6(Icmpv6Spec::default()))
                } else {
                    Ok(TransportSpec::Icmp(IcmpSpec::default()))
                }
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TcpSpec {
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub flags: TcpFlagSet,
    pub sequence: Option<u32>,
    pub acknowledgement: Option<u32>,
    pub window_size: Option<u16>,
    pub options: Option<Vec<u8>>,
}

impl TcpSpec {
    pub(crate) fn from_request(request: &TransportRequest, tcp: &TcpRequest) -> SpecResult<Self> {
        let parsed_options = build_tcp_options_from_flags(tcp)?;

        Ok(Self {
            source_port: request.source_port,
            destination_port: request.destination_port,
            flags: TcpFlagSet::from_string(tcp.flags.as_deref().unwrap_or(""))?,
            sequence: tcp.sequence,
            acknowledgement: tcp.acknowledgement,
            window_size: tcp.window_size,
            options: parsed_options,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct TcpFlagSet {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlagSet {
    pub(crate) fn from_string(flags: &str) -> SpecResult<Self> {
        let mut set = Self::default();
        for ch in flags.chars() {
            let flag = ch.to_ascii_uppercase();
            let is_duplicate = match flag {
                'S' if set.syn => true,
                'A' if set.ack => true,
                'F' if set.fin => true,
                'R' if set.rst => true,
                'P' if set.psh => true,
                'U' if set.urg => true,
                'E' if set.ece => true,
                'C' if set.cwr => true,
                _ => false,
            };

            if is_duplicate {
                return Err(SpecError::DuplicateTcpFlag { flag });
            }

            match flag {
                'S' => set.syn = true,
                'A' => set.ack = true,
                'F' => set.fin = true,
                'R' => set.rst = true,
                'P' => set.psh = true,
                'U' => set.urg = true,
                'E' => set.ece = true,
                'C' => set.cwr = true,
                other => {
                    return Err(SpecError::UnsupportedTcpFlag { flag: other });
                }
            }
        }
        Ok(set)
    }
}

#[derive(Debug, Clone, Default)]
pub struct UdpSpec {
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
}

impl UdpSpec {
    pub(crate) fn from_request(request: &TransportRequest) -> SpecResult<Self> {
        Ok(Self {
            source_port: request.source_port,
            destination_port: request.destination_port,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct IcmpSpec {
    pub kind: Option<u8>,
    pub code: Option<u8>,
    pub identifier: Option<u16>,
    pub sequence: Option<u16>,
}

impl IcmpSpec {
    pub(crate) fn from_request(icmp: &IcmpRequest) -> SpecResult<Self> {
        Ok(Self {
            kind: icmp.kind,
            code: icmp.code,
            identifier: icmp.identifier,
            sequence: icmp.sequence,
        })
    }
}

/// Build TCP options from dedicated CLI flags (recommended approach)
pub(crate) fn build_tcp_options_from_flags(tcp: &TcpRequest) -> SpecResult<Option<Vec<u8>>> {
    // If hex is provided, use it directly
    if let Some(hex) = tcp.options_hex.as_ref() {
        let options = parse_tcp_options_hex(hex)?;
        validate_tcp_options(&options)?;
        return Ok(Some(options));
    }

    // Build from individual flags
    let mut bytes = Vec::new();

    if let Some(mss) = tcp.mss {
        bytes.extend_from_slice(&[0x02, 0x04]);
        bytes.extend_from_slice(&mss.to_be_bytes());
    }

    if let Some(wscale) = tcp.window_scale {
        if wscale > 14 {
            return Err(SpecError::TcpWindowScaleOutOfRange);
        }
        bytes.extend_from_slice(&[0x03, 0x03, wscale]);
    }

    if tcp.sack_permitted.unwrap_or(false) {
        bytes.extend_from_slice(&[0x04, 0x02]);
    }

    if let Some(ts) = tcp.timestamps.as_ref() {
        let (ts_val_str, ts_ecr_str) = ts.split_once(':').ok_or(SpecError::TcpTimestampsFormat)?;
        let ts_val =
            ts_val_str
                .parse::<u32>()
                .map_err(|source| SpecError::TcpTimestampValueParse {
                    value: ts_val_str.to_string(),
                    source,
                })?;
        let ts_ecr =
            ts_ecr_str
                .parse::<u32>()
                .map_err(|source| SpecError::TcpTimestampEchoParse {
                    value: ts_ecr_str.to_string(),
                    source,
                })?;
        bytes.extend_from_slice(&[0x08, 0x0a]);
        bytes.extend_from_slice(&ts_val.to_be_bytes());
        bytes.extend_from_slice(&ts_ecr.to_be_bytes());
    }

    // Pad to 32-bit boundary with zeros (RFC 9293)
    if !bytes.is_empty() && bytes.len() % 4 != 0 {
        let padding = 4 - (bytes.len() % 4);
        bytes.extend(std::iter::repeat_n(0u8, padding));
    }

    if bytes.is_empty() {
        Ok(None)
    } else {
        validate_tcp_options(&bytes)?;
        Ok(Some(bytes))
    }
}

/// Parse hex-only TCP options
pub(crate) fn parse_tcp_options_hex(hex: &str) -> SpecResult<Vec<u8>> {
    parse_hex_bytes(hex)
}

fn validate_tcp_options(options: &[u8]) -> SpecResult<()> {
    let header_len = TCP_BASE_HEADER_LEN + options.len();
    if header_len > TCP_MAX_HEADER_LEN {
        return Err(SpecError::TcpHeaderTooLong {
            length: header_len,
            max: TCP_MAX_HEADER_LEN,
        });
    }
    if !options.len().is_multiple_of(4) {
        return Err(SpecError::TcpOptionsNotAligned {
            length: options.len(),
        });
    }
    Ok(())
}
