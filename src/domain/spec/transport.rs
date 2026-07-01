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
pub(crate) struct Icmpv6Spec {
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
pub(crate) enum TransportSpec {
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

    pub(crate) fn label(&self) -> &'static str {
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
pub(crate) struct TcpSpec {
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
pub(crate) struct TcpFlagSet {
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
        for token in tcp_flag_tokens(flags) {
            for flag in parse_tcp_flag_token(&token)? {
                set.insert(flag)?;
            }
        }
        Ok(set)
    }

    fn insert(&mut self, flag: TcpFlag) -> SpecResult<()> {
        let slot = match flag {
            TcpFlag::Syn => &mut self.syn,
            TcpFlag::Ack => &mut self.ack,
            TcpFlag::Fin => &mut self.fin,
            TcpFlag::Rst => &mut self.rst,
            TcpFlag::Psh => &mut self.psh,
            TcpFlag::Urg => &mut self.urg,
            TcpFlag::Ece => &mut self.ece,
            TcpFlag::Cwr => &mut self.cwr,
        };
        if *slot {
            return Err(SpecError::DuplicateTcpFlag { flag: flag.name() });
        }
        *slot = true;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpFlag {
    Syn,
    Ack,
    Fin,
    Rst,
    Psh,
    Urg,
    Ece,
    Cwr,
}

impl TcpFlag {
    fn name(self) -> &'static str {
        match self {
            Self::Syn => "syn",
            Self::Ack => "ack",
            Self::Fin => "fin",
            Self::Rst => "rst",
            Self::Psh => "psh",
            Self::Urg => "urg",
            Self::Ece => "ece",
            Self::Cwr => "cwr",
        }
    }
}

fn tcp_flag_tokens(flags: &str) -> impl Iterator<Item = String> + '_ {
    flags
        .split(|ch: char| ch == ',' || ch == '+' || ch.is_whitespace())
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_tcp_flag_token(token: &str) -> SpecResult<Vec<TcpFlag>> {
    let normalized = token.to_ascii_lowercase();
    let named = match normalized.as_str() {
        "syn" => Some(TcpFlag::Syn),
        "ack" => Some(TcpFlag::Ack),
        "fin" => Some(TcpFlag::Fin),
        "rst" => Some(TcpFlag::Rst),
        "psh" | "push" => Some(TcpFlag::Psh),
        "urg" => Some(TcpFlag::Urg),
        "ece" => Some(TcpFlag::Ece),
        "cwr" => Some(TcpFlag::Cwr),
        _ => None,
    };
    if let Some(flag) = named {
        return Ok(vec![flag]);
    }

    if token.chars().all(is_compact_tcp_flag) {
        return token.chars().map(compact_tcp_flag).collect();
    }

    Err(SpecError::UnsupportedTcpFlagToken {
        token: token.to_string(),
    })
}

fn is_compact_tcp_flag(ch: char) -> bool {
    matches!(
        ch.to_ascii_uppercase(),
        'S' | 'A' | 'F' | 'R' | 'P' | 'U' | 'E' | 'C'
    )
}

fn compact_tcp_flag(ch: char) -> SpecResult<TcpFlag> {
    match ch.to_ascii_uppercase() {
        'S' => Ok(TcpFlag::Syn),
        'A' => Ok(TcpFlag::Ack),
        'F' => Ok(TcpFlag::Fin),
        'R' => Ok(TcpFlag::Rst),
        'P' => Ok(TcpFlag::Psh),
        'U' => Ok(TcpFlag::Urg),
        'E' => Ok(TcpFlag::Ece),
        'C' => Ok(TcpFlag::Cwr),
        _ => Err(SpecError::UnsupportedTcpFlagToken {
            token: ch.to_string(),
        }),
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct UdpSpec {
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
pub(crate) struct IcmpSpec {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::{
        Icmpv6ErrorCode, Icmpv6ErrorKind, Icmpv6Request, TcpRequest, TransportProtocolRequest,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn tcp_flags_accept_all_supported_flags_case_insensitively() {
        let flags = TcpFlagSet::from_string("safrpuec").unwrap();

        assert!(flags.syn);
        assert!(flags.ack);
        assert!(flags.fin);
        assert!(flags.rst);
        assert!(flags.psh);
        assert!(flags.urg);
        assert!(flags.ece);
        assert!(flags.cwr);
    }

    #[test]
    fn tcp_flags_reject_duplicate_and_unknown_flags() {
        assert!(matches!(
            TcpFlagSet::from_string("SS").unwrap_err(),
            SpecError::DuplicateTcpFlag { flag: "syn" }
        ));
        assert!(matches!(
            TcpFlagSet::from_string("X").unwrap_err(),
            SpecError::UnsupportedTcpFlagToken { token } if token == "X"
        ));
    }

    #[test]
    fn tcp_flags_accept_named_and_separated_forms() {
        for value in ["S", "SA", "syn", "syn,ack", "syn+ack", "syn ack", "SyN,Ack"] {
            let flags = TcpFlagSet::from_string(value).unwrap();
            assert!(flags.syn, "expected SYN from {value}");
            if value != "S" && value != "syn" {
                assert!(flags.ack, "expected ACK from {value}");
            }
        }
    }

    #[test]
    fn build_tcp_options_from_individual_flags_pads_to_word_boundary() {
        let options = build_tcp_options_from_flags(&TcpRequest {
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: Some(true),
            ..Default::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(
            options,
            vec![0x02, 0x04, 0x05, 0xb4, 0x03, 0x03, 0x07, 0x04, 0x02, 0, 0, 0]
        );
    }

    #[test]
    fn build_tcp_options_from_timestamps() {
        let options = build_tcp_options_from_flags(&TcpRequest {
            timestamps: Some("9:10".to_string()),
            ..Default::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(options, vec![0x08, 0x0a, 0, 0, 0, 9, 0, 0, 0, 10, 0, 0]);
    }

    #[test]
    fn build_tcp_options_prefers_raw_hex() {
        let options = build_tcp_options_from_flags(&TcpRequest {
            options_hex: Some("01 01 00 00".to_string()),
            mss: Some(1460),
            ..Default::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(options, vec![1, 1, 0, 0]);
    }

    #[test]
    fn build_tcp_options_rejects_bad_window_scale_timestamp_and_alignment() {
        assert!(matches!(
            build_tcp_options_from_flags(&TcpRequest {
                window_scale: Some(15),
                ..Default::default()
            })
            .unwrap_err(),
            SpecError::TcpWindowScaleOutOfRange
        ));
        assert!(matches!(
            build_tcp_options_from_flags(&TcpRequest {
                timestamps: Some("1".to_string()),
                ..Default::default()
            })
            .unwrap_err(),
            SpecError::TcpTimestampsFormat
        ));
        assert!(matches!(
            build_tcp_options_from_flags(&TcpRequest {
                options_hex: Some("010203".to_string()),
                ..Default::default()
            })
            .unwrap_err(),
            SpecError::TcpOptionsNotAligned { length: 3 }
        ));
    }

    #[test]
    fn build_tcp_options_rejects_too_long_header() {
        let err = build_tcp_options_from_flags(&TcpRequest {
            options_hex: Some("00".repeat(44)),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(
            err,
            SpecError::TcpHeaderTooLong {
                length: 64,
                max: 60
            }
        ));
    }

    #[test]
    fn tcp_spec_from_request_parses_ports_flags_and_options() {
        let spec = TcpSpec::from_request(
            &TransportRequest {
                source_port: Some(1234),
                destination_port: Some(80),
                ..Default::default()
            },
            &TcpRequest {
                flags: Some("SA".to_string()),
                sequence: Some(10),
                acknowledgement: Some(20),
                window_size: Some(4096),
                options_hex: Some("01010000".to_string()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(spec.source_port, Some(1234));
        assert_eq!(spec.destination_port, Some(80));
        assert!(spec.flags.syn);
        assert!(spec.flags.ack);
        assert_eq!(spec.sequence, Some(10));
        assert_eq!(spec.acknowledgement, Some(20));
        assert_eq!(spec.window_size, Some(4096));
        assert_eq!(spec.options, Some(vec![1, 1, 0, 0]));
    }

    #[test]
    fn transport_spec_infers_udp_when_ports_are_present() {
        let spec = TransportSpec::from_request(
            &TransportRequest {
                destination_port: Some(53),
                ..Default::default()
            },
            None,
            false,
        )
        .unwrap();

        assert!(matches!(
            spec,
            TransportSpec::Udp(UdpSpec {
                destination_port: Some(53),
                ..
            })
        ));
    }

    #[test]
    fn transport_spec_infers_icmp_from_destination_family() {
        let v4 = TransportSpec::from_request(
            &TransportRequest::default(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            true,
        )
        .unwrap();
        let v6 = TransportSpec::from_request(
            &TransportRequest::default(),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            false,
        )
        .unwrap();

        assert!(matches!(v4, TransportSpec::Icmp(_)));
        assert!(matches!(v6, TransportSpec::Icmpv6(_)));
    }

    #[test]
    fn transport_spec_infers_icmpv6_from_preference_without_destination() {
        let spec = TransportSpec::from_request(&TransportRequest::default(), None, true).unwrap();

        assert!(matches!(spec, TransportSpec::Icmpv6(_)));
        assert_eq!(spec.label(), "ICMPv6");
    }

    #[test]
    fn transport_spec_uses_explicit_command() {
        let spec = TransportSpec::from_request(
            &TransportRequest {
                command: Some(TransportProtocolRequest::Tcp(TcpRequest {
                    flags: Some("S".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
            None,
            false,
        )
        .unwrap();

        assert!(matches!(spec, TransportSpec::Tcp(_)));
        assert_eq!(spec.label(), "TCP");
    }

    #[test]
    fn icmpv6_spec_derives_type_and_default_code_from_error_kind() {
        let spec = Icmpv6Spec::from_request(&Icmpv6Request {
            error: Some(Icmpv6ErrorKind::TimeExceeded),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(spec.kind, Some(3));
        assert_eq!(spec.code, Some(0));
    }

    #[test]
    fn icmpv6_spec_derives_type_and_code_from_named_error_code() {
        let spec = Icmpv6Spec::from_request(&Icmpv6Request {
            error_code: Some(Icmpv6ErrorCode::DestinationUnreachablePortUnreachable),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(spec.kind, Some(1));
        assert_eq!(spec.code, Some(4));
    }

    #[test]
    fn icmpv6_spec_rejects_mismatched_code_and_mtu_kind() {
        assert!(matches!(
            Icmpv6Spec::from_request(&Icmpv6Request {
                kind: Some(3),
                error_code: Some(Icmpv6ErrorCode::DestinationUnreachableNoRoute),
                ..Default::default()
            })
            .unwrap_err(),
            SpecError::Icmpv6ErrorCodeMismatch { existing: 3, .. }
        ));
        assert!(matches!(
            Icmpv6Spec::from_request(&Icmpv6Request {
                kind: Some(1),
                mtu: Some(1280),
                ..Default::default()
            })
            .unwrap_err(),
            SpecError::Icmpv6MtuRequiresPacketTooBig
        ));
    }

    #[test]
    fn icmpv6_spec_derives_packet_too_big_parameter_from_mtu() {
        let spec = Icmpv6Spec::from_request(&Icmpv6Request {
            mtu: Some(1280),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(spec.kind, Some(2));
        assert_eq!(spec.code, Some(0));
        assert_eq!(spec.parameter, Some(1280));
    }
}
