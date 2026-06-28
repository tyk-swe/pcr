// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use super::error::{SpecError, SpecResult};

use crate::engine::request::{
    IcmpRequest, Icmpv6ErrorCode, Icmpv6ErrorKind, Icmpv6Request, TcpRequest,
    TransportProtocolRequest, TransportRequest,
};

use super::utils::parse_hex_bytes;

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
        use pnet::packet::icmpv6::Icmpv6Types;

        let mut kind = icmp.kind;
        let mut code = icmp.code;
        let mut parameter = icmp.parameter;

        if let Some(selected) = icmp.error {
            let derived = icmpv6_error_kind_to_type(selected);
            kind.get_or_insert(derived.0);
            if code.is_none() {
                code = Some(default_error_code_for(selected));
            }
        }

        if let Some(selected_code) = icmp.error_code {
            let (expected_type, resolved_code) = icmpv6_error_code_to_type_and_value(selected_code);
            match kind {
                Some(existing) if existing != expected_type.0 => {
                    return Err(SpecError::Icmpv6ErrorCodeMismatch {
                        code: selected_code,
                        existing,
                    });
                }
                _ => {
                    kind = Some(expected_type.0);
                }
            }
            code = Some(resolved_code);
        }

        if let Some(mtu) = icmp.mtu {
            let packet_too_big = Icmpv6Types::PacketTooBig.0;
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

fn icmpv6_error_kind_to_type(kind: Icmpv6ErrorKind) -> pnet::packet::icmpv6::Icmpv6Type {
    use pnet::packet::icmpv6::Icmpv6Types;

    match kind {
        Icmpv6ErrorKind::DestinationUnreachable => Icmpv6Types::DestinationUnreachable,
        Icmpv6ErrorKind::PacketTooBig => Icmpv6Types::PacketTooBig,
        Icmpv6ErrorKind::TimeExceeded => Icmpv6Types::TimeExceeded,
        Icmpv6ErrorKind::ParameterProblem => Icmpv6Types::ParameterProblem,
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

fn icmpv6_error_code_to_type_and_value(
    code: Icmpv6ErrorCode,
) -> (pnet::packet::icmpv6::Icmpv6Type, u8) {
    use pnet::packet::icmpv6::Icmpv6Types;

    match code {
        Icmpv6ErrorCode::DestinationUnreachableNoRoute => (Icmpv6Types::DestinationUnreachable, 0),
        Icmpv6ErrorCode::DestinationUnreachableAdminProhibited => {
            (Icmpv6Types::DestinationUnreachable, 1)
        }
        Icmpv6ErrorCode::DestinationUnreachableBeyondScope => {
            (Icmpv6Types::DestinationUnreachable, 2)
        }
        Icmpv6ErrorCode::DestinationUnreachableAddressUnreachable => {
            (Icmpv6Types::DestinationUnreachable, 3)
        }
        Icmpv6ErrorCode::DestinationUnreachablePortUnreachable => {
            (Icmpv6Types::DestinationUnreachable, 4)
        }
        Icmpv6ErrorCode::DestinationUnreachableSourcePolicy => {
            (Icmpv6Types::DestinationUnreachable, 5)
        }
        Icmpv6ErrorCode::DestinationUnreachableRejectRoute => {
            (Icmpv6Types::DestinationUnreachable, 6)
        }
        Icmpv6ErrorCode::DestinationUnreachableSourceRoutingError => {
            (Icmpv6Types::DestinationUnreachable, 7)
        }
        Icmpv6ErrorCode::TimeExceededHopLimit => (Icmpv6Types::TimeExceeded, 0),
        Icmpv6ErrorCode::TimeExceededReassembly => (Icmpv6Types::TimeExceeded, 1),
        Icmpv6ErrorCode::ParameterProblemErroneousHeader => (Icmpv6Types::ParameterProblem, 0),
        Icmpv6ErrorCode::ParameterProblemUnrecognizedNextHeader => {
            (Icmpv6Types::ParameterProblem, 1)
        }
        Icmpv6ErrorCode::ParameterProblemUnrecognizedOption => (Icmpv6Types::ParameterProblem, 2),
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
        return parse_tcp_options_hex(hex).map(Some);
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
        Ok(Some(bytes))
    }
}

/// Parse hex-only TCP options
pub(crate) fn parse_tcp_options_hex(hex: &str) -> SpecResult<Vec<u8>> {
    parse_hex_bytes(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::request::{
        IcmpRequest, Icmpv6ErrorCode, Icmpv6ErrorKind, Icmpv6Request, TcpRequest,
        TransportProtocolRequest, TransportRequest,
    };

    #[test]
    fn tcp_flag_set_parses_supported_combinations() {
        for (raw, expected) in [
            ("", (false, false, false, false, false, false, false, false)),
            ("S", (true, false, false, false, false, false, false, false)),
            ("SA", (true, true, false, false, false, false, false, false)),
            ("sa", (true, true, false, false, false, false, false, false)),
            ("SAFRPU", (true, true, true, true, true, true, false, false)),
            ("EC", (false, false, false, false, false, false, true, true)),
        ] {
            let flags = TcpFlagSet::from_string(raw).unwrap();
            assert_eq!(
                (
                    flags.syn, flags.ack, flags.fin, flags.rst, flags.psh, flags.urg, flags.ece,
                    flags.cwr
                ),
                expected,
                "{raw}",
            );
        }
    }

    #[test]
    fn tcp_flag_set_duplicate_flag_error() {
        let result = TcpFlagSet::from_string("SS");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::DuplicateTcpFlag { .. }
        ));
    }

    #[test]
    fn tcp_flag_set_unsupported_flag() {
        let result = TcpFlagSet::from_string("X");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::UnsupportedTcpFlag { .. }
        ));
    }

    #[test]
    fn transport_spec_labels_match_variants() {
        assert!(matches!(TransportSpec::default(), TransportSpec::Auto));
        for (spec, expected) in [
            (TransportSpec::default(), "AUTO"),
            (TransportSpec::Tcp(TcpSpec::default()), "TCP"),
            (TransportSpec::Udp(UdpSpec::default()), "UDP"),
            (TransportSpec::Icmp(IcmpSpec::default()), "ICMP"),
            (TransportSpec::Icmpv6(Icmpv6Spec::default()), "ICMPv6"),
        ] {
            assert_eq!(spec.label(), expected);
        }
    }

    #[test]
    fn transport_spec_infer_udp_from_port() {
        let options = TransportRequest {
            source_port: Some(12345),
            ..Default::default()
        };
        let spec = TransportSpec::from_request(&options, None, false).unwrap();
        assert!(matches!(spec, TransportSpec::Udp(_)));
    }

    #[test]
    fn transport_spec_infer_icmp_for_ipv4() {
        let options = TransportRequest::default();
        let dest = Some(IpAddr::V4("192.168.1.1".parse().unwrap()));
        let spec = TransportSpec::from_request(&options, dest, false).unwrap();
        assert!(matches!(spec, TransportSpec::Icmp(_)));
    }

    #[test]
    fn transport_spec_infer_icmpv6_for_ipv6() {
        let options = TransportRequest::default();
        let dest = Some(IpAddr::V6("2001:db8::1".parse().unwrap()));
        let spec = TransportSpec::from_request(&options, dest, false).unwrap();
        assert!(matches!(spec, TransportSpec::Icmpv6(_)));
    }

    #[test]
    fn transport_spec_infer_icmpv6_when_ipv6_preferred() {
        let options = TransportRequest::default();
        let spec = TransportSpec::from_request(&options, None, true).unwrap();
        assert!(matches!(spec, TransportSpec::Icmpv6(_)));
    }

    #[test]
    fn tcp_spec_from_options() {
        let options = TransportRequest {
            source_port: Some(40000),
            destination_port: Some(80),
            ..Default::default()
        };

        let tcp_options = TcpRequest {
            flags: Some("SA".to_string()),
            sequence: Some(1000),
            acknowledgement: Some(2000),
            window_size: Some(8192),
            mss: None,
            window_scale: None,
            sack_permitted: None,
            timestamps: None,
            options_hex: None,
        };

        let spec = TcpSpec::from_request(&options, &tcp_options).unwrap();
        assert_eq!(spec.source_port, Some(40000));
        assert_eq!(spec.destination_port, Some(80));
        assert!(spec.flags.syn);
        assert!(spec.flags.ack);
        assert_eq!(spec.sequence, Some(1000));
        assert_eq!(spec.acknowledgement, Some(2000));
        assert_eq!(spec.window_size, Some(8192));
    }

    #[test]
    fn tcp_options_mss() {
        let tcp_options = TcpRequest {
            flags: None,
            sequence: None,
            acknowledgement: None,
            window_size: None,
            mss: Some(1460),
            window_scale: None,
            sack_permitted: None,
            timestamps: None,
            options_hex: None,
        };

        let options = build_tcp_options_from_flags(&tcp_options).unwrap();
        assert!(options.is_some());
        let opts = options.unwrap();
        assert_eq!(opts[0], 0x02); // MSS option kind
        assert_eq!(opts[1], 0x04); // MSS option length
        assert_eq!(u16::from_be_bytes([opts[2], opts[3]]), 1460);
    }

    #[test]
    fn tcp_options_window_scale() {
        let tcp_options = TcpRequest {
            flags: None,
            sequence: None,
            acknowledgement: None,
            window_size: None,
            mss: None,
            window_scale: Some(7),
            sack_permitted: None,
            timestamps: None,
            options_hex: None,
        };

        let options = build_tcp_options_from_flags(&tcp_options).unwrap();
        assert!(options.is_some());
        let opts = options.unwrap();
        assert_eq!(opts[0], 0x03); // Window scale kind
        assert_eq!(opts[1], 0x03); // Window scale length
        assert_eq!(opts[2], 7); // Scale value
    }

    #[test]
    fn tcp_options_window_scale_out_of_range() {
        let tcp_options = TcpRequest {
            flags: None,
            sequence: None,
            acknowledgement: None,
            window_size: None,
            mss: None,
            window_scale: Some(15), // Invalid: window scale must be in range 0-14 per RFC 7323
            sack_permitted: None,
            timestamps: None,
            options_hex: None,
        };

        let result = build_tcp_options_from_flags(&tcp_options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::TcpWindowScaleOutOfRange
        ));
    }

    #[test]
    fn tcp_options_sack_permitted() {
        let tcp_options = TcpRequest {
            flags: None,
            sequence: None,
            acknowledgement: None,
            window_size: None,
            mss: None,
            window_scale: None,
            sack_permitted: Some(true),
            timestamps: None,
            options_hex: None,
        };

        let options = build_tcp_options_from_flags(&tcp_options).unwrap();
        assert!(options.is_some());
        let opts = options.unwrap();
        assert_eq!(opts[0], 0x04); // SACK permitted kind
        assert_eq!(opts[1], 0x02); // SACK permitted length
    }

    #[test]
    fn tcp_options_timestamps() {
        let tcp_options = TcpRequest {
            flags: None,
            sequence: None,
            acknowledgement: None,
            window_size: None,
            mss: None,
            window_scale: None,
            sack_permitted: None,
            timestamps: Some("12345:67890".to_string()),
            options_hex: None,
        };

        let options = build_tcp_options_from_flags(&tcp_options).unwrap();
        assert!(options.is_some());
        let opts = options.unwrap();
        assert_eq!(opts[0], 0x08); // Timestamp kind
        assert_eq!(opts[1], 0x0a); // Timestamp length
        assert_eq!(
            u32::from_be_bytes([opts[2], opts[3], opts[4], opts[5]]),
            12345
        );
        assert_eq!(
            u32::from_be_bytes([opts[6], opts[7], opts[8], opts[9]]),
            67890
        );
    }

    #[test]
    fn tcp_options_timestamps_invalid_format() {
        let tcp_options = TcpRequest {
            flags: None,
            sequence: None,
            acknowledgement: None,
            window_size: None,
            mss: None,
            window_scale: None,
            sack_permitted: None,
            timestamps: Some("12345".to_string()), // Invalid: missing colon separator (expected format: tsval:tsecr)
            options_hex: None,
        };

        let result = build_tcp_options_from_flags(&tcp_options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::TcpTimestampsFormat
        ));
    }

    #[test]
    fn tcp_options_padding() {
        let tcp_options = TcpRequest {
            flags: None,
            sequence: None,
            acknowledgement: None,
            window_size: None,
            mss: None,
            window_scale: Some(7), // 3-byte option, needs 1 byte padding
            sack_permitted: None,
            timestamps: None,
            options_hex: None,
        };

        let options = build_tcp_options_from_flags(&tcp_options).unwrap();
        assert!(options.is_some());
        let opts = options.unwrap();
        assert_eq!(opts.len() % 4, 0); // Should be padded to 32-bit boundary
        assert_eq!(opts.len(), 4); // 3 bytes + 1 padding
                                   // RFC 9293 (Section 3.1): "The padding is composed of zeros."
        assert_eq!(
            opts[3], 0x00,
            "TCP option padding must be zero (EOL), not NOP"
        );
    }

    #[test]
    fn udp_spec_from_options() {
        let options = TransportRequest {
            source_port: Some(12345),
            destination_port: Some(53),
            ..Default::default()
        };

        let spec = UdpSpec::from_request(&options).unwrap();
        assert_eq!(spec.source_port, Some(12345));
        assert_eq!(spec.destination_port, Some(53));
    }

    #[test]
    fn icmp_spec_from_options() {
        let icmp_options = IcmpRequest {
            kind: Some(8), // Echo request
            code: Some(0),
            identifier: Some(100),
            sequence: Some(1),
        };

        let spec = IcmpSpec::from_request(&icmp_options).unwrap();
        assert_eq!(spec.kind, Some(8));
        assert_eq!(spec.code, Some(0));
        assert_eq!(spec.identifier, Some(100));
        assert_eq!(spec.sequence, Some(1));
    }

    #[test]
    fn icmpv6_spec_with_error_kind() {
        let icmpv6_options = Icmpv6Request {
            kind: None,
            code: None,
            identifier: None,
            sequence: None,
            parameter: None,
            error: Some(Icmpv6ErrorKind::DestinationUnreachable),
            error_code: None,
            mtu: None,
        };

        let spec = Icmpv6Spec::from_request(&icmpv6_options).unwrap();
        assert_eq!(spec.kind, Some(1)); // Destination unreachable type
        assert_eq!(spec.code, Some(0)); // Default code
    }

    #[test]
    fn icmpv6_spec_with_mtu() {
        let icmpv6_options = Icmpv6Request {
            kind: None,
            code: None,
            identifier: None,
            sequence: None,
            parameter: None,
            error: None,
            error_code: None,
            mtu: Some(1280),
        };

        let spec = Icmpv6Spec::from_request(&icmpv6_options).unwrap();
        assert_eq!(spec.kind, Some(2)); // Packet too big
        assert_eq!(spec.code, Some(0));
        assert_eq!(spec.parameter, Some(1280));
    }

    #[test]
    fn icmpv6_spec_mtu_requires_packet_too_big() {
        let icmpv6_options = Icmpv6Request {
            kind: Some(1), // Destination unreachable, not packet too big
            code: None,
            identifier: None,
            sequence: None,
            parameter: None,
            error: None,
            error_code: None,
            mtu: Some(1280),
        };

        let result = Icmpv6Spec::from_request(&icmpv6_options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::Icmpv6MtuRequiresPacketTooBig
        ));
    }

    #[test]
    fn icmpv6_spec_error_code_mismatch() {
        let icmpv6_options = Icmpv6Request {
            kind: Some(3), // Time exceeded
            code: None,
            identifier: None,
            sequence: None,
            parameter: None,
            error: None,
            error_code: Some(Icmpv6ErrorCode::DestinationUnreachableNoRoute), // Requires type 1
            mtu: None,
        };

        let result = Icmpv6Spec::from_request(&icmpv6_options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::Icmpv6ErrorCodeMismatch { .. }
        ));
    }

    #[test]
    fn transport_spec_explicit_tcp() {
        let tcp_options = TcpRequest {
            flags: Some("S".to_string()),
            sequence: None,
            acknowledgement: None,
            window_size: None,
            mss: None,
            window_scale: None,
            sack_permitted: None,
            timestamps: None,
            options_hex: None,
        };

        let options = TransportRequest {
            command: Some(TransportProtocolRequest::Tcp(tcp_options)),
            ..Default::default()
        };

        let spec = TransportSpec::from_request(&options, None, false).unwrap();
        assert!(matches!(spec, TransportSpec::Tcp(_)));
    }

    #[test]
    fn transport_spec_explicit_udp() {
        let options = TransportRequest {
            destination_port: Some(53),
            command: Some(TransportProtocolRequest::Udp),
            ..Default::default()
        };

        let spec = TransportSpec::from_request(&options, None, false).unwrap();
        assert!(matches!(spec, TransportSpec::Udp(_)));
    }
}
