// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::cli;
use crate::engine::request as req;

impl From<&cli::OneShotOptions> for req::PacketRequest {
    fn from(options: &cli::OneShotOptions) -> Self {
        Self {
            destination: req::DestinationRequest {
                destination: options.destination.clone(),
                destination_ip: options.ip.destination_ip.clone(),
                interface: options.transmit.interface.clone(),
                resolved_destination: None,
            },
            layer2: req::Layer2Request::from(&options.layer2),
            ip: req::IpRequest::from(&options.ip),
            ipv6: req::Ipv6Request::from(&options.ip),
            transport: req::TransportRequest::from(&options.transport),
            payload: req::PayloadRequest::from(&options.payload),
            transmit: req::TransmissionRequest::from(&options.transmit),
            listener: req::ListenerRequest::from(&options.listen),
            rules_file: options.rule.rules_file.clone(),
            logging: req::LoggingRequest::from(&options.logging),
        }
    }
}

impl From<&cli::Layer2Options> for req::Layer2Request {
    fn from(options: &cli::Layer2Options) -> Self {
        Self {
            source_mac: options.source_mac.clone(),
            destination_mac: options.destination_mac.clone(),
            ethertype: options.ethertype.clone(),
            vlan: req::VlanRequest::from(&options.vlan),
        }
    }
}

impl From<&cli::VlanOptions> for req::VlanRequest {
    fn from(options: &cli::VlanOptions) -> Self {
        Self {
            id: options.id,
            priority: options.priority,
            drop_eligible_indicator: options.drop_eligible_indicator,
        }
    }
}

impl From<&cli::IpOptions> for req::IpRequest {
    fn from(options: &cli::IpOptions) -> Self {
        Self {
            source_ip: options.source_ip.clone(),
            destination_ip: options.destination_ip.clone(),
            prefer_ipv6: options.prefer_ipv6,
            prefer_ipv4: options.prefer_ipv4,
            ttl: options.ttl,
            tos: options.tos,
            identification: options.identification,
            fragment: req::FragmentRequest {
                mtu: options.fragment_mtu,
                offset: options.fragment_offset,
                more_fragments: options.more_fragments,
                dont_fragment: options.dont_fragment,
                overlap: options.fragment_overlap,
                teardrop: options.teardrop,
                profile: options.fragment_profile.map(req::FragmentProfile::from),
                fragment_id: options.fragment_id,
            },
        }
    }
}

impl From<&cli::IpOptions> for req::Ipv6Request {
    fn from(options: &cli::IpOptions) -> Self {
        Self {
            extensions: options.ipv6_extensions.clone(),
        }
    }
}

impl From<&cli::TransportOptions> for req::TransportRequest {
    fn from(options: &cli::TransportOptions) -> Self {
        Self {
            command: options
                .command
                .as_ref()
                .map(req::TransportProtocolRequest::from),
            source_port: options.source_port,
            destination_port: options.destination_port,
        }
    }
}

impl From<&cli::TransportCommand> for req::TransportProtocolRequest {
    fn from(command: &cli::TransportCommand) -> Self {
        match command {
            cli::TransportCommand::Tcp(options) => Self::Tcp(req::TcpRequest::from(options)),
            cli::TransportCommand::Udp(_) => Self::Udp,
            cli::TransportCommand::Icmp(options) => Self::Icmp(req::IcmpRequest::from(options)),
            cli::TransportCommand::Icmpv6(options) => {
                Self::Icmpv6(req::Icmpv6Request::from(options))
            }
        }
    }
}

impl From<&cli::TcpOptions> for req::TcpRequest {
    fn from(options: &cli::TcpOptions) -> Self {
        Self {
            flags: options.flags.clone(),
            sequence: options.sequence,
            acknowledgement: options.acknowledgement,
            window_size: options.window_size,
            mss: options.mss,
            window_scale: options.window_scale,
            sack_permitted: options.sack_permitted,
            timestamps: options.timestamps.clone(),
            options_hex: options.options_hex.clone(),
        }
    }
}

impl From<&cli::IcmpOptions> for req::IcmpRequest {
    fn from(options: &cli::IcmpOptions) -> Self {
        Self {
            kind: options.kind,
            code: options.code,
            identifier: options.identifier,
            sequence: options.sequence,
        }
    }
}

impl From<&cli::Icmpv6Options> for req::Icmpv6Request {
    fn from(options: &cli::Icmpv6Options) -> Self {
        Self {
            kind: options.kind,
            code: options.code,
            identifier: options.identifier,
            sequence: options.sequence,
            parameter: options.parameter,
            error: options.error.map(req::Icmpv6ErrorKind::from),
            error_code: options.error_code.map(req::Icmpv6ErrorCode::from),
            mtu: options.mtu,
        }
    }
}

impl From<&cli::PayloadOptions> for req::PayloadRequest {
    fn from(options: &cli::PayloadOptions) -> Self {
        Self {
            data: options.data.clone(),
            data_hex: options.data_hex.clone(),
            data_file: options.data_file.clone(),
            random_payload_size: options.random_payload_size,
            dns_query: options.dns_query.clone(),
            dns_type: options.dns_type.clone(),
            http_method: options.http_method.clone(),
            http_path: options.http_path.clone(),
            http_host: options.http_host.clone(),
            tls_client_hello: options.tls_client_hello.clone(),
        }
    }
}

impl From<&cli::TransmitOptions> for req::TransmissionRequest {
    fn from(options: &cli::TransmitOptions) -> Self {
        Self {
            count: options.count,
            interval: options.interval.clone(),
            flood: options.flood,
            loop_forever: options.loop_forever,
            force_layer3: options.force_layer3,
            ipv6_nd: options.ipv6_nd,
        }
    }
}

impl From<&cli::ListenOptions> for req::ListenerRequest {
    fn from(options: &cli::ListenOptions) -> Self {
        Self {
            listen: options.listen,
            filter: options.filter.clone(),
            promiscuous: options.promiscuous,
            show_reply: options.show_reply,
            timeout: options.timeout,
            capture_file: options.capture_file.clone(),
            queue_capacity: options.queue_capacity,
        }
    }
}

impl From<&cli::LoggingOptions> for req::LoggingRequest {
    fn from(options: &cli::LoggingOptions) -> Self {
        Self {
            log_file: options.log_file.clone(),
            pcap_write: options.pcap_write.clone(),
            metrics_json: options.metrics_json.clone(),
            log_level: options.log_level.map(req::LogLevel::from),
            structured: options.structured,
            prometheus_bind: options.prometheus_bind.clone(),
            allow_public_metrics: options.allow_public_metrics,
        }
    }
}

impl From<cli::FragmentProfile> for req::FragmentProfile {
    fn from(profile: cli::FragmentProfile) -> Self {
        match profile {
            cli::FragmentProfile::Overlap => Self::Overlap,
            cli::FragmentProfile::Teardrop => Self::Teardrop,
            cli::FragmentProfile::TinyOverlap => Self::TinyOverlap,
        }
    }
}

impl From<cli::LogLevel> for req::LogLevel {
    fn from(level: cli::LogLevel) -> Self {
        match level {
            cli::LogLevel::Trace => Self::Trace,
            cli::LogLevel::Debug => Self::Debug,
            cli::LogLevel::Info => Self::Info,
            cli::LogLevel::Warn => Self::Warn,
            cli::LogLevel::Error => Self::Error,
        }
    }
}

impl From<cli::Icmpv6ErrorKind> for req::Icmpv6ErrorKind {
    fn from(kind: cli::Icmpv6ErrorKind) -> Self {
        match kind {
            cli::Icmpv6ErrorKind::DestinationUnreachable => Self::DestinationUnreachable,
            cli::Icmpv6ErrorKind::PacketTooBig => Self::PacketTooBig,
            cli::Icmpv6ErrorKind::TimeExceeded => Self::TimeExceeded,
            cli::Icmpv6ErrorKind::ParameterProblem => Self::ParameterProblem,
        }
    }
}

impl From<cli::Icmpv6ErrorCode> for req::Icmpv6ErrorCode {
    fn from(code: cli::Icmpv6ErrorCode) -> Self {
        match code {
            cli::Icmpv6ErrorCode::DestinationUnreachableNoRoute => {
                Self::DestinationUnreachableNoRoute
            }
            cli::Icmpv6ErrorCode::DestinationUnreachableAdminProhibited => {
                Self::DestinationUnreachableAdminProhibited
            }
            cli::Icmpv6ErrorCode::DestinationUnreachableBeyondScope => {
                Self::DestinationUnreachableBeyondScope
            }
            cli::Icmpv6ErrorCode::DestinationUnreachableAddressUnreachable => {
                Self::DestinationUnreachableAddressUnreachable
            }
            cli::Icmpv6ErrorCode::DestinationUnreachablePortUnreachable => {
                Self::DestinationUnreachablePortUnreachable
            }
            cli::Icmpv6ErrorCode::DestinationUnreachableSourcePolicy => {
                Self::DestinationUnreachableSourcePolicy
            }
            cli::Icmpv6ErrorCode::DestinationUnreachableRejectRoute => {
                Self::DestinationUnreachableRejectRoute
            }
            cli::Icmpv6ErrorCode::DestinationUnreachableSourceRoutingError => {
                Self::DestinationUnreachableSourceRoutingError
            }
            cli::Icmpv6ErrorCode::TimeExceededHopLimit => Self::TimeExceededHopLimit,
            cli::Icmpv6ErrorCode::TimeExceededReassembly => Self::TimeExceededReassembly,
            cli::Icmpv6ErrorCode::ParameterProblemErroneousHeader => {
                Self::ParameterProblemErroneousHeader
            }
            cli::Icmpv6ErrorCode::ParameterProblemUnrecognizedNextHeader => {
                Self::ParameterProblemUnrecognizedNextHeader
            }
            cli::Icmpv6ErrorCode::ParameterProblemUnrecognizedOption => {
                Self::ParameterProblemUnrecognizedOption
            }
        }
    }
}
