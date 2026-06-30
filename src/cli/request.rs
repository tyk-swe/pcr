// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::{commands, enums, options};
use crate::domain::{command as cmd, request as req};

impl From<&options::OneShotOptions> for req::PacketRequest {
    fn from(options: &options::OneShotOptions) -> Self {
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

impl From<&commands::DnsQueryOptions> for cmd::DnsRequest {
    fn from(options: &commands::DnsQueryOptions) -> Self {
        Self {
            domain: options.domain.clone(),
            record_type: options.record_type.clone(),
            server: options.server.clone(),
            timeout: options.timeout,
            transaction_id: options.transaction_id,
            transport: options.transport,
            retries: options.retries,
        }
    }
}

#[cfg(feature = "repl")]
impl From<&commands::InteractiveOptions> for cmd::InteractiveRequest {
    fn from(options: &commands::InteractiveOptions) -> Self {
        Self {
            script: options.script.clone(),
            auto_listen: options.auto_listen,
        }
    }
}

#[cfg(feature = "daemon")]
impl From<&commands::DaemonOptions> for cmd::DaemonRequest {
    fn from(options: &commands::DaemonOptions) -> Self {
        Self {
            rules_file: options.rule_options.rules_file.clone(),
            foreground: options.foreground,
            control_socket: options.control_socket.clone(),
        }
    }
}

#[cfg(feature = "pcap")]
impl From<&commands::ListenCommandOptions> for cmd::ListenRequest {
    fn from(options: &commands::ListenCommandOptions) -> Self {
        Self {
            listen: req::ListenerRequest::from(&options.listen),
            persistent: options.persistent,
        }
    }
}

#[cfg(feature = "traceroute")]
impl From<&commands::TracerouteOptions> for cmd::TracerouteRequest {
    fn from(options: &commands::TracerouteOptions) -> Self {
        Self {
            destination: options.destination.clone(),
            max_ttl: options.max_ttl,
            probes: options.probes,
            protocol: cmd::TracerouteProtocol::from(options.protocol),
            no_dns: options.no_dns,
            timeout: options.timeout,
        }
    }
}

#[cfg(feature = "scan")]
impl From<&commands::ScanCommand> for cmd::ScanRequest {
    fn from(command: &commands::ScanCommand) -> Self {
        match command {
            commands::ScanCommand::TcpSyn(options) => {
                Self::TcpSyn(cmd::PortScanRequest::from(options))
            }
            commands::ScanCommand::TcpFin(options) => {
                Self::TcpFin(cmd::PortScanRequest::from(options))
            }
            commands::ScanCommand::TcpNull(options) => {
                Self::TcpNull(cmd::PortScanRequest::from(options))
            }
            commands::ScanCommand::TcpXmas(options) => {
                Self::TcpXmas(cmd::PortScanRequest::from(options))
            }
            commands::ScanCommand::TcpAck(options) => {
                Self::TcpAck(cmd::PortScanRequest::from(options))
            }
            commands::ScanCommand::SctpInit(options) => {
                Self::SctpInit(cmd::PortScanRequest::from(options))
            }
            commands::ScanCommand::Icmp(options) => {
                Self::Icmp(cmd::TimedScanRequest::from(options))
            }
            commands::ScanCommand::Udp(options) => Self::Udp(cmd::PortScanRequest::from(options)),
            commands::ScanCommand::Arp(options) => Self::Arp(cmd::TimedScanRequest::from(options)),
            commands::ScanCommand::Ndp(options) => Self::Ndp(cmd::TimedScanRequest::from(options)),
        }
    }
}

#[cfg(feature = "scan")]
impl From<&commands::PortScanOptions> for cmd::PortScanRequest {
    fn from(options: &commands::PortScanOptions) -> Self {
        Self {
            target: options.target.clone(),
            ports: options.ports.clone(),
            interface: options.interface.clone(),
            source_ip: options.source_ip.clone(),
        }
    }
}

#[cfg(feature = "scan")]
impl From<&commands::TimedScanOptions> for cmd::TimedScanRequest {
    fn from(options: &commands::TimedScanOptions) -> Self {
        Self {
            target: options.target.clone(),
            interface: options.interface.clone(),
            source_ip: options.source_ip.clone(),
            timeout: options.timeout,
        }
    }
}

#[cfg(feature = "fuzz")]
impl From<&commands::FuzzOptions> for cmd::FuzzRequest {
    fn from(options: &commands::FuzzOptions) -> Self {
        Self {
            target: options.target.clone(),
            port: options.port,
            protocol: cmd::FuzzProtocol::from(options.protocol),
            strategy: cmd::FuzzStrategy::from(options.strategy),
            count: options.count,
            delay: options.delay,
        }
    }
}

impl From<&options::Layer2Options> for req::Layer2Request {
    fn from(options: &options::Layer2Options) -> Self {
        Self {
            source_mac: options.source_mac.clone(),
            destination_mac: options.destination_mac.clone(),
            ethertype: options.ethertype.clone(),
            vlan: req::VlanRequest::from(&options.vlan),
        }
    }
}

impl From<&options::VlanOptions> for req::VlanRequest {
    fn from(options: &options::VlanOptions) -> Self {
        Self {
            id: options.id,
            priority: options.priority,
            drop_eligible_indicator: options.drop_eligible_indicator,
        }
    }
}

impl From<&options::IpOptions> for req::IpRequest {
    fn from(options: &options::IpOptions) -> Self {
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

impl From<&options::IpOptions> for req::Ipv6Request {
    fn from(options: &options::IpOptions) -> Self {
        Self {
            extensions: options.ipv6_extensions.clone(),
        }
    }
}

impl From<&options::TransportOptions> for req::TransportRequest {
    fn from(options: &options::TransportOptions) -> Self {
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

impl From<&options::TransportCommand> for req::TransportProtocolRequest {
    fn from(command: &options::TransportCommand) -> Self {
        match command {
            options::TransportCommand::Tcp(options) => Self::Tcp(req::TcpRequest::from(options)),
            options::TransportCommand::Udp(_) => Self::Udp,
            options::TransportCommand::Icmp(options) => Self::Icmp(req::IcmpRequest::from(options)),
            options::TransportCommand::Icmpv6(options) => {
                Self::Icmpv6(req::Icmpv6Request::from(options))
            }
        }
    }
}

impl From<&options::TcpOptions> for req::TcpRequest {
    fn from(options: &options::TcpOptions) -> Self {
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

impl From<&options::IcmpOptions> for req::IcmpRequest {
    fn from(options: &options::IcmpOptions) -> Self {
        Self {
            kind: options.kind,
            code: options.code,
            identifier: options.identifier,
            sequence: options.sequence,
        }
    }
}

impl From<&options::Icmpv6Options> for req::Icmpv6Request {
    fn from(options: &options::Icmpv6Options) -> Self {
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

impl From<&options::PayloadOptions> for req::PayloadRequest {
    fn from(options: &options::PayloadOptions) -> Self {
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

impl From<&options::TransmitOptions> for req::TransmissionRequest {
    fn from(options: &options::TransmitOptions) -> Self {
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

impl From<&options::ListenOptions> for req::ListenerRequest {
    fn from(options: &options::ListenOptions) -> Self {
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

impl From<&options::LoggingOptions> for req::LoggingRequest {
    fn from(options: &options::LoggingOptions) -> Self {
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

impl From<enums::FragmentProfile> for req::FragmentProfile {
    fn from(profile: enums::FragmentProfile) -> Self {
        match profile {
            enums::FragmentProfile::Overlap => Self::Overlap,
            enums::FragmentProfile::Teardrop => Self::Teardrop,
            enums::FragmentProfile::TinyOverlap => Self::TinyOverlap,
        }
    }
}

impl From<enums::LogLevel> for req::LogLevel {
    fn from(level: enums::LogLevel) -> Self {
        match level {
            enums::LogLevel::Trace => Self::Trace,
            enums::LogLevel::Debug => Self::Debug,
            enums::LogLevel::Info => Self::Info,
            enums::LogLevel::Warn => Self::Warn,
            enums::LogLevel::Error => Self::Error,
        }
    }
}

impl From<enums::Icmpv6ErrorKind> for req::Icmpv6ErrorKind {
    fn from(kind: enums::Icmpv6ErrorKind) -> Self {
        match kind {
            enums::Icmpv6ErrorKind::DestinationUnreachable => Self::DestinationUnreachable,
            enums::Icmpv6ErrorKind::PacketTooBig => Self::PacketTooBig,
            enums::Icmpv6ErrorKind::TimeExceeded => Self::TimeExceeded,
            enums::Icmpv6ErrorKind::ParameterProblem => Self::ParameterProblem,
        }
    }
}

impl From<enums::Icmpv6ErrorCode> for req::Icmpv6ErrorCode {
    fn from(code: enums::Icmpv6ErrorCode) -> Self {
        match code {
            enums::Icmpv6ErrorCode::DestinationUnreachableNoRoute => {
                Self::DestinationUnreachableNoRoute
            }
            enums::Icmpv6ErrorCode::DestinationUnreachableAdminProhibited => {
                Self::DestinationUnreachableAdminProhibited
            }
            enums::Icmpv6ErrorCode::DestinationUnreachableBeyondScope => {
                Self::DestinationUnreachableBeyondScope
            }
            enums::Icmpv6ErrorCode::DestinationUnreachableAddressUnreachable => {
                Self::DestinationUnreachableAddressUnreachable
            }
            enums::Icmpv6ErrorCode::DestinationUnreachablePortUnreachable => {
                Self::DestinationUnreachablePortUnreachable
            }
            enums::Icmpv6ErrorCode::DestinationUnreachableSourcePolicy => {
                Self::DestinationUnreachableSourcePolicy
            }
            enums::Icmpv6ErrorCode::DestinationUnreachableRejectRoute => {
                Self::DestinationUnreachableRejectRoute
            }
            enums::Icmpv6ErrorCode::DestinationUnreachableSourceRoutingError => {
                Self::DestinationUnreachableSourceRoutingError
            }
            enums::Icmpv6ErrorCode::TimeExceededHopLimit => Self::TimeExceededHopLimit,
            enums::Icmpv6ErrorCode::TimeExceededReassembly => Self::TimeExceededReassembly,
            enums::Icmpv6ErrorCode::ParameterProblemErroneousHeader => {
                Self::ParameterProblemErroneousHeader
            }
            enums::Icmpv6ErrorCode::ParameterProblemUnrecognizedNextHeader => {
                Self::ParameterProblemUnrecognizedNextHeader
            }
            enums::Icmpv6ErrorCode::ParameterProblemUnrecognizedOption => {
                Self::ParameterProblemUnrecognizedOption
            }
        }
    }
}

#[cfg(feature = "traceroute")]
impl From<commands::TracerouteProtocol> for cmd::TracerouteProtocol {
    fn from(protocol: commands::TracerouteProtocol) -> Self {
        match protocol {
            commands::TracerouteProtocol::Udp => Self::Udp,
            commands::TracerouteProtocol::Tcp => Self::Tcp,
            commands::TracerouteProtocol::Icmp => Self::Icmp,
        }
    }
}

#[cfg(feature = "fuzz")]
impl From<commands::FuzzProtocol> for cmd::FuzzProtocol {
    fn from(protocol: commands::FuzzProtocol) -> Self {
        match protocol {
            commands::FuzzProtocol::Tcp => Self::Tcp,
            commands::FuzzProtocol::Udp => Self::Udp,
            commands::FuzzProtocol::Icmp => Self::Icmp,
        }
    }
}

#[cfg(feature = "fuzz")]
impl From<commands::FuzzStrategy> for cmd::FuzzStrategy {
    fn from(strategy: commands::FuzzStrategy) -> Self {
        match strategy {
            commands::FuzzStrategy::BitFlip => Self::BitFlip,
            commands::FuzzStrategy::ByteSwap => Self::ByteSwap,
            commands::FuzzStrategy::RandomPayload => Self::RandomPayload,
            commands::FuzzStrategy::Boundary => Self::Boundary,
        }
    }
}
