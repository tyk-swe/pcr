// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::{cli_commands, cmd};

#[cfg(feature = "pcap")]
use super::req;

impl From<&cli_commands::DnsQueryOptions> for cmd::DnsRequest {
    fn from(options: &cli_commands::DnsQueryOptions) -> Self {
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
impl From<&cli_commands::InteractiveOptions> for cmd::InteractiveRequest {
    fn from(options: &cli_commands::InteractiveOptions) -> Self {
        Self {
            script: options.script.clone(),
            auto_listen: options.auto_listen,
        }
    }
}

#[cfg(feature = "daemon")]
impl From<&cli_commands::DaemonOptions> for cmd::DaemonRequest {
    fn from(options: &cli_commands::DaemonOptions) -> Self {
        Self {
            rules_file: options.rule_options.rules_file.clone(),
            foreground: options.foreground,
            control_socket: options.control_socket.clone(),
        }
    }
}

#[cfg(feature = "pcap")]
impl From<&cli_commands::ListenCommandOptions> for cmd::ListenRequest {
    fn from(options: &cli_commands::ListenCommandOptions) -> Self {
        Self {
            listen: req::ListenerRequest::from(&options.listen),
            persistent: options.persistent,
        }
    }
}

#[cfg(feature = "traceroute")]
impl From<&cli_commands::TracerouteOptions> for cmd::TracerouteRequest {
    fn from(options: &cli_commands::TracerouteOptions) -> Self {
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
impl From<&cli_commands::ScanCommand> for cmd::ScanRequest {
    fn from(command: &cli_commands::ScanCommand) -> Self {
        match command {
            cli_commands::ScanCommand::TcpSyn(options) => {
                Self::TcpSyn(cmd::PortScanRequest::from(options))
            }
            cli_commands::ScanCommand::TcpFin(options) => {
                Self::TcpFin(cmd::PortScanRequest::from(options))
            }
            cli_commands::ScanCommand::TcpNull(options) => {
                Self::TcpNull(cmd::PortScanRequest::from(options))
            }
            cli_commands::ScanCommand::TcpXmas(options) => {
                Self::TcpXmas(cmd::PortScanRequest::from(options))
            }
            cli_commands::ScanCommand::TcpAck(options) => {
                Self::TcpAck(cmd::PortScanRequest::from(options))
            }
            cli_commands::ScanCommand::SctpInit(options) => {
                Self::SctpInit(cmd::PortScanRequest::from(options))
            }
            cli_commands::ScanCommand::Icmp(options) => {
                Self::Icmp(cmd::TimedScanRequest::from(options))
            }
            cli_commands::ScanCommand::Udp(options) => {
                Self::Udp(cmd::PortScanRequest::from(options))
            }
            cli_commands::ScanCommand::Arp(options) => {
                Self::Arp(cmd::TimedScanRequest::from(options))
            }
            cli_commands::ScanCommand::Ndp(options) => {
                Self::Ndp(cmd::TimedScanRequest::from(options))
            }
        }
    }
}

#[cfg(feature = "scan")]
impl From<&cli_commands::PortScanOptions> for cmd::PortScanRequest {
    fn from(options: &cli_commands::PortScanOptions) -> Self {
        Self {
            target: options.target.clone(),
            ports: options.ports.clone(),
            interface: options.interface.clone(),
            source_ip: options.source_ip.clone(),
        }
    }
}

#[cfg(feature = "scan")]
impl From<&cli_commands::TimedScanOptions> for cmd::TimedScanRequest {
    fn from(options: &cli_commands::TimedScanOptions) -> Self {
        Self {
            target: options.target.clone(),
            interface: options.interface.clone(),
            source_ip: options.source_ip.clone(),
            timeout: options.timeout,
        }
    }
}

#[cfg(feature = "fuzz")]
impl From<&cli_commands::FuzzOptions> for cmd::FuzzRequest {
    fn from(options: &cli_commands::FuzzOptions) -> Self {
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

#[cfg(test)]
mod tests {
    use crate::cli::commands as cli_commands;
    use crate::domain::command as cmd;
    use crate::domain::command::DnsTransportMode;

    #[test]
    fn dns_query_options_map_all_fields() {
        let request = cmd::DnsRequest::from(&cli_commands::DnsQueryOptions {
            domain: "example.test".to_string(),
            record_type: "TXT".to_string(),
            server: "9.9.9.9".to_string(),
            timeout: 750,
            transaction_id: Some(7),
            transport: DnsTransportMode::Udp,
            retries: 4,
        });

        assert_eq!(request.domain, "example.test");
        assert_eq!(request.record_type, "TXT");
        assert_eq!(request.server, "9.9.9.9");
        assert_eq!(request.timeout, 750);
        assert_eq!(request.transaction_id, Some(7));
        assert_eq!(request.transport, DnsTransportMode::Udp);
        assert_eq!(request.retries, 4);
    }

    #[cfg(feature = "scan")]
    #[test]
    fn scan_command_maps_port_and_timed_variants() {
        let port = cli_commands::PortScanOptions {
            target: "192.0.2.1".to_string(),
            ports: "80,443".to_string(),
            interface: Some("eth0".to_string()),
            source_ip: Some("192.0.2.10".to_string()),
        };
        let timed = cli_commands::TimedScanOptions {
            target: "192.0.2.0/30".to_string(),
            interface: Some("eth1".to_string()),
            source_ip: Some("192.0.2.11".to_string()),
            timeout: 500,
        };

        let tcp = cmd::ScanRequest::from(&cli_commands::ScanCommand::TcpSyn(port.clone()));
        let arp = cmd::ScanRequest::from(&cli_commands::ScanCommand::Arp(timed.clone()));

        assert!(matches!(
            tcp,
            cmd::ScanRequest::TcpSyn(request)
                if request.target == "192.0.2.1"
                    && request.ports == "80,443"
                    && request.interface.as_deref() == Some("eth0")
                    && request.source_ip.as_deref() == Some("192.0.2.10")
        ));
        assert!(matches!(
            arp,
            cmd::ScanRequest::Arp(request)
                if request.target == "192.0.2.0/30"
                    && request.interface.as_deref() == Some("eth1")
                    && request.source_ip.as_deref() == Some("192.0.2.11")
                    && request.timeout == 500
        ));

        assert!(matches!(
            cmd::ScanRequest::from(&cli_commands::ScanCommand::TcpFin(port.clone())),
            cmd::ScanRequest::TcpFin(request)
                if request.target == "192.0.2.1" && request.ports == "80,443"
        ));
        assert!(matches!(
            cmd::ScanRequest::from(&cli_commands::ScanCommand::TcpNull(port.clone())),
            cmd::ScanRequest::TcpNull(request)
                if request.target == "192.0.2.1" && request.ports == "80,443"
        ));
        assert!(matches!(
            cmd::ScanRequest::from(&cli_commands::ScanCommand::TcpXmas(port.clone())),
            cmd::ScanRequest::TcpXmas(request)
                if request.target == "192.0.2.1" && request.ports == "80,443"
        ));
        assert!(matches!(
            cmd::ScanRequest::from(&cli_commands::ScanCommand::TcpAck(port.clone())),
            cmd::ScanRequest::TcpAck(request)
                if request.target == "192.0.2.1" && request.ports == "80,443"
        ));
        assert!(matches!(
            cmd::ScanRequest::from(&cli_commands::ScanCommand::SctpInit(port.clone())),
            cmd::ScanRequest::SctpInit(request)
                if request.target == "192.0.2.1" && request.ports == "80,443"
        ));
        assert!(matches!(
            cmd::ScanRequest::from(&cli_commands::ScanCommand::Udp(port)),
            cmd::ScanRequest::Udp(request)
                if request.target == "192.0.2.1" && request.ports == "80,443"
        ));
        assert!(matches!(
            cmd::ScanRequest::from(&cli_commands::ScanCommand::Icmp(timed.clone())),
            cmd::ScanRequest::Icmp(request)
                if request.target == "192.0.2.0/30" && request.timeout == 500
        ));
        assert!(matches!(
            cmd::ScanRequest::from(&cli_commands::ScanCommand::Ndp(timed)),
            cmd::ScanRequest::Ndp(request)
                if request.target == "192.0.2.0/30" && request.timeout == 500
        ));
    }

    #[cfg(feature = "traceroute")]
    #[test]
    fn traceroute_options_map_protocol_and_controls() {
        let request = cmd::TracerouteRequest::from(&cli_commands::TracerouteOptions {
            destination: "example.test".to_string(),
            max_ttl: 12,
            probes: 3,
            protocol: cli_commands::TracerouteProtocol::Tcp,
            no_dns: Some(true),
            timeout: 2000,
        });

        assert_eq!(request.destination, "example.test");
        assert_eq!(request.max_ttl, 12);
        assert_eq!(request.probes, 3);
        assert_eq!(request.protocol, cmd::TracerouteProtocol::Tcp);
        assert_eq!(request.no_dns, Some(true));
        assert_eq!(request.timeout, 2000);
    }

    #[cfg(feature = "fuzz")]
    #[test]
    fn fuzz_options_map_protocol_strategy_and_limits() {
        let request = cmd::FuzzRequest::from(&cli_commands::FuzzOptions {
            target: "192.0.2.1".to_string(),
            port: Some(53),
            protocol: cli_commands::FuzzProtocol::Udp,
            strategy: cli_commands::FuzzStrategy::Boundary,
            count: 10,
            delay: 20,
        });

        assert_eq!(request.target, "192.0.2.1");
        assert_eq!(request.port, Some(53));
        assert_eq!(request.protocol, cmd::FuzzProtocol::Udp);
        assert_eq!(request.strategy, cmd::FuzzStrategy::Boundary);
        assert_eq!(request.count, 10);
        assert_eq!(request.delay, 20);
    }
}
