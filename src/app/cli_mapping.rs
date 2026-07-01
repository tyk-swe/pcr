// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::cli::commands::PacketcraftCommand;
use crate::cli::enums::OutputFormat as CliOutputFormat;
use crate::cli::options::{OneShotOptions, TransportCommand};
use crate::cli::PacketcraftArgs;
#[cfg(feature = "daemon")]
use crate::domain::command::DaemonRequest;
#[cfg(feature = "fuzz")]
use crate::domain::command::FuzzRequest;
#[cfg(feature = "repl")]
use crate::domain::command::InteractiveRequest;
#[cfg(feature = "pcap")]
use crate::domain::command::ListenRequest;
#[cfg(feature = "scan")]
use crate::domain::command::ScanRequest;
#[cfg(feature = "traceroute")]
use crate::domain::command::TracerouteRequest;
use crate::domain::command::{DnsRequest, EngineCommand};
use crate::domain::policy::{TrafficBudget, TrafficPolicy};
use crate::domain::request::PacketRequest;
use crate::engine::config::EngineConfig;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum CliMappingError {
    #[error("compact target conflicts with {option}")]
    CompactTargetConflict { option: &'static str },
    #[error("{protocol} target '{target}' must include a destination port or use --dport")]
    CompactTargetMissingPort {
        protocol: &'static str,
        target: String,
    },
    #[error("compact target port {target_port} conflicts with --dport {explicit_port}")]
    CompactTargetPortConflict {
        target_port: u16,
        explicit_port: u16,
    },
    #[error("{protocol} target '{target}' must not include a port")]
    CompactTargetUnexpectedPort {
        protocol: &'static str,
        target: String,
    },
    #[error("compact target '{target}' is malformed")]
    CompactTargetMalformed { target: String },
    #[error("DNS query requires a domain")]
    DnsQueryInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompactTarget {
    host: String,
    port: Option<u16>,
}

pub(crate) fn normalize_send_options(
    options: &crate::cli::options::SendOptions,
) -> Result<PacketRequest, CliMappingError> {
    normalize_one_shot_options(&options.oneshot)
}

pub(crate) fn normalize_dns_query_options(
    options: &crate::cli::commands::DnsQueryOptions,
) -> Result<DnsRequest, CliMappingError> {
    let Some(domain) = options
        .domain_name()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err(CliMappingError::DnsQueryInvalid);
    };

    Ok(DnsRequest {
        domain: domain.to_string(),
        record_type: options.record_type.clone(),
        server: options.server.clone(),
        timeout: options.timeout,
        transaction_id: options.transaction_id,
        transport: options.transport,
        retries: options.retries,
    })
}

pub(crate) fn normalize_one_shot_options(
    options: &OneShotOptions,
) -> Result<PacketRequest, CliMappingError> {
    let mut request = PacketRequest::from(options);
    apply_compact_target(options, &mut request)?;
    Ok(request)
}

fn apply_compact_target(
    options: &OneShotOptions,
    request: &mut PacketRequest,
) -> Result<(), CliMappingError> {
    let Some((protocol, target)) = compact_target(&options.transport.command) else {
        return Ok(());
    };

    if options.destination.is_some() {
        return Err(CliMappingError::CompactTargetConflict { option: "--dest" });
    }
    if options.ip.destination_ip.is_some() {
        return Err(CliMappingError::CompactTargetConflict { option: "--dip" });
    }

    let parsed = parse_compact_target(target)?;
    request.destination.destination = Some(parsed.host.clone());

    match protocol {
        "tcp" | "udp" => match (parsed.port, options.transport.destination_port) {
            (Some(target_port), Some(explicit_port)) if target_port != explicit_port => {
                return Err(CliMappingError::CompactTargetPortConflict {
                    target_port,
                    explicit_port,
                });
            }
            (Some(port), _) => request.transport.destination_port = Some(port),
            (None, None) => {
                return Err(CliMappingError::CompactTargetMissingPort {
                    protocol,
                    target: target.to_string(),
                });
            }
            (None, Some(_)) => {}
        },
        "icmp" | "icmpv6" if parsed.port.is_some() => {
            return Err(CliMappingError::CompactTargetUnexpectedPort {
                protocol,
                target: target.to_string(),
            });
        }
        _ => {}
    }

    Ok(())
}

fn compact_target(command: &Option<TransportCommand>) -> Option<(&'static str, &str)> {
    match command.as_ref()? {
        TransportCommand::Tcp(options) => options.target.as_deref().map(|target| ("tcp", target)),
        TransportCommand::Udp(options) => options.target.as_deref().map(|target| ("udp", target)),
        TransportCommand::Icmp(options) => options.target.as_deref().map(|target| ("icmp", target)),
        TransportCommand::Icmpv6(options) => {
            options.target.as_deref().map(|target| ("icmpv6", target))
        }
    }
}

#[cfg(feature = "repl")]
pub(crate) fn transport_has_compact_target(command: &Option<TransportCommand>) -> bool {
    compact_target(command).is_some()
}

#[cfg(feature = "repl")]
pub(crate) fn transport_compact_target_has_port(
    command: &Option<TransportCommand>,
) -> Result<bool, CliMappingError> {
    let Some((_, target)) = compact_target(command) else {
        return Ok(false);
    };

    Ok(parse_compact_target(target)?.port.is_some())
}

fn parse_compact_target(raw: &str) -> Result<CompactTarget, CliMappingError> {
    let target = raw.trim();
    if let Some(rest) = target.strip_prefix('[') {
        if let Some((host, suffix)) = rest.split_once(']') {
            if host.trim().is_empty() {
                return Err(CliMappingError::CompactTargetMalformed {
                    target: target.to_string(),
                });
            }
            if suffix.is_empty() {
                return Ok(CompactTarget {
                    host: host.to_string(),
                    port: None,
                });
            }
            if let Some(raw_port) = suffix.strip_prefix(':') {
                let Some(port) = parse_port(raw_port) else {
                    return Err(CliMappingError::CompactTargetMalformed {
                        target: target.to_string(),
                    });
                };
                return Ok(CompactTarget {
                    host: host.to_string(),
                    port: Some(port),
                });
            }
            return Err(CliMappingError::CompactTargetMalformed {
                target: target.to_string(),
            });
        }
        return Err(CliMappingError::CompactTargetMalformed {
            target: target.to_string(),
        });
    }

    if target.parse::<std::net::IpAddr>().is_ok() {
        return Ok(CompactTarget {
            host: target.to_string(),
            port: None,
        });
    }

    if target.matches(':').count() == 1 {
        if let Some((host, port)) = target.rsplit_once(':') {
            if let Some(port) = parse_port(port) {
                return Ok(CompactTarget {
                    host: host.to_string(),
                    port: Some(port),
                });
            }
        }
    }

    Ok(CompactTarget {
        host: target.to_string(),
        port: None,
    })
}

fn parse_port(raw: &str) -> Option<u16> {
    raw.parse().ok()
}

impl PacketcraftArgs {
    pub(crate) fn engine_config(&self) -> EngineConfig {
        let rule_options = match &self.command {
            #[cfg(feature = "daemon")]
            PacketcraftCommand::Daemon(opts) => Some(&opts.rule_options),
            _ => self.one_shot_options().map(|options| &options.rule),
        };
        let logging_options = self.one_shot_options().map(|options| &options.logging);

        let mut budget = TrafficBudget::default();
        if let Some(value) = self.safety.traffic_max_targets {
            budget.max_targets = value;
        }
        if let Some(value) = self.safety.traffic_max_ports {
            budget.max_ports = value;
        }
        if let Some(value) = self.safety.traffic_max_packets {
            budget.max_estimated_packets = value;
        }
        if let Some(value) = self.safety.traffic_batch_size {
            budget.max_batch_size = value;
        }
        if let Some(value) = self.safety.traffic_rate {
            budget.max_rate_per_sec = value;
        }

        let traffic_policy = TrafficPolicy {
            allow_public_targets: self.safety.allow_public_targets,
            allow_malformed: self.safety.allow_malformed,
            allow_high_volume: self.safety.allow_high_volume,
            allow_unbounded_sends: rule_options
                .map(|options| options.allow_unbounded_sends)
                .unwrap_or(false),
            dry_run: self.effective_dry_run(),
            budget,
        };

        EngineConfig {
            prometheus_bind: logging_options.and_then(|options| options.prometheus_bind.clone()),
            rule_workers: rule_options.and_then(|options| options.rule_workers),
            rule_queue: rule_options.and_then(|options| options.rule_queue),
            send_workers: rule_options.and_then(|options| options.send_workers),
            send_queue: rule_options.and_then(|options| options.send_queue),
            traffic_policy,
            dry_run: self.effective_dry_run(),
        }
    }

    pub(crate) fn try_engine_command(&self) -> Result<EngineCommand, CliMappingError> {
        match &self.command {
            PacketcraftCommand::Send(options) => {
                Ok(EngineCommand::Send(normalize_send_options(options)?))
            }
            PacketcraftCommand::DryRun(options) => {
                Ok(EngineCommand::DryRun(normalize_send_options(options)?))
            }
            #[cfg(feature = "repl")]
            PacketcraftCommand::Interactive(options) => Ok(EngineCommand::Interactive(
                InteractiveRequest::from(options),
            )),
            #[cfg(feature = "daemon")]
            PacketcraftCommand::Daemon(options) => {
                Ok(EngineCommand::Daemon(DaemonRequest::from(options)))
            }
            #[cfg(feature = "pcap")]
            PacketcraftCommand::Listen(options) => {
                Ok(EngineCommand::Listen(ListenRequest::from(options)))
            }
            #[cfg(feature = "traceroute")]
            PacketcraftCommand::Traceroute(options) => {
                Ok(EngineCommand::Traceroute(TracerouteRequest::from(options)))
            }
            #[cfg(feature = "scan")]
            PacketcraftCommand::Scan(command) => {
                Ok(EngineCommand::Scan(ScanRequest::from(command)))
            }
            PacketcraftCommand::Dns(command) => match command {
                crate::cli::commands::DnsCommand::Query(options) => Ok(EngineCommand::DnsQuery(
                    normalize_dns_query_options(options)?,
                )),
            },
            PacketcraftCommand::DnsQuery(options) => Ok(EngineCommand::DnsQuery(
                normalize_dns_query_options(options)?,
            )),
            PacketcraftCommand::Doctor(options) => Ok(EngineCommand::Doctor(
                crate::domain::command::DoctorRequest::from(options),
            )),
            PacketcraftCommand::Features(options) => Ok(EngineCommand::Features(
                crate::domain::command::FeatureRequest::from(options),
            )),
            PacketcraftCommand::Examples(options) => Ok(EngineCommand::Examples(
                crate::domain::command::ExamplesRequest::from(options),
            )),
            PacketcraftCommand::Completions(options) => Ok(EngineCommand::Completions(
                crate::domain::command::CompletionsRequest::from(options),
            )),
            PacketcraftCommand::Man => Ok(EngineCommand::Man),
            #[cfg(feature = "fuzz")]
            PacketcraftCommand::Fuzz(options) => {
                Ok(EngineCommand::Fuzz(FuzzRequest::from(options)))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn engine_command(&self) -> EngineCommand {
        self.try_engine_command()
            .expect("test helper received invalid CLI mapping input")
    }
}

impl From<CliOutputFormat> for crate::output::OutputFormat {
    fn from(format: CliOutputFormat) -> Self {
        match format {
            CliOutputFormat::Summary => Self::Summary,
            CliOutputFormat::Detailed => Self::Detailed,
            CliOutputFormat::Hex => Self::Hex,
            CliOutputFormat::Json => Self::Json,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{commands, options};
    use crate::domain::command::{DnsTransportMode, EngineCommand};
    use crate::domain::request::TransportProtocolRequest;
    use crate::output::OutputFormat;
    use clap::Parser;

    fn args(command: PacketcraftCommand, dry_run: bool) -> PacketcraftArgs {
        PacketcraftArgs {
            verbose: 0,
            output_format: None,
            dry_run,
            safety: options::SafetyOptions::default(),
            command,
        }
    }

    fn parse_cli(args: &[&str]) -> PacketcraftArgs {
        PacketcraftArgs::parse_from(std::iter::once("packetcraftr").chain(args.iter().copied()))
    }

    #[test]
    fn engine_config_maps_safety_budget_and_one_shot_rule_options() {
        let mut args = args(
            PacketcraftCommand::Send(options::SendOptions {
                oneshot: options::OneShotOptions {
                    rule: options::RuleOptions {
                        rule_workers: Some(2),
                        rule_queue: Some(3),
                        send_workers: Some(4),
                        send_queue: Some(5),
                        allow_unbounded_sends: true,
                        ..Default::default()
                    },
                    logging: options::LoggingOptions {
                        prometheus_bind: Some("127.0.0.1:9090".to_string()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            }),
            false,
        );
        args.safety.allow_public_targets = true;
        args.safety.allow_malformed = true;
        args.safety.allow_high_volume = true;
        args.safety.traffic_max_targets = Some(11);
        args.safety.traffic_max_ports = Some(12);
        args.safety.traffic_max_packets = Some(13);
        args.safety.traffic_batch_size = Some(14);
        args.safety.traffic_rate = Some(15);

        let config = args.engine_config();

        assert_eq!(config.prometheus_bind.as_deref(), Some("127.0.0.1:9090"));
        assert_eq!(config.rule_workers, Some(2));
        assert_eq!(config.rule_queue, Some(3));
        assert_eq!(config.send_workers, Some(4));
        assert_eq!(config.send_queue, Some(5));
        assert!(config.traffic_policy.allow_public_targets);
        assert!(config.traffic_policy.allow_malformed);
        assert!(config.traffic_policy.allow_high_volume);
        assert!(config.traffic_policy.allow_unbounded_sends);
        assert_eq!(config.traffic_policy.budget.max_targets, 11);
        assert_eq!(config.traffic_policy.budget.max_ports, 12);
        assert_eq!(config.traffic_policy.budget.max_estimated_packets, 13);
        assert_eq!(config.traffic_policy.budget.max_batch_size, 14);
        assert_eq!(config.traffic_policy.budget.max_rate_per_sec, 15);
        assert!(!config.dry_run);
    }

    #[test]
    fn engine_config_marks_dry_run_for_global_flag_or_subcommand() {
        let global = args(
            PacketcraftCommand::Send(options::SendOptions::default()),
            true,
        )
        .engine_config();
        let subcommand = args(
            PacketcraftCommand::DryRun(options::SendOptions::default()),
            false,
        )
        .engine_config();

        assert!(global.dry_run);
        assert!(global.traffic_policy.dry_run);
        assert!(subcommand.dry_run);
        assert!(subcommand.traffic_policy.dry_run);
    }

    #[test]
    fn engine_command_maps_send_and_dry_run_requests() {
        let send = args(
            PacketcraftCommand::Send(options::SendOptions {
                oneshot: options::OneShotOptions {
                    destination: Some("127.0.0.1".to_string()),
                    ..Default::default()
                },
            }),
            false,
        )
        .engine_command();
        let dry_run = args(
            PacketcraftCommand::DryRun(options::SendOptions {
                oneshot: options::OneShotOptions {
                    destination: Some("localhost".to_string()),
                    ..Default::default()
                },
            }),
            false,
        )
        .engine_command();

        assert!(matches!(
            send,
            EngineCommand::Send(request)
                if request.destination.destination.as_deref() == Some("127.0.0.1")
        ));
        assert!(matches!(
            dry_run,
            EngineCommand::DryRun(request)
                if request.destination.destination.as_deref() == Some("localhost")
        ));
    }

    #[test]
    fn plan_and_dry_run_alias_map_to_plan_mode_command() {
        let plan = parse_cli(&["plan", "udp", "127.0.0.1:9", "--data", "hello"])
            .try_engine_command()
            .unwrap();
        let dry_run = parse_cli(&[
            "dry-run",
            "-d",
            "127.0.0.1",
            "--data",
            "hello",
            "udp",
            "--dport",
            "9",
        ])
        .try_engine_command()
        .unwrap();

        assert!(matches!(
            plan,
            EngineCommand::DryRun(request)
                if request.destination.destination.as_deref() == Some("127.0.0.1")
                    && request.transport.destination_port == Some(9)
        ));
        assert!(matches!(
            dry_run,
            EngineCommand::DryRun(request)
                if request.destination.destination.as_deref() == Some("127.0.0.1")
                    && request.transport.destination_port == Some(9)
        ));
    }

    #[test]
    fn compact_tcp_and_udp_targets_normalize_destination_and_port() {
        let udp = parse_cli(&["plan", "udp", "127.0.0.1:9", "--data", "hello"])
            .try_engine_command()
            .unwrap();
        let tcp = parse_cli(&["send", "tcp", "[::1]:443", "--flags", "syn"])
            .try_engine_command()
            .unwrap();

        assert!(matches!(
            udp,
            EngineCommand::DryRun(request)
                if request.destination.destination.as_deref() == Some("127.0.0.1")
                    && request.transport.destination_port == Some(9)
                    && matches!(request.transport.command, Some(TransportProtocolRequest::Udp))
        ));
        assert!(matches!(
            tcp,
            EngineCommand::Send(request)
                if request.destination.destination.as_deref() == Some("::1")
                    && request.transport.destination_port == Some(443)
                    && matches!(request.transport.command, Some(TransportProtocolRequest::Tcp(_)))
        ));
    }

    #[test]
    fn compact_target_conflicts_and_missing_ports_are_mapping_errors() {
        let conflict = parse_cli(&["plan", "-d", "127.0.0.1", "udp", "localhost:9"])
            .try_engine_command()
            .unwrap_err();
        let missing_port = parse_cli(&["plan", "udp", "localhost"])
            .try_engine_command()
            .unwrap_err();
        let port_conflict = parse_cli(&["plan", "udp", "localhost:9", "--dport", "10"])
            .try_engine_command()
            .unwrap_err();

        assert!(matches!(
            conflict,
            CliMappingError::CompactTargetConflict { option: "--dest" }
        ));
        assert!(matches!(
            missing_port,
            CliMappingError::CompactTargetMissingPort {
                protocol: "udp",
                ..
            }
        ));
        assert!(matches!(
            port_conflict,
            CliMappingError::CompactTargetPortConflict {
                target_port: 9,
                explicit_port: 10
            }
        ));
    }

    #[test]
    fn malformed_bracketed_compact_targets_are_mapping_errors() {
        let tcp_bad_port = parse_cli(&["plan", "tcp", "[::1]:bogus", "--dport", "443"])
            .try_engine_command()
            .unwrap_err();
        let icmpv6_bad_suffix = parse_cli(&["plan", "icmpv6", "[::1]:bogus"])
            .try_engine_command()
            .unwrap_err();
        let missing_close = parse_cli(&["plan", "tcp", "[::1", "--dport", "443"])
            .try_engine_command()
            .unwrap_err();

        assert!(matches!(
            tcp_bad_port,
            CliMappingError::CompactTargetMalformed { .. }
        ));
        assert!(matches!(
            icmpv6_bad_suffix,
            CliMappingError::CompactTargetMalformed { .. }
        ));
        assert!(matches!(
            missing_close,
            CliMappingError::CompactTargetMalformed { .. }
        ));
    }

    #[test]
    fn dns_query_and_legacy_dns_query_map_identically() {
        let nested = parse_cli(&["dns", "query", "example.test", "--type", "AAAA"])
            .try_engine_command()
            .unwrap();
        let legacy = parse_cli(&["dns-query", "--domain", "example.test", "--type", "AAAA"])
            .try_engine_command()
            .unwrap();

        assert!(matches!(
            (&nested, &legacy),
            (EngineCommand::DnsQuery(a), EngineCommand::DnsQuery(b))
                if a.domain == b.domain && a.record_type == b.record_type
        ));
    }

    #[test]
    fn engine_command_maps_dns_query_options() {
        let command = args(
            PacketcraftCommand::DnsQuery(commands::DnsQueryOptions {
                domain: Some("example.test".to_string()),
                domain_option: None,
                record_type: "AAAA".to_string(),
                server: "1.1.1.1".to_string(),
                timeout: 250,
                transaction_id: Some(42),
                transport: DnsTransportMode::Tcp,
                retries: 2,
            }),
            false,
        )
        .engine_command();

        assert!(matches!(
            command,
            EngineCommand::DnsQuery(request)
                if request.domain == "example.test"
                    && request.record_type == "AAAA"
                    && request.server == "1.1.1.1"
                    && request.timeout == 250
                    && request.transaction_id == Some(42)
                    && request.transport == DnsTransportMode::Tcp
                    && request.retries == 2
        ));
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn engine_command_maps_listen_options() {
        let command = args(
            PacketcraftCommand::Listen(commands::ListenCommandOptions {
                listen: options::ListenOptions {
                    listen: Some(true),
                    filter: Some("icmp".to_string()),
                    queue_capacity: Some(128),
                    ..Default::default()
                },
                persistent: Some(true),
            }),
            false,
        )
        .engine_command();

        assert!(matches!(
            command,
            EngineCommand::Listen(request)
                if request.listen.listen == Some(true)
                    && request.listen.filter.as_deref() == Some("icmp")
                    && request.listen.queue_capacity == Some(128)
                    && request.persistent == Some(true)
        ));
    }

    #[cfg(feature = "daemon")]
    #[test]
    fn engine_command_maps_daemon_options() {
        let command = args(
            PacketcraftCommand::Daemon(commands::DaemonOptions {
                rule_options: options::RuleOptions {
                    rules_file: Some("rules.yml".to_string()),
                    ..Default::default()
                },
                foreground: Some(true),
                control_socket: Some("/tmp/packetcraftr.sock".to_string()),
            }),
            false,
        )
        .engine_command();

        assert!(matches!(
            command,
            EngineCommand::Daemon(request)
                if request.rules_file.as_deref() == Some("rules.yml")
                    && request.foreground == Some(true)
                    && request.control_socket.as_deref() == Some("/tmp/packetcraftr.sock")
        ));
    }

    #[cfg(feature = "repl")]
    #[test]
    fn engine_command_maps_interactive_options() {
        let command = args(
            PacketcraftCommand::Interactive(commands::InteractiveOptions {
                script: Some("session.pcr".to_string()),
                auto_listen: Some(true),
            }),
            false,
        )
        .engine_command();

        assert!(matches!(
            command,
            EngineCommand::Interactive(request)
                if request.script.as_deref() == Some("session.pcr")
                    && request.auto_listen == Some(true)
        ));
    }

    #[cfg(feature = "traceroute")]
    #[test]
    fn engine_command_maps_traceroute_options() {
        let command = args(
            PacketcraftCommand::Traceroute(commands::TracerouteOptions {
                destination: "example.test".to_string(),
                max_ttl: 16,
                probes: 2,
                protocol: commands::TracerouteProtocol::Icmp,
                no_dns: Some(true),
                timeout: 750,
            }),
            false,
        )
        .engine_command();

        assert!(matches!(
            command,
            EngineCommand::Traceroute(request)
                if request.destination == "example.test"
                    && request.max_ttl == 16
                    && request.probes == 2
                    && request.protocol == crate::domain::command::TracerouteProtocol::Icmp
                    && request.no_dns == Some(true)
                    && request.timeout == 750
        ));
    }

    #[cfg(feature = "scan")]
    #[test]
    fn engine_command_maps_scan_options() {
        let command = args(
            PacketcraftCommand::Scan(commands::ScanCommand::TcpSyn(commands::PortScanOptions {
                target: "192.0.2.1".to_string(),
                ports: "22,80".to_string(),
                interface: Some("eth0".to_string()),
                source_ip: Some("192.0.2.10".to_string()),
            })),
            false,
        )
        .engine_command();

        assert!(matches!(
            command,
            EngineCommand::Scan(crate::domain::command::ScanRequest::TcpSyn(request))
                if request.target == "192.0.2.1"
                    && request.ports == "22,80"
                    && request.interface.as_deref() == Some("eth0")
                    && request.source_ip.as_deref() == Some("192.0.2.10")
        ));
    }

    #[cfg(feature = "fuzz")]
    #[test]
    fn engine_command_maps_fuzz_options() {
        let command = args(
            PacketcraftCommand::Fuzz(commands::FuzzOptions {
                target: "192.0.2.1".to_string(),
                port: Some(443),
                protocol: commands::FuzzProtocol::Tcp,
                strategy: commands::FuzzStrategy::BitFlip,
                count: 5,
                delay: 25,
            }),
            false,
        )
        .engine_command();

        assert!(matches!(
            command,
            EngineCommand::Fuzz(request)
                if request.target == "192.0.2.1"
                    && request.port == Some(443)
                    && request.protocol == crate::domain::command::FuzzProtocol::Tcp
                    && request.strategy == crate::domain::command::FuzzStrategy::BitFlip
                    && request.count == 5
                    && request.delay == 25
        ));
    }

    #[test]
    fn output_format_mapping_preserves_all_variants() {
        assert!(matches!(
            OutputFormat::from(CliOutputFormat::Summary),
            OutputFormat::Summary
        ));
        assert!(matches!(
            OutputFormat::from(CliOutputFormat::Detailed),
            OutputFormat::Detailed
        ));
        assert!(matches!(
            OutputFormat::from(CliOutputFormat::Hex),
            OutputFormat::Hex
        ));
        assert!(matches!(
            OutputFormat::from(CliOutputFormat::Json),
            OutputFormat::Json
        ));
    }
}
