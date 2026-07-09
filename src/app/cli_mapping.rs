// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::cli::commands::PacketcraftCommand;
use crate::cli::enums::OutputFormat as CliOutputFormat;
use crate::cli::options::OneShotOptions;
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
use crate::domain::request::{LoggingRequest, PacketRequest};
use crate::engine::config::EngineConfig;

impl PacketcraftArgs {
    pub(crate) fn engine_config(&self) -> EngineConfig {
        let rule_options = match &self.command {
            #[cfg(feature = "daemon")]
            PacketcraftCommand::Daemon(opts) => Some(&opts.rule_options),
            _ => self.one_shot_options().map(|options| &options.rule),
        };

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
            prometheus_bind: self.observability.prometheus_bind.clone(),
            rule_workers: rule_options.and_then(|options| options.rule_workers),
            rule_queue: rule_options.and_then(|options| options.rule_queue),
            send_workers: rule_options.and_then(|options| options.send_workers),
            send_queue: rule_options.and_then(|options| options.send_queue),
            traffic_policy,
            dry_run: self.effective_dry_run(),
        }
    }

    pub(crate) fn engine_command(&self) -> EngineCommand {
        match &self.command {
            PacketcraftCommand::Send(options) => {
                EngineCommand::Send(self.packet_request(&options.oneshot))
            }
            PacketcraftCommand::DryRun(options) => {
                EngineCommand::DryRun(self.packet_request(&options.oneshot))
            }
            #[cfg(feature = "repl")]
            PacketcraftCommand::Interactive(options) => {
                EngineCommand::Interactive(InteractiveRequest::from(options))
            }
            #[cfg(feature = "daemon")]
            PacketcraftCommand::Daemon(options) => {
                EngineCommand::Daemon(DaemonRequest::from(options))
            }
            #[cfg(feature = "pcap")]
            PacketcraftCommand::Listen(options) => {
                EngineCommand::Listen(ListenRequest::from(options))
            }
            #[cfg(feature = "traceroute")]
            PacketcraftCommand::Traceroute(options) => {
                EngineCommand::Traceroute(TracerouteRequest::from(options))
            }
            #[cfg(feature = "scan")]
            PacketcraftCommand::Scan(command) => EngineCommand::Scan(ScanRequest::from(command)),
            PacketcraftCommand::DnsQuery(options) => {
                EngineCommand::DnsQuery(DnsRequest::from(options))
            }
            #[cfg(feature = "fuzz")]
            PacketcraftCommand::Fuzz(options) => EngineCommand::Fuzz(FuzzRequest::from(options)),
        }
    }

    fn packet_request(&self, options: &OneShotOptions) -> PacketRequest {
        let mut request = PacketRequest::from(options);
        let observability = LoggingRequest::from(&self.observability);
        request.logging.log_file = observability.log_file;
        request.logging.log_level = observability.log_level;
        request.logging.structured = observability.structured;
        request.logging.prometheus_bind = observability.prometheus_bind;
        request.logging.allow_public_metrics = observability.allow_public_metrics;
        request
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
    use crate::output::OutputFormat;

    fn args(command: PacketcraftCommand, dry_run: bool) -> PacketcraftArgs {
        PacketcraftArgs {
            verbose: 0,
            output_format: None,
            dry_run,
            safety: options::SafetyOptions::default(),
            observability: options::ObservabilityOptions::default(),
            command,
        }
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
                    ..Default::default()
                },
            }),
            false,
        );
        args.observability.prometheus_bind = Some("127.0.0.1:9090".to_string());
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
        let mut send_args = args(
            PacketcraftCommand::Send(options::SendOptions {
                oneshot: options::OneShotOptions {
                    destination: Some("127.0.0.1".to_string()),
                    logging: options::PacketLoggingOptions {
                        pcap_write: Some("sent.pcap".to_string()),
                        metrics_json: Some("metrics.json".to_string()),
                    },
                    ..Default::default()
                },
            }),
            false,
        );
        send_args.observability = options::ObservabilityOptions {
            log_file: Some("packet.log".to_string()),
            log_level: Some(crate::cli::enums::LogLevel::Debug),
            structured: Some(true),
            prometheus_bind: Some("127.0.0.1:9090".to_string()),
            allow_public_metrics: Some(true),
        };
        let send = send_args.engine_command();
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
                    && request.logging.log_file.as_deref() == Some("packet.log")
                    && request.logging.pcap_write.as_deref() == Some("sent.pcap")
                    && request.logging.metrics_json.as_deref() == Some("metrics.json")
                    && request.logging.log_level == Some(crate::domain::request::LogLevel::Debug)
                    && request.logging.structured == Some(true)
                    && request.logging.prometheus_bind.as_deref() == Some("127.0.0.1:9090")
                    && request.logging.allow_public_metrics == Some(true)
        ));
        assert!(matches!(
            dry_run,
            EngineCommand::DryRun(request)
                if request.destination.destination.as_deref() == Some("localhost")
        ));
    }

    #[test]
    fn engine_command_maps_dns_query_options() {
        let command = args(
            PacketcraftCommand::DnsQuery(commands::DnsQueryOptions {
                domain: "example.test".to_string(),
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
