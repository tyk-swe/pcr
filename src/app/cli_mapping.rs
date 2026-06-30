// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::cli::commands::PacketcraftCommand;
use crate::cli::enums::OutputFormat as CliOutputFormat;
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

    pub(crate) fn engine_command(&self) -> EngineCommand {
        match &self.command {
            PacketcraftCommand::Send(options) => {
                EngineCommand::Send(PacketRequest::from(&options.oneshot))
            }
            PacketcraftCommand::DryRun(options) => {
                EngineCommand::DryRun(PacketRequest::from(&options.oneshot))
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
