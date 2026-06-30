// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::cli::{self, PacketcraftArgs, PacketcraftCommand};
use crate::domain::command::EngineCommand;
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
                EngineCommand::Interactive(options.to_request())
            }
            #[cfg(feature = "daemon")]
            PacketcraftCommand::Daemon(options) => EngineCommand::Daemon(options.to_request()),
            #[cfg(feature = "pcap")]
            PacketcraftCommand::Listen(options) => EngineCommand::Listen(options.to_request()),
            #[cfg(feature = "traceroute")]
            PacketcraftCommand::Traceroute(options) => {
                EngineCommand::Traceroute(options.to_request())
            }
            #[cfg(feature = "scan")]
            PacketcraftCommand::Scan(command) => EngineCommand::Scan(command.to_request()),
            PacketcraftCommand::DnsQuery(options) => EngineCommand::DnsQuery(options.to_request()),
            #[cfg(feature = "fuzz")]
            PacketcraftCommand::Fuzz(options) => EngineCommand::Fuzz(options.to_request()),
        }
    }
}

impl From<cli::OutputFormat> for crate::output::OutputFormat {
    fn from(format: cli::OutputFormat) -> Self {
        match format {
            cli::OutputFormat::Summary => Self::Summary,
            cli::OutputFormat::Detailed => Self::Detailed,
            cli::OutputFormat::Hex => Self::Hex,
            cli::OutputFormat::Json => Self::Json,
        }
    }
}
