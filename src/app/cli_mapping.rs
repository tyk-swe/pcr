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
    use clap::Parser;

    use crate::cli::commands::PacketcraftCommand;
    use crate::domain::command::EngineCommand;
    use crate::domain::request::TransportProtocolRequest;

    #[test]
    fn parses_dry_run_and_maps_one_shot_request() {
        let args = PacketcraftArgs::parse_from([
            "packetcraftr",
            "--output-format",
            "json",
            "dry-run",
            "-d",
            "127.0.0.1",
            "--data",
            "hello",
            "--count",
            "2",
            "--force-layer3=false",
            "udp",
            "--dport",
            "9",
        ]);

        assert!(args.effective_dry_run());
        assert_eq!(args.output_format, Some(CliOutputFormat::Json));

        let EngineCommand::DryRun(request) = args.engine_command() else {
            panic!("expected dry-run command");
        };
        assert_eq!(
            request.destination.destination.as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(request.payload.data.as_deref(), Some("hello"));
        assert_eq!(request.transmit.count, Some(2));
        assert_eq!(request.transmit.force_layer3, Some(false));
        assert_eq!(request.transport.destination_port, Some(9));
        assert!(matches!(
            request.transport.command,
            Some(TransportProtocolRequest::Udp)
        ));
    }

    #[test]
    fn parses_boolish_flags() {
        let args = PacketcraftArgs::parse_from([
            "packetcraftr",
            "send",
            "-d",
            "127.0.0.1",
            "--flood",
            "--prefer-ipv6=false",
            "--force-layer3=true",
            "icmp",
        ]);

        let PacketcraftCommand::Send(options) = args.command else {
            panic!("expected send command");
        };
        assert_eq!(options.oneshot.transmit.flood, Some(true));
        assert_eq!(options.oneshot.ip.prefer_ipv6, Some(false));
        assert_eq!(options.oneshot.transmit.force_layer3, Some(true));
    }

    #[test]
    fn maps_output_format_values() {
        assert!(matches!(
            crate::output::OutputFormat::from(CliOutputFormat::Summary),
            crate::output::OutputFormat::Summary
        ));
        assert!(matches!(
            crate::output::OutputFormat::from(CliOutputFormat::Detailed),
            crate::output::OutputFormat::Detailed
        ));
        assert!(matches!(
            crate::output::OutputFormat::from(CliOutputFormat::Hex),
            crate::output::OutputFormat::Hex
        ));
        assert!(matches!(
            crate::output::OutputFormat::from(CliOutputFormat::Json),
            crate::output::OutputFormat::Json
        ));
    }

    #[test]
    fn maps_send_command_to_request() {
        let args = PacketcraftArgs::parse_from([
            "packetcraftr",
            "--allow-public-targets",
            "send",
            "-d",
            "192.0.2.10",
            "--sport",
            "12345",
            "tcp",
            "--dport",
            "443",
            "--flags",
            "SA",
            "--seq",
            "7",
            "--ack",
            "9",
        ]);

        assert!(!args.effective_dry_run());
        assert!(args.engine_config().traffic_policy.allow_public_targets);

        let EngineCommand::Send(request) = args.engine_command() else {
            panic!("expected send command");
        };
        assert_eq!(
            request.destination.destination.as_deref(),
            Some("192.0.2.10")
        );
        assert_eq!(request.transport.source_port, Some(12345));
        assert_eq!(request.transport.destination_port, Some(443));
        let Some(TransportProtocolRequest::Tcp(tcp)) = request.transport.command else {
            panic!("expected tcp request");
        };
        assert_eq!(tcp.flags.as_deref(), Some("SA"));
        assert_eq!(tcp.sequence, Some(7));
        assert_eq!(tcp.acknowledgement, Some(9));
    }
}
