// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod commands;
pub(crate) mod enums;
pub(crate) mod options;
#[cfg(feature = "repl")]
pub(crate) mod repl;
mod request;
pub(crate) mod validators;

use clap::Parser;

/// Top-level CLI arguments for PacketcraftR.
#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Modular packet crafting, transmission, and automation toolkit",
    long_about = "PacketcraftR builds packets layer-by-layer (Ethernet -> IP -> Transport -> Payload) for authorized lab, protocol-development, and network-testing work. \
The stable rescue surface focuses on safe dry-run previews, packet validation, and finite packet transmission planning. \
Optional operational tools appear when their Cargo features are enabled.",
    after_help = "EXAMPLES:

  1. Preview a UDP payload to loopback without transmitting:
     packetcraftr dry-run -d 127.0.0.1 --data hello udp --dport 9

  2. Preview JSON output for automation:
     packetcraftr --output-format json dry-run -d 127.0.0.1 --data hello udp --dport 9

  3. Build an ICMP Echo Request preview:
     packetcraftr dry-run -d 127.0.0.1 icmp --icmp-type 8 --icmp-code 0

  4. Preview a raw payload from hex:
     packetcraftr dry-run -d 127.0.0.1 --data-hex \"aa bb cc\" udp --dport 9"
)]
pub(crate) struct PacketcraftArgs {
    /// Set the verbosity level (-v: info, -vv: debug, -vvv: trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Set the output format for display and logging.
    #[arg(long, value_enum)]
    pub output_format: Option<enums::OutputFormat>,
    /// Preview what would be sent without transmitting any packets.
    #[arg(
        long,
        global = true,
        help = "Preview what would be sent without transmitting any packets"
    )]
    pub dry_run: bool,
    #[command(flatten, next_help_heading = "Safety")]
    pub safety: options::SafetyOptions,
    #[command(flatten, next_help_heading = "Observability")]
    pub observability: options::ObservabilityOptions,
    /// Select an operation mode.
    #[command(subcommand)]
    pub command: commands::PacketcraftCommand,
}

impl PacketcraftArgs {
    pub(crate) fn one_shot_options(&self) -> Option<&options::OneShotOptions> {
        match &self.command {
            commands::PacketcraftCommand::Send(options)
            | commands::PacketcraftCommand::DryRun(options) => Some(&options.oneshot),
            _ => None,
        }
    }

    pub(crate) fn effective_dry_run(&self) -> bool {
        self.dry_run || matches!(&self.command, commands::PacketcraftCommand::DryRun(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn args(command: commands::PacketcraftCommand, dry_run: bool) -> PacketcraftArgs {
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
    fn one_shot_options_returns_send_options() {
        let args = args(
            commands::PacketcraftCommand::Send(options::SendOptions {
                oneshot: options::OneShotOptions {
                    destination: Some("127.0.0.1".to_string()),
                    ..Default::default()
                },
            }),
            false,
        );

        assert_eq!(
            args.one_shot_options()
                .and_then(|opts| opts.destination.as_deref()),
            Some("127.0.0.1")
        );
    }

    #[test]
    fn one_shot_options_returns_dry_run_options() {
        let args = args(
            commands::PacketcraftCommand::DryRun(options::SendOptions {
                oneshot: options::OneShotOptions {
                    destination: Some("localhost".to_string()),
                    ..Default::default()
                },
            }),
            false,
        );

        assert_eq!(
            args.one_shot_options()
                .and_then(|opts| opts.destination.as_deref()),
            Some("localhost")
        );
    }

    #[test]
    fn one_shot_options_returns_none_for_dns_query() {
        let args = args(
            commands::PacketcraftCommand::DnsQuery(commands::DnsQueryOptions::default()),
            false,
        );

        assert!(args.one_shot_options().is_none());
    }

    #[test]
    fn effective_dry_run_honors_global_flag_and_subcommand() {
        let global = args(
            commands::PacketcraftCommand::Send(options::SendOptions::default()),
            true,
        );
        let subcommand = args(
            commands::PacketcraftCommand::DryRun(options::SendOptions::default()),
            false,
        );
        let live = args(
            commands::PacketcraftCommand::Send(options::SendOptions::default()),
            false,
        );

        assert!(global.effective_dry_run());
        assert!(subcommand.effective_dry_run());
        assert!(!live.effective_dry_run());
    }

    #[test]
    fn parser_accepts_json_output_format_before_command() {
        let parsed = PacketcraftArgs::try_parse_from([
            "packetcraftr",
            "--output-format",
            "json",
            "dns-query",
            "--domain",
            "example.test",
        ])
        .unwrap();

        assert_eq!(parsed.output_format, Some(enums::OutputFormat::Json));
        assert!(matches!(
            parsed.command,
            commands::PacketcraftCommand::DnsQuery(options)
                if options.domain == "example.test"
        ));
    }

    #[test]
    fn parser_accepts_global_dry_run_before_subcommand() {
        let parsed = PacketcraftArgs::try_parse_from([
            "packetcraftr",
            "--dry-run",
            "send",
            "--dest",
            "127.0.0.1",
        ])
        .unwrap();

        assert!(parsed.dry_run);
        assert!(parsed.effective_dry_run());
        assert!(matches!(
            parsed.command,
            commands::PacketcraftCommand::Send(options)
                if options.oneshot.destination.as_deref() == Some("127.0.0.1")
        ));
    }

    #[test]
    fn parser_accepts_global_observability_before_dns_query() {
        let parsed = PacketcraftArgs::try_parse_from([
            "packetcraftr",
            "--log-file",
            "packet.log",
            "--log-level",
            "debug",
            "--log-structured",
            "dns-query",
            "--domain",
            "example.test",
        ])
        .unwrap();

        assert_eq!(parsed.observability.log_file.as_deref(), Some("packet.log"));
        assert_eq!(parsed.observability.log_level, Some(enums::LogLevel::Debug));
        assert_eq!(parsed.observability.structured, Some(true));
        assert!(matches!(
            parsed.command,
            commands::PacketcraftCommand::DnsQuery(options)
                if options.domain == "example.test"
        ));
    }

    #[test]
    fn parser_accepts_global_observability_after_dns_query() {
        let parsed = PacketcraftArgs::try_parse_from([
            "packetcraftr",
            "dns-query",
            "--domain",
            "example.test",
            "--log-level",
            "warn",
        ])
        .unwrap();

        assert_eq!(parsed.observability.log_level, Some(enums::LogLevel::Warn));
        assert!(matches!(
            parsed.command,
            commands::PacketcraftCommand::DnsQuery(options)
                if options.domain == "example.test"
        ));
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn parser_accepts_prometheus_observability_after_dns_query() {
        let parsed = PacketcraftArgs::try_parse_from([
            "packetcraftr",
            "dns-query",
            "--domain",
            "example.test",
            "--prometheus-bind",
            "127.0.0.1:9090",
            "--allow-public-metrics=false",
        ])
        .unwrap();

        assert_eq!(
            parsed.observability.prometheus_bind.as_deref(),
            Some("127.0.0.1:9090")
        );
        assert_eq!(parsed.observability.allow_public_metrics, Some(false));
        assert!(matches!(
            parsed.command,
            commands::PacketcraftCommand::DnsQuery(options)
                if options.domain == "example.test"
        ));
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn parser_rejects_pcap_write_on_dns_query() {
        let err = PacketcraftArgs::try_parse_from([
            "packetcraftr",
            "dns-query",
            "--domain",
            "example.test",
            "--pcap-write",
            "sent.pcap",
        ])
        .unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn parser_rejects_pcap_write_on_dns_query() {
        let err = PacketcraftArgs::try_parse_from([
            "packetcraftr",
            "dns-query",
            "--domain",
            "example.test",
            "--pcap-write",
            "sent.pcap",
        ])
        .unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn parser_rejects_metrics_json_on_dns_query() {
        let err = PacketcraftArgs::try_parse_from([
            "packetcraftr",
            "dns-query",
            "--domain",
            "example.test",
            "--metrics-json",
            "metrics.json",
        ])
        .unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}
