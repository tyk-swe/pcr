// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use clap::{Args, ValueEnum};
use packetcraftr::{packet, workflow};

use super::address_family::CliAddressFamily;
use super::capture_limits::CaptureLimitArgs;
use super::policy::HostnameTrafficPolicyArgs;
use super::route::CliLinkMode;

pub(super) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr scan 192.0.2.10 --transport tcp --ports 22,80,443
  packetcraftr --output ndjson scan 198.51.100.10 --transport icmp"#;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliScanTransport {
    #[default]
    Tcp,
    Udp,
    Icmp,
}

impl From<CliScanTransport> for workflow::scan::Transport {
    fn from(value: CliScanTransport) -> Self {
        match value {
            CliScanTransport::Tcp => Self::Tcp,
            CliScanTransport::Udp => Self::Udp,
            CliScanTransport::Icmp => Self::Icmp,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct ScanArgs {
    /// Explicit IP address or hostname to scan.
    #[arg(value_name = "ADDRESS_OR_HOSTNAME")]
    pub(crate) target: String,
    /// TCP SYN, UDP, or ICMP echo probes.
    #[arg(long, value_enum, default_value_t = CliScanTransport::Tcp)]
    pub(crate) transport: CliScanTransport,
    /// Select all authorized addresses or only one IP family.
    #[arg(long, value_enum, default_value_t = CliAddressFamily::Any)]
    pub(crate) family: CliAddressFamily,
    /// Comma-separated TCP/UDP destination ports; omitted for ICMP.
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    pub(crate) ports: Vec<u16>,
    /// Number of bounded attempts per selected endpoint.
    #[arg(long, default_value_t = 1)]
    pub(crate) attempts: u32,
    /// Response window for each capture-ready batch.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) timeout_ms: u64,
    /// Optional average probe-rate ceiling; batches remain deliberate bursts.
    #[arg(long)]
    pub(crate) rate: Option<u32>,
    /// Maximum probes sent by one shared-capture exchange batch.
    #[arg(long, default_value_t = workflow::scan::DEFAULT_SCAN_BATCH_SIZE)]
    pub(crate) batch_size: usize,
    /// Maximum distinct destination ports accepted by the request.
    #[arg(long, default_value_t = workflow::scan::DEFAULT_MAX_SCAN_PORTS)]
    pub(crate) max_ports: usize,
    /// Maximum generated probes after target resolution and attempts.
    #[arg(long, default_value_t = packet::template::DEFAULT_MAX_TEMPLATE_PACKETS)]
    pub(crate) max_probes: usize,
    /// Maximum worst-case timeout plus intentional rate delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
    /// Maximum undecodable exact frames retained across the scan.
    #[arg(long, default_value_t = workflow::scan::DEFAULT_MAX_UNDECODED_SCAN_FRAMES)]
    pub(crate) max_undecoded: usize,
    /// Interface name or numeric index used as an exact route constraint.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(crate) interface: Option<String>,
    /// Interface-owned source preference used only for route selection.
    #[arg(long)]
    pub(crate) source: Option<IpAddr>,
    /// Automatic, Layer 2, or raw Layer 3 transmission intent.
    #[arg(long, value_enum, default_value_t = CliLinkMode::Auto)]
    pub(crate) link_mode: CliLinkMode,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitArgs,
    #[command(flatten)]
    pub(crate) policy: HostnameTrafficPolicyArgs,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::CliScanTransport;
    use crate::arguments::{Cli, Command};

    #[test]
    fn typed_transport_ports_and_finite_limits_parse() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "scan",
            "192.168.56.10",
            "--transport",
            "udp",
            "--ports",
            "53,161",
            "--attempts",
            "2",
            "--batch-size",
            "2",
            "--rate",
            "10",
        ])
        .unwrap();
        let Command::Scan(arguments) = cli.command else {
            panic!("expected scan command");
        };
        assert!(matches!(arguments.transport, CliScanTransport::Udp));
        assert_eq!(arguments.ports, [53, 161]);
        assert_eq!(arguments.attempts, 2);
        assert_eq!(arguments.batch_size, 2);
        assert_eq!(arguments.rate, Some(10));
    }
}
