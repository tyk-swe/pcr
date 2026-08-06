// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use clap::{Args, ValueEnum};
use packetcraftr::workflow;

use crate::command_options::{
    CaptureLimitArgs, CliAddressFamily, CliLinkMode, HostnameTrafficPolicyArgs,
};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr dns 192.0.2.53 example.test --type a
  packetcraftr --output json dns 192.0.2.53 _service._tcp.example.test --type srv"#;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum CliDnsQueryType {
    #[default]
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Soa,
    Srv,
    Txt,
    Any,
}

impl From<CliDnsQueryType> for workflow::dns::QueryType {
    fn from(value: CliDnsQueryType) -> Self {
        match value {
            CliDnsQueryType::A => Self::A,
            CliDnsQueryType::Aaaa => Self::Aaaa,
            CliDnsQueryType::Cname => Self::Cname,
            CliDnsQueryType::Mx => Self::Mx,
            CliDnsQueryType::Ns => Self::Ns,
            CliDnsQueryType::Ptr => Self::Ptr,
            CliDnsQueryType::Soa => Self::Soa,
            CliDnsQueryType::Srv => Self::Srv,
            CliDnsQueryType::Txt => Self::Txt,
            CliDnsQueryType::Any => Self::Any,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct DnsArgs {
    /// Explicit DNS server IP address or hostname.
    #[arg(value_name = "SERVER")]
    pub(crate) server: String,
    /// Bounded ASCII DNS owner name to query.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
    /// DNS question type.
    #[arg(long = "type", value_enum, default_value_t = CliDnsQueryType::A)]
    pub(crate) query_type: CliDnsQueryType,
    /// Select the first authorized server address or one IP family.
    #[arg(long, value_enum, default_value_t = CliAddressFamily::Any)]
    pub(crate) family: CliAddressFamily,
    /// DNS server UDP port.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_DNS_SERVER_PORT)]
    pub(crate) port: u16,
    /// Explicit 16-bit transaction ID; a process-local value is generated when omitted.
    #[arg(long)]
    pub(crate) transaction_id: Option<u16>,
    /// First UDP source port; an ephemeral-range value is generated when omitted.
    #[arg(long)]
    pub(crate) source_port: Option<u16>,
    /// Disable the recursion-desired query flag.
    #[arg(long)]
    pub(crate) no_recursion: bool,
    /// Number of independently re-resolved and re-authorized attempts.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_DNS_ATTEMPTS)]
    pub(crate) attempts: u32,
    /// Response window for each capture-ready query.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) timeout_ms: u64,
    /// Optional average query-rate ceiling.
    #[arg(long)]
    pub(crate) rate: Option<u32>,
    /// Maximum worst-case timeout plus intentional retry delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
    /// Maximum complete DNS message bytes decoded.
    #[arg(long, default_value_t = workflow::dns::MAX_DNS_MESSAGE_BYTES)]
    pub(crate) max_message_bytes: usize,
    /// Maximum total answer, authority, and additional records decoded.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_DNS_RECORDS)]
    pub(crate) max_records: usize,
    /// Maximum compression-pointer traversals for any decoded DNS name.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_DNS_NAME_POINTERS)]
    pub(crate) max_name_pointers: usize,
    /// Maximum TXT character strings in one record.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_DNS_TXT_STRINGS)]
    pub(crate) max_txt_strings: usize,
    /// Maximum aggregate TXT data bytes in one record.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_DNS_TXT_BYTES)]
    pub(crate) max_txt_bytes: usize,
    /// Maximum rejected-record metadata entries retained.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_REJECTED_DNS_RECORDS)]
    pub(crate) max_rejected_records: usize,
    /// Maximum undecodable exact frames retained across attempts.
    #[arg(long, default_value_t = workflow::dns::DEFAULT_MAX_UNDECODED_DNS_FRAMES)]
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

    use super::{CliAddressFamily, CliDnsQueryType, CliLinkMode};
    use crate::{cli::Cli, commands::Command};

    #[test]
    fn query_policy_route_and_finite_bounds_parse() {
        let cli = Cli::try_parse_from([
            "packetcraftr",
            "dns",
            "10.0.0.53",
            "_service._tcp.example.test",
            "--type",
            "srv",
            "--family",
            "ipv4",
            "--port",
            "5353",
            "--transaction-id",
            "7",
            "--source-port",
            "50000",
            "--attempts",
            "3",
            "--rate",
            "10",
            "--interface",
            "test0",
            "--source",
            "10.0.0.2",
            "--link-mode",
            "layer3",
        ])
        .unwrap();
        let Command::Dns(arguments) = cli.command else {
            panic!("expected DNS command");
        };
        assert!(matches!(arguments.query_type, CliDnsQueryType::Srv));
        assert!(matches!(arguments.family, CliAddressFamily::Ipv4));
        assert_eq!(arguments.port, 5353);
        assert_eq!(arguments.transaction_id, Some(7));
        assert_eq!(arguments.source_port, Some(50_000));
        assert_eq!(arguments.attempts, 3);
        assert_eq!(arguments.rate, Some(10));
        assert_eq!(arguments.interface.as_deref(), Some("test0"));
        assert_eq!(arguments.source, Some("10.0.0.2".parse().unwrap()));
        assert!(matches!(arguments.link_mode, CliLinkMode::Layer3));
    }
}
