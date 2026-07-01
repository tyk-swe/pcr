// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(any(
    feature = "daemon",
    feature = "pcap",
    feature = "repl",
    feature = "traceroute"
))]
use clap::builder::BoolishValueParser;
#[cfg(any(feature = "fuzz", feature = "traceroute"))]
use clap::ValueEnum;
use clap::{value_parser, Args, Subcommand};

#[cfg(feature = "pcap")]
use super::options::ListenOptions;
#[cfg(feature = "daemon")]
use super::options::RuleOptions;
use super::options::SendOptions;
use super::validators::dns_record_type_validator;
use crate::domain::command::DnsTransportMode;

/// Global operation modes.
#[derive(Debug, Subcommand)]
pub(crate) enum PacketcraftCommand {
    /// Send a finite packet request.
    Send(SendOptions),
    /// Preview a packet request without transmitting.
    DryRun(SendOptions),
    /// Start the interactive REPL shell.
    #[cfg(feature = "repl")]
    Interactive(InteractiveOptions),
    /// Run as a background daemon with automation.
    #[cfg(feature = "daemon")]
    Daemon(DaemonOptions),
    /// Listen for network packets and react.
    #[cfg(feature = "pcap")]
    Listen(ListenCommandOptions),
    /// Map network routes (traceroute).
    #[cfg(feature = "traceroute")]
    Traceroute(TracerouteOptions),
    /// Execute network scans (TCP SYN, UDP, etc.).
    #[command(subcommand)]
    #[cfg(feature = "scan")]
    Scan(ScanCommand),
    /// Perform a DNS query.
    DnsQuery(DnsQueryOptions),
    /// Fuzz a target with malformed packets.
    #[cfg(feature = "fuzz")]
    Fuzz(FuzzOptions),
}

#[cfg(feature = "fuzz")]
#[derive(Debug, Args, Clone)]
pub(crate) struct FuzzOptions {
    /// Target IP address (IPv4/IPv6).
    #[arg(long = "target")]
    pub target: String,

    /// Target port (required for TCP/UDP).
    #[arg(
        long = "port",
        required_if_eq("protocol", "tcp"),
        required_if_eq("protocol", "udp")
    )]
    pub port: Option<u16>,

    /// Select the protocol to fuzz.
    #[arg(long = "protocol", value_enum)]
    pub protocol: FuzzProtocol,

    /// Select the fuzzing strategy.
    #[arg(long = "strategy", value_enum, default_value_t = FuzzStrategy::RandomPayload)]
    pub strategy: FuzzStrategy,

    /// Number of packets to send.
    #[arg(long = "count", default_value_t = 100)]
    pub count: u64,

    /// Delay between packets (in ms).
    #[arg(long = "delay", default_value_t = 10)]
    pub delay: u64,
}

#[cfg(feature = "fuzz")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum FuzzProtocol {
    /// Fuzz TCP protocol fields.
    Tcp,
    /// Fuzz UDP payload and headers.
    Udp,
    /// Fuzz ICMP packet structures.
    Icmp,
}

#[cfg(feature = "fuzz")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum FuzzStrategy {
    /// Randomly flip bits in the payload.
    BitFlip,
    /// Randomly swap bytes in the payload.
    ByteSwap,
    /// Replace payload with random bytes.
    #[value(alias = "random")]
    RandomPayload,
    /// Test boundary values (empty, max size).
    #[value(alias = "byte-overflow")]
    Boundary,
}

#[derive(Debug, Args, Clone, Default)]
pub(crate) struct DnsQueryOptions {
    /// Domain to query.
    #[arg(long = "domain")]
    pub domain: String,
    /// DNS record type.
    #[arg(long = "type", default_value = "A", value_parser = dns_record_type_validator)]
    pub record_type: String,
    /// DNS server IP.
    #[arg(long = "server", default_value = "8.8.8.8")]
    pub server: String,
    /// Query timeout (in ms).
    #[arg(long = "timeout", value_parser = value_parser!(u64), default_value_t = 1000)]
    pub timeout: u64,
    /// DNS Transaction ID.
    #[arg(long = "tid")]
    pub transaction_id: Option<u16>,
    /// DNS transport to use.
    #[arg(long = "transport", value_parser = value_parser!(DnsTransportMode), default_value_t = DnsTransportMode::Auto)]
    pub transport: DnsTransportMode,
    /// Extra attempts after the first attempt.
    #[arg(long = "retries", value_parser = value_parser!(u8).range(0..=5), default_value_t = 0)]
    pub retries: u8,
}

#[cfg(feature = "repl")]
#[derive(Debug, Args)]
pub(crate) struct InteractiveOptions {
    /// Preload a script file.
    #[arg(long = "script")]
    pub script: Option<String>,
    /// Automatically listen for replies.
    #[arg(
        long = "auto-listen",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub auto_listen: Option<bool>,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Args)]
pub(crate) struct DaemonOptions {
    #[command(flatten)]
    pub rule_options: RuleOptions,
    /// Run in the foreground.
    #[arg(
        long = "foreground",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub foreground: Option<bool>,
    /// Control socket path.
    #[arg(long = "control-socket")]
    #[cfg_attr(not(unix), arg(hide = true))]
    pub control_socket: Option<String>,
}

#[cfg(feature = "pcap")]
#[derive(Debug, Args)]
pub(crate) struct ListenCommandOptions {
    #[command(flatten, next_help_heading = "Listener configuration")]
    pub listen: ListenOptions,
    /// Continue listening after timeout.
    #[arg(
        long = "persistent",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub persistent: Option<bool>,
}

#[cfg(feature = "traceroute")]
#[derive(Debug, Args, Clone, Default)]
pub(crate) struct TracerouteOptions {
    /// Target destination.
    #[arg(long = "dest")]
    pub destination: String,
    /// Maximum TTL.
    #[arg(long = "max-ttl", value_parser = value_parser!(u8), default_value_t = 30)]
    pub max_ttl: u8,
    /// Number of probes per hop.
    #[arg(long = "probes", value_parser = value_parser!(u8), default_value_t = 3)]
    pub probes: u8,
    /// Probe protocol.
    #[arg(long = "protocol", value_enum, default_value_t = TracerouteProtocol::Udp)]
    pub protocol: TracerouteProtocol,
    /// Disable reverse DNS resolution.
    #[arg(
        long = "no-dns",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub no_dns: Option<bool>,
    /// Probe timeout (in ms).
    #[arg(long = "timeout", value_parser = value_parser!(u64), default_value_t = 3000)]
    pub timeout: u64,
}

#[cfg(feature = "traceroute")]
#[derive(Debug, Copy, Clone, ValueEnum, Default)]
pub(crate) enum TracerouteProtocol {
    /// Use UDP probes.
    #[default]
    Udp,
    /// Use TCP SYN probes.
    Tcp,
    /// Use ICMP Echo probes.
    Icmp,
}

#[cfg(feature = "scan")]
#[derive(Debug, Args, Clone)]
pub(crate) struct PortScanOptions {
    /// Target IP or CIDR (e.g., 192.168.1.0/24).
    #[arg(long = "target")]
    pub target: String,
    /// Ports to scan (e.g., "80,443", "1-100").
    #[arg(long = "ports")]
    pub ports: String,
    /// Scanning interface.
    #[arg(long = "interface")]
    pub interface: Option<String>,
    /// Source IP address to use for crafted scan probes.
    #[arg(long = "source-ip")]
    pub source_ip: Option<String>,
}

#[cfg(feature = "scan")]
#[derive(Debug, Args, Clone)]
pub(crate) struct TimedScanOptions {
    /// Target IP or CIDR (e.g., 192.168.1.0/24).
    #[arg(long = "target")]
    pub target: String,
    /// Scanning interface.
    #[arg(long = "interface")]
    pub interface: Option<String>,
    /// Source IP address to use for crafted scan probes.
    #[arg(long = "source-ip")]
    pub source_ip: Option<String>,
    /// Timeout (in ms).
    #[arg(long = "timeout", value_parser = value_parser!(u64), default_value_t = 1_000)]
    pub timeout: u64,
}

#[cfg(feature = "scan")]
#[derive(Debug, Subcommand)]
pub(crate) enum ScanCommand {
    /// Perform a TCP SYN scan (half-open).
    #[command(name = "tcp-syn")]
    TcpSyn(PortScanOptions),
    /// Perform a TCP FIN scan (inverse mapping).
    #[command(name = "tcp-fin")]
    TcpFin(PortScanOptions),
    /// Perform a TCP NULL scan (no flags set).
    #[command(name = "tcp-null")]
    TcpNull(PortScanOptions),
    /// Perform a TCP XMAS scan (FIN+URG+PUSH).
    #[command(name = "tcp-xmas")]
    TcpXmas(PortScanOptions),
    /// Perform a TCP ACK scan (firewall mapping).
    #[command(name = "tcp-ack")]
    TcpAck(PortScanOptions),
    /// Perform an SCTP INIT scan.
    #[command(name = "sctp-init")]
    SctpInit(PortScanOptions),
    /// Perform an ICMP echo scan (ping sweep).
    Icmp(TimedScanOptions),
    /// Perform a UDP scan.
    Udp(PortScanOptions),
    /// Perform an ARP scan (local network discovery).
    Arp(TimedScanOptions),
    /// Perform an NDP scan (IPv6 local network discovery).
    Ndp(TimedScanOptions),
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct DnsHarness {
        #[command(flatten)]
        options: DnsQueryOptions,
    }

    fn parse_dns(args: &[&str]) -> Result<DnsHarness, clap::Error> {
        DnsHarness::try_parse_from(std::iter::once("test").chain(args.iter().copied()))
    }

    #[test]
    fn dns_query_defaults_are_stable_for_dry_planning() {
        let parsed = parse_dns(&["--domain", "example.test"]).unwrap();

        assert_eq!(parsed.options.domain, "example.test");
        assert_eq!(parsed.options.record_type, "A");
        assert_eq!(parsed.options.server, "8.8.8.8");
        assert_eq!(parsed.options.timeout, 1000);
        assert_eq!(parsed.options.transaction_id, None);
        assert_eq!(parsed.options.transport, DnsTransportMode::Auto);
        assert_eq!(parsed.options.retries, 0);
    }

    #[test]
    fn dns_query_accepts_supported_record_types_without_normalizing_case() {
        let parsed = parse_dns(&["--domain", "example.test", "--type", "aaaa"]).unwrap();

        assert_eq!(parsed.options.record_type, "aaaa");
    }

    #[test]
    fn dns_query_rejects_unknown_record_type() {
        let err = parse_dns(&["--domain", "example.test", "--type", "notatype"]).unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn dns_query_retries_accept_configured_range_boundaries() {
        let min = parse_dns(&["--domain", "example.test", "--retries", "0"]).unwrap();
        let max = parse_dns(&["--domain", "example.test", "--retries", "5"]).unwrap();

        assert_eq!(min.options.retries, 0);
        assert_eq!(max.options.retries, 5);
    }

    #[test]
    fn dns_query_retries_reject_values_above_cap() {
        let err = parse_dns(&["--domain", "example.test", "--retries", "6"]).unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[cfg(feature = "traceroute")]
    #[derive(Debug, Parser)]
    struct TracerouteHarness {
        #[command(flatten)]
        options: TracerouteOptions,
    }

    #[cfg(feature = "traceroute")]
    #[test]
    fn traceroute_boolish_no_dns_accepts_missing_and_explicit_values() {
        let implicit =
            TracerouteHarness::try_parse_from(["test", "--dest", "192.0.2.1", "--no-dns"]).unwrap();
        let explicit =
            TracerouteHarness::try_parse_from(["test", "--dest", "192.0.2.1", "--no-dns=false"])
                .unwrap();

        assert_eq!(implicit.options.no_dns, Some(true));
        assert_eq!(explicit.options.no_dns, Some(false));
    }
}
