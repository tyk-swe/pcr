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
    #[arg(long = "count", value_parser = value_parser!(u64).range(1..), default_value_t = 100)]
    pub count: u64,

    /// Delay between packets (in ms).
    #[arg(long = "delay", value_parser = value_parser!(u64).range(0..), default_value_t = 10)]
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
    #[arg(long = "timeout", value_parser = value_parser!(u64).range(1..), default_value_t = 1000)]
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
    #[arg(long = "max-ttl", value_parser = value_parser!(u8).range(1..), default_value_t = 30)]
    pub max_ttl: u8,
    /// Number of probes per hop.
    #[arg(long = "probes", value_parser = value_parser!(u8).range(1..), default_value_t = 3)]
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
    #[arg(long = "timeout", value_parser = value_parser!(u64).range(1..), default_value_t = 3000)]
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
    #[arg(long = "timeout", value_parser = value_parser!(u64).range(1..), default_value_t = 1_000)]
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

    #[test]
    fn dns_query_timeout_rejects_zero() {
        let err = parse_dns(&["--domain", "example.test", "--timeout", "0"]).unwrap_err();

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

    #[cfg(feature = "traceroute")]
    #[test]
    fn traceroute_rejects_zero_controls() {
        for args in [
            ["test", "--dest", "192.0.2.1", "--max-ttl", "0"].as_slice(),
            ["test", "--dest", "192.0.2.1", "--probes", "0"].as_slice(),
            ["test", "--dest", "192.0.2.1", "--timeout", "0"].as_slice(),
        ] {
            let err = TracerouteHarness::try_parse_from(args).unwrap_err();

            assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        }
    }

    #[cfg(feature = "traceroute")]
    #[test]
    fn traceroute_preserves_valid_defaults() {
        let parsed = TracerouteHarness::try_parse_from(["test", "--dest", "192.0.2.1"]).unwrap();

        assert_eq!(parsed.options.max_ttl, 30);
        assert_eq!(parsed.options.probes, 3);
        assert_eq!(parsed.options.timeout, 3000);
    }

    #[cfg(feature = "fuzz")]
    #[derive(Debug, Parser)]
    struct FuzzHarness {
        #[command(flatten)]
        options: FuzzOptions,
    }

    #[cfg(feature = "fuzz")]
    #[test]
    fn fuzz_strategy_parser_accepts_documented_aliases() {
        let random = FuzzHarness::try_parse_from([
            "test",
            "--target",
            "192.0.2.1",
            "--protocol",
            "icmp",
            "--strategy",
            "random",
        ])
        .unwrap();
        let byte_overflow = FuzzHarness::try_parse_from([
            "test",
            "--target",
            "192.0.2.1",
            "--protocol",
            "icmp",
            "--strategy",
            "byte-overflow",
        ])
        .unwrap();

        assert_eq!(random.options.strategy, FuzzStrategy::RandomPayload);
        assert_eq!(byte_overflow.options.strategy, FuzzStrategy::Boundary);
    }

    #[cfg(feature = "fuzz")]
    #[test]
    fn fuzz_count_rejects_zero_and_delay_allows_zero() {
        let err = FuzzHarness::try_parse_from([
            "test",
            "--target",
            "192.0.2.1",
            "--protocol",
            "icmp",
            "--count",
            "0",
        ])
        .unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);

        let parsed = FuzzHarness::try_parse_from([
            "test",
            "--target",
            "192.0.2.1",
            "--protocol",
            "icmp",
            "--delay",
            "0",
        ])
        .unwrap();

        assert_eq!(parsed.options.delay, 0);
    }

    #[cfg(feature = "scan")]
    #[derive(Debug, Parser)]
    struct ScanHarness {
        #[command(subcommand)]
        command: ScanCommand,
    }

    #[cfg(feature = "scan")]
    fn parse_scan(args: &[&str]) -> ScanCommand {
        ScanHarness::try_parse_from(std::iter::once("test").chain(args.iter().copied()))
            .unwrap()
            .command
    }

    #[cfg(feature = "scan")]
    #[test]
    fn scan_parser_selects_each_subcommand_variant() {
        assert!(matches!(
            parse_scan(&["tcp-syn", "--target", "192.0.2.1", "--ports", "80"]),
            ScanCommand::TcpSyn(options)
                if options.target == "192.0.2.1" && options.ports == "80"
        ));
        assert!(matches!(
            parse_scan(&["tcp-fin", "--target", "192.0.2.1", "--ports", "80"]),
            ScanCommand::TcpFin(options)
                if options.target == "192.0.2.1" && options.ports == "80"
        ));
        assert!(matches!(
            parse_scan(&["tcp-null", "--target", "192.0.2.1", "--ports", "80"]),
            ScanCommand::TcpNull(options)
                if options.target == "192.0.2.1" && options.ports == "80"
        ));
        assert!(matches!(
            parse_scan(&["tcp-xmas", "--target", "192.0.2.1", "--ports", "80"]),
            ScanCommand::TcpXmas(options)
                if options.target == "192.0.2.1" && options.ports == "80"
        ));
        assert!(matches!(
            parse_scan(&["tcp-ack", "--target", "192.0.2.1", "--ports", "80"]),
            ScanCommand::TcpAck(options)
                if options.target == "192.0.2.1" && options.ports == "80"
        ));
        assert!(matches!(
            parse_scan(&["sctp-init", "--target", "192.0.2.1", "--ports", "9899"]),
            ScanCommand::SctpInit(options)
                if options.target == "192.0.2.1" && options.ports == "9899"
        ));
        assert!(matches!(
            parse_scan(&["icmp", "--target", "192.0.2.0/30", "--timeout", "250"]),
            ScanCommand::Icmp(options)
                if options.target == "192.0.2.0/30" && options.timeout == 250
        ));
        assert!(matches!(
            parse_scan(&["udp", "--target", "192.0.2.1", "--ports", "53"]),
            ScanCommand::Udp(options)
                if options.target == "192.0.2.1" && options.ports == "53"
        ));
        assert!(matches!(
            parse_scan(&["arp", "--target", "192.0.2.0/30", "--timeout", "250"]),
            ScanCommand::Arp(options)
                if options.target == "192.0.2.0/30" && options.timeout == 250
        ));
        assert!(matches!(
            parse_scan(&["ndp", "--target", "2001:db8::/126", "--timeout", "250"]),
            ScanCommand::Ndp(options)
                if options.target == "2001:db8::/126" && options.timeout == 250
        ));
    }

    #[cfg(feature = "scan")]
    #[test]
    fn timed_scan_timeout_rejects_zero() {
        for args in [
            ["icmp", "--target", "192.0.2.0/30", "--timeout", "0"].as_slice(),
            ["arp", "--target", "192.0.2.0/30", "--timeout", "0"].as_slice(),
            ["ndp", "--target", "2001:db8::/126", "--timeout", "0"].as_slice(),
        ] {
            let err =
                ScanHarness::try_parse_from(std::iter::once("test").chain(args.iter().copied()))
                    .unwrap_err();

            assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        }
    }
}
