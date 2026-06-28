// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use clap::builder::BoolishValueParser;
use clap::{value_parser, Args, Subcommand};
use serde::{Deserialize, Serialize};

use super::enums::{FragmentProfile, Icmpv6ErrorCode, Icmpv6ErrorKind, LogLevel};
use super::validators::{dns_record_type_validator, mac_address_validator, socket_addr_validator};

/// Default one-shot packet crafting configuration.
#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct OneShotOptions {
    /// Destination IP address or hostname.
    #[arg(short = 'd', long = "dest")]
    pub destination: Option<String>,
    #[command(flatten, next_help_heading = "Layer 2 options")]
    pub layer2: Layer2Options,
    #[command(flatten, next_help_heading = "IP options")]
    pub ip: IpOptions,
    #[command(flatten, next_help_heading = "Transport options")]
    pub transport: TransportOptions,
    #[command(flatten, next_help_heading = "Payload options")]
    pub payload: PayloadOptions,
    #[command(flatten, next_help_heading = "Transmission control")]
    pub transmit: TransmitOptions,
    #[command(flatten, next_help_heading = "Listener options")]
    pub listen: ListenOptions,
    #[command(flatten, next_help_heading = "Automation")]
    pub rule: RuleOptions,
    #[command(flatten, next_help_heading = "Logging")]
    pub logging: LoggingOptions,
}

/// Stable packet send command options.
#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct SendOptions {
    #[command(flatten, next_help_heading = "One-shot packet crafting")]
    pub oneshot: OneShotOptions,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct Layer2Options {
    /// Source MAC address (e.g., aa:bb:cc:dd:ee:ff).
    #[arg(long = "smac", value_parser = mac_address_validator)]
    pub source_mac: Option<String>,
    /// Destination MAC address (e.g., 11:22:33:44:55:66).
    #[arg(long = "dmac", value_parser = mac_address_validator)]
    pub destination_mac: Option<String>,
    /// EtherType (e.g., 0x0800, IPv4, IPv6, ARP).
    #[arg(long = "ethertype")]
    pub ethertype: Option<String>,
    #[command(flatten, next_help_heading = "VLAN options")]
    #[serde(default)]
    /// Configure VLAN tagging options. Defaults ensure compatibility with legacy profiles.
    pub vlan: VlanOptions,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct VlanOptions {
    /// VLAN ID (1-4094).
    #[arg(long = "vlan-id", value_parser = value_parser!(u16).range(1..=4094))]
    pub id: Option<u16>,
    /// VLAN priority (0-7).
    #[arg(long = "vlan-prio", value_parser = value_parser!(u8).range(0..=7))]
    pub priority: Option<u8>,
    /// Drop Eligible Indicator (DEI) bit.
    #[arg(
        long = "vlan-dei",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub drop_eligible_indicator: Option<bool>,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct IpOptions {
    /// Source IP address (e.g., 192.168.1.10, fe80::1).
    #[arg(long = "sip")]
    pub source_ip: Option<String>,
    /// Destination IP address (overrides -d/--dest).
    #[arg(long = "dip")]
    pub destination_ip: Option<String>,
    /// Prefer IPv6 address resolution.
    #[arg(
        long = "prefer-ipv6",
        conflicts_with = "prefer_ipv4",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub prefer_ipv6: Option<bool>,
    /// Prefer IPv4 address resolution.
    #[arg(
        long = "prefer-ipv4",
        conflicts_with = "prefer_ipv6",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub prefer_ipv4: Option<bool>,
    /// TTL (IPv4) or Hop Limit (IPv6) [default: 64].
    #[arg(long = "ttl", value_parser = value_parser!(u8))]
    pub ttl: Option<u8>,
    /// Type of Service (IPv4) or Traffic Class (IPv6) [default: 0].
    #[arg(long = "tos", value_parser = value_parser!(u8))]
    pub tos: Option<u8>,
    /// IP Identification field (IPv4) [default: random].
    #[arg(long = "id", value_parser = value_parser!(u16))]
    pub identification: Option<u16>,
    /// MTU for fragmentation (fragments if payload exceeds this).
    #[arg(long = "frag", value_parser = value_parser!(u16))]
    pub fragment_mtu: Option<u16>,
    /// Manual fragment offset.
    #[arg(long = "frag-offset", value_parser = value_parser!(u16))]
    pub fragment_offset: Option<u16>,
    /// Force the More Fragments (MF) flag.
    #[arg(
        long = "mf-flag",
        conflicts_with = "dont_fragment",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub more_fragments: Option<bool>,
    /// Force the Don't Fragment (DF) flag.
    #[arg(
        long = "df-flag",
        conflicts_with = "more_fragments",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub dont_fragment: Option<bool>,
    /// Generate overlapping fragments.
    #[arg(
        long = "frag-overlap",
        conflicts_with_all = &["teardrop", "fragment_profile"],
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub fragment_overlap: Option<bool>,
    /// Generate teardrop fragments.
    #[arg(
        long = "teardrop",
        conflicts_with_all = &["fragment_overlap", "fragment_profile"],
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub teardrop: Option<bool>,
    /// Apply a specific fragmentation profile.
    #[arg(long = "frag-profile", value_enum, conflicts_with_all = &["fragment_overlap", "teardrop"])]
    pub fragment_profile: Option<FragmentProfile>,
    /// IPv6 Fragment ID.
    #[arg(long = "frag-id", value_parser = value_parser!(u32))]
    pub fragment_id: Option<u32>,
    /// Add IPv6 extension headers.
    #[arg(long = "ipv6-ext", action = clap::ArgAction::Append)]
    #[serde(default)]
    pub ipv6_extensions: Vec<String>,
}

#[derive(Debug, Subcommand, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportCommand {
    /// Craft TCP packets.
    Tcp(TcpOptions),
    /// Craft UDP packets.
    Udp(UdpOptions),
    /// Craft ICMP packets.
    Icmp(IcmpOptions),
    /// Craft ICMPv6 packets.
    Icmpv6(Icmpv6Options),
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct UdpOptions {}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct TransportOptions {
    #[command(subcommand)]
    pub command: Option<TransportCommand>,
    /// Set the source port (0-65535).
    #[arg(long = "sport", value_parser = value_parser!(u16), global = true)]
    pub source_port: Option<u16>,
    /// Set the destination port (0-65535).
    #[arg(long = "dport", value_parser = value_parser!(u16), global = true)]
    pub destination_port: Option<u16>,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct TcpOptions {
    /// Set TCP flags (available: S, A, F, R, P, U, E, C).
    #[arg(long = "flags")]
    pub flags: Option<String>,
    /// TCP sequence number [default: random].
    #[arg(long = "seq", value_parser = value_parser!(u32))]
    pub sequence: Option<u32>,
    /// TCP acknowledgement number [default: 0].
    #[arg(long = "ack", value_parser = value_parser!(u32))]
    pub acknowledgement: Option<u32>,
    /// TCP window size [default: 64240].
    #[arg(long = "window", value_parser = value_parser!(u16))]
    pub window_size: Option<u16>,
    /// TCP Maximum Segment Size (MSS) option.
    #[arg(long = "tcp-mss", value_parser = value_parser!(u16))]
    pub mss: Option<u16>,
    /// TCP window scale option (0-14).
    #[arg(long = "tcp-window-scale", value_parser = value_parser!(u8).range(0..=14))]
    pub window_scale: Option<u8>,
    /// Enable the TCP SACK Permitted option.
    #[arg(
        long = "tcp-sack-permitted",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub sack_permitted: Option<bool>,
    /// TCP timestamp option (format: val:echo e.g., 123:0).
    #[arg(long = "tcp-timestamps")]
    pub timestamps: Option<String>,
    /// Raw TCP options (as a hex string, e.g., 020405b4).
    #[arg(long = "tcp-options-hex", conflicts_with_all = &["mss", "window_scale", "sack_permitted", "timestamps"])]
    pub options_hex: Option<String>,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct IcmpOptions {
    /// ICMP type (e.g., 8=Echo Request, 0=Echo Reply).
    #[arg(long = "icmp-type", value_parser = value_parser!(u8))]
    pub kind: Option<u8>,
    /// ICMP code.
    #[arg(long = "icmp-code", value_parser = value_parser!(u8))]
    pub code: Option<u8>,
    /// ICMP identifier.
    #[arg(long = "icmp-id", value_parser = value_parser!(u16))]
    pub identifier: Option<u16>,
    /// ICMP sequence number.
    #[arg(long = "icmp-seq", value_parser = value_parser!(u16))]
    pub sequence: Option<u16>,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct Icmpv6Options {
    /// ICMPv6 type.
    #[arg(long = "icmpv6-type", value_parser = value_parser!(u8))]
    pub kind: Option<u8>,
    /// ICMPv6 code.
    #[arg(long = "icmpv6-code", value_parser = value_parser!(u8))]
    pub code: Option<u8>,
    /// ICMPv6 identifier.
    #[arg(long = "icmpv6-id", value_parser = value_parser!(u16))]
    pub identifier: Option<u16>,
    /// ICMPv6 sequence number.
    #[arg(long = "icmpv6-seq", value_parser = value_parser!(u16))]
    pub sequence: Option<u16>,
    /// ICMPv6 parameter.
    #[arg(long = "param", value_parser = value_parser!(u32))]
    pub parameter: Option<u32>,
    /// ICMPv6 error family.
    #[arg(long = "error", value_enum)]
    pub error: Option<Icmpv6ErrorKind>,
    /// ICMPv6 error code.
    #[arg(long = "error-code", value_enum)]
    pub error_code: Option<Icmpv6ErrorCode>,
    /// MTU for Packet Too Big messages.
    #[arg(long = "mtu", value_parser = value_parser!(u32))]
    pub mtu: Option<u32>,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct PayloadOptions {
    /// Inline string payload (e.g., "GET / HTTP/1.0").
    #[arg(long = "data", group = "payload_source", global = true)]
    pub data: Option<String>,
    /// Payload from a hex string (e.g., deadbeef).
    #[arg(long = "data-hex", group = "payload_source", global = true)]
    pub data_hex: Option<String>,
    /// Load the payload from a file.
    #[arg(long = "data-file", group = "payload_source", global = true)]
    pub data_file: Option<String>,
    /// Size for a random payload.
    #[arg(long = "rand-payload", value_parser = value_parser!(usize), group = "payload_source", global = true)]
    pub random_payload_size: Option<usize>,

    /// DNS query payload.
    #[arg(long = "dns-query", group = "payload_source", global = true)]
    pub dns_query: Option<String>,
    /// DNS record type.
    #[arg(long = "dns-type", requires = "dns_query", value_parser = dns_record_type_validator, global = true)]
    pub dns_type: Option<String>,

    /// HTTP method.
    #[arg(long = "http-method", group = "payload_source", global = true)]
    pub http_method: Option<String>,
    /// HTTP path.
    #[arg(long = "http-path", requires = "http_method", global = true)]
    pub http_path: Option<String>,
    /// HTTP Host header.
    #[arg(long = "http-host", requires = "http_method", global = true)]
    pub http_host: Option<String>,

    /// TLS Client Hello (SNI).
    #[arg(long = "tls-hello", group = "payload_source", global = true)]
    pub tls_client_hello: Option<String>,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct TransmitOptions {
    /// Number of packets to send; must be greater than zero [default: 1].
    #[arg(long = "count", value_parser = value_parser!(u64))]
    pub count: Option<u64>,
    /// Send interval (e.g., 1s, 500ms, 100us).
    #[arg(long = "interval")]
    pub interval: Option<String>,
    /// Enable flood mode (no delay between packets); requires --count unless unbounded sends are explicitly allowed.
    #[arg(
        long = "flood",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub flood: Option<bool>,
    /// Loop sending packets forever; requires --allow-unbounded-sends.
    #[arg(
        long = "loop",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub loop_forever: Option<bool>,
    /// Network interface to use.
    #[arg(long = "interface")]
    pub interface: Option<String>,
    /// Force Layer 3 (IP-only) transmission.
    #[arg(
        long = "force-layer3",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub force_layer3: Option<bool>,
    /// Force IPv6 Neighbor Discovery (NDP).
    #[arg(
        long = "ipv6-nd",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub ipv6_nd: Option<bool>,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct ListenOptions {
    /// Listen for replies after sending.
    #[arg(
        long = "listen-reply",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    #[cfg_attr(not(feature = "pcap"), arg(hide = true))]
    pub listen: Option<bool>,
    /// BPF filter expression (e.g., "tcp port 80", "icmp", "host 10.0.0.1 and udp").
    /// Uses tcpdump/libpcap syntax. See <https://www.tcpdump.org/manpages/pcap-filter.7.html>
    #[arg(long = "filter")]
    #[cfg_attr(not(feature = "pcap"), arg(hide = true))]
    pub filter: Option<String>,
    /// Enable promiscuous mode.
    #[arg(
        long = "promisc",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    #[cfg_attr(not(feature = "pcap"), arg(hide = true))]
    pub promiscuous: Option<bool>,
    /// Show reply packets in output.
    #[arg(
        long = "show-reply",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    #[cfg_attr(not(feature = "pcap"), arg(hide = true))]
    pub show_reply: Option<bool>,
    /// Listen timeout (in seconds).
    #[arg(long = "timeout", value_parser = value_parser!(u64))]
    #[cfg_attr(not(feature = "pcap"), arg(hide = true))]
    pub timeout: Option<u64>,
    /// Save captured packets to a pcap file.
    #[arg(long = "pcap-save")]
    #[cfg_attr(not(feature = "pcap"), arg(hide = true))]
    pub capture_file: Option<String>,
    /// Internal queue capacity.
    #[arg(long = "queue-capacity", value_parser = clap::value_parser!(usize))]
    #[cfg_attr(not(feature = "pcap"), arg(hide = true))]
    pub queue_capacity: Option<usize>,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct RuleOptions {
    /// Path to the rules file.
    #[arg(long = "rules")]
    pub rules_file: Option<String>,
    /// Number of rule worker threads.
    #[arg(long = "rule-workers", value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
    pub rule_workers: Option<usize>,
    /// Rule queue size.
    #[arg(long = "rule-queue")]
    pub rule_queue: Option<usize>,
    /// Number of send worker threads.
    #[arg(long = "send-workers", value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
    pub send_workers: Option<usize>,
    /// Send queue size.
    #[arg(long = "send-queue")]
    pub send_queue: Option<usize>,
    /// Allow explicitly unbounded loop or flood sends.
    #[arg(long = "allow-unbounded-sends")]
    pub allow_unbounded_sends: bool,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub struct LoggingOptions {
    /// Log output to a file.
    #[arg(long = "log-file")]
    pub log_file: Option<String>,
    /// Override the log level.
    #[arg(long = "log-level", value_enum)]
    pub log_level: Option<LogLevel>,
    /// Enable structured JSON logging.
    #[arg(
        long = "log-structured",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub structured: Option<bool>,
    /// Write sent packets to a pcap file.
    #[arg(long = "pcap-write")]
    #[cfg_attr(not(feature = "pcap"), arg(hide = true))]
    pub pcap_write: Option<String>,
    /// Save a metrics snapshot to a JSON file.
    #[arg(long = "metrics-json")]
    #[cfg_attr(not(feature = "metrics"), arg(hide = true))]
    pub metrics_json: Option<String>,
    /// Prometheus bind address.
    #[arg(long = "prometheus-bind", value_parser = socket_addr_validator)]
    #[cfg_attr(not(feature = "metrics"), arg(hide = true))]
    pub prometheus_bind: Option<String>,
    /// Allow public access to metrics.
    #[arg(
        long = "allow-public-metrics",
        action = clap::ArgAction::Set,
        value_parser = BoolishValueParser::new(),
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    #[cfg_attr(not(feature = "metrics"), arg(hide = true))]
    pub allow_public_metrics: Option<bool>,
}
