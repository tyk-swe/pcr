// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use clap::builder::BoolishValueParser;
#[cfg(any(not(feature = "pcap"), not(feature = "metrics")))]
use clap::builder::TypedValueParser;
use clap::{value_parser, Args, Subcommand};
use serde::{Deserialize, Serialize};

use super::enums::{FragmentProfile, Icmpv6ErrorCode, Icmpv6ErrorKind, LogLevel};
#[cfg(feature = "metrics")]
use super::validators::socket_addr_validator;
use super::validators::{dns_record_type_validator, mac_address_validator};

#[cfg(not(feature = "pcap"))]
fn unsupported_pcap_bool(value: &str) -> Result<bool, String> {
    unsupported_feature_bool(value, "pcap")
}

#[cfg(not(feature = "pcap"))]
fn unsupported_pcap_string(_: &str) -> Result<String, String> {
    Err("this flag requires packetcraftr to be built with the 'pcap' feature".to_string())
}

#[cfg(not(feature = "pcap"))]
fn unsupported_pcap_u64(_: &str) -> Result<u64, String> {
    Err("this flag requires packetcraftr to be built with the 'pcap' feature".to_string())
}

#[cfg(not(feature = "pcap"))]
fn unsupported_pcap_usize(_: &str) -> Result<usize, String> {
    Err("this flag requires packetcraftr to be built with the 'pcap' feature".to_string())
}

#[cfg(not(feature = "metrics"))]
fn unsupported_metrics_bool(value: &str) -> Result<bool, String> {
    unsupported_feature_bool(value, "metrics")
}

#[cfg(not(feature = "metrics"))]
fn unsupported_metrics_string(_: &str) -> Result<String, String> {
    Err("this flag requires packetcraftr to be built with the 'metrics' feature".to_string())
}

#[cfg(any(not(feature = "pcap"), not(feature = "metrics")))]
fn unsupported_feature_bool(value: &str, feature: &str) -> Result<bool, String> {
    let cmd = clap::Command::new("packetcraftr");

    match BoolishValueParser::new().parse_ref(&cmd, None, std::ffi::OsStr::new(value)) {
        Ok(false) => Ok(false),
        _ => Err(format!(
            "this flag requires packetcraftr to be built with the '{feature}' feature"
        )),
    }
}

/// Default one-shot packet crafting configuration.
#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub(crate) struct OneShotOptions {
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
pub(crate) struct SendOptions {
    #[command(flatten, next_help_heading = "One-shot packet crafting")]
    pub oneshot: OneShotOptions,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub(crate) struct Layer2Options {
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
pub(crate) struct VlanOptions {
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
pub(crate) struct IpOptions {
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
pub(crate) enum TransportCommand {
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
pub(crate) struct UdpOptions {}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub(crate) struct TransportOptions {
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
pub(crate) struct TcpOptions {
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
pub(crate) struct IcmpOptions {
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
pub(crate) struct Icmpv6Options {
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
pub(crate) struct PayloadOptions {
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
pub(crate) struct TransmitOptions {
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
pub(crate) struct ListenOptions {
    /// Listen for replies after sending.
    #[cfg_attr(
        feature = "pcap",
        arg(
            long = "listen-reply",
            action = clap::ArgAction::Set,
            value_parser = BoolishValueParser::new(),
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true"
        )
    )]
    #[cfg_attr(
        not(feature = "pcap"),
        arg(
            long = "listen-reply",
            action = clap::ArgAction::Set,
            value_parser = unsupported_pcap_bool,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true",
            hide = true
        )
    )]
    pub listen: Option<bool>,
    /// BPF filter expression (e.g., "tcp port 80", "icmp", "host 10.0.0.1 and udp").
    /// Uses tcpdump/libpcap syntax. See <https://www.tcpdump.org/manpages/pcap-filter.7.html>
    #[cfg_attr(feature = "pcap", arg(long = "filter"))]
    #[cfg_attr(
        not(feature = "pcap"),
        arg(long = "filter", value_parser = unsupported_pcap_string, hide = true)
    )]
    pub filter: Option<String>,
    /// Enable promiscuous mode.
    #[cfg_attr(
        feature = "pcap",
        arg(
            long = "promisc",
            action = clap::ArgAction::Set,
            value_parser = BoolishValueParser::new(),
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true"
        )
    )]
    #[cfg_attr(
        not(feature = "pcap"),
        arg(
            long = "promisc",
            action = clap::ArgAction::Set,
            value_parser = unsupported_pcap_bool,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true",
            hide = true
        )
    )]
    pub promiscuous: Option<bool>,
    /// Show reply packets in output.
    #[cfg_attr(
        feature = "pcap",
        arg(
            long = "show-reply",
            action = clap::ArgAction::Set,
            value_parser = BoolishValueParser::new(),
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true"
        )
    )]
    #[cfg_attr(
        not(feature = "pcap"),
        arg(
            long = "show-reply",
            action = clap::ArgAction::Set,
            value_parser = unsupported_pcap_bool,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true",
            hide = true
        )
    )]
    pub show_reply: Option<bool>,
    /// Listen timeout (in seconds).
    #[cfg_attr(feature = "pcap", arg(long = "timeout", value_parser = value_parser!(u64)))]
    #[cfg_attr(
        not(feature = "pcap"),
        arg(long = "timeout", value_parser = unsupported_pcap_u64, hide = true)
    )]
    pub timeout: Option<u64>,
    /// Save captured packets to a pcap file.
    #[cfg_attr(feature = "pcap", arg(long = "pcap-save"))]
    #[cfg_attr(
        not(feature = "pcap"),
        arg(long = "pcap-save", value_parser = unsupported_pcap_string, hide = true)
    )]
    pub capture_file: Option<String>,
    /// Internal queue capacity.
    #[cfg_attr(
        feature = "pcap",
        arg(long = "queue-capacity", value_parser = clap::value_parser!(usize))
    )]
    #[cfg_attr(
        not(feature = "pcap"),
        arg(long = "queue-capacity", value_parser = unsupported_pcap_usize, hide = true)
    )]
    pub queue_capacity: Option<usize>,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub(crate) struct RuleOptions {
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
pub(crate) struct SafetyOptions {
    /// Allow packet-producing commands to target public IP addresses.
    #[arg(long = "allow-public-targets", global = true)]
    pub allow_public_targets: bool,
    /// Allow malformed packet shapes such as overlap or teardrop fragments.
    #[arg(long = "allow-malformed", global = true)]
    pub allow_malformed: bool,
    /// Allow plans that exceed recommended traffic defaults when explicit caps are raised.
    #[arg(long = "allow-high-volume", global = true)]
    pub allow_high_volume: bool,
    /// Maximum expanded target count.
    #[arg(long = "traffic-max-targets", global = true, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
    pub traffic_max_targets: Option<usize>,
    /// Maximum expanded port count.
    #[arg(long = "traffic-max-ports", global = true, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
    pub traffic_max_ports: Option<usize>,
    /// Maximum estimated packet count.
    #[arg(long = "traffic-max-packets", global = true, value_parser = value_parser!(u64).range(1..))]
    pub traffic_max_packets: Option<u64>,
    /// Maximum send batch size.
    #[arg(long = "traffic-batch-size", global = true, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
    pub traffic_batch_size: Option<usize>,
    /// Maximum send rate in packets per second.
    #[arg(long = "traffic-rate", global = true, value_parser = value_parser!(u64).range(1..))]
    pub traffic_rate: Option<u64>,
}

#[derive(Debug, Default, Clone, Args, Serialize, Deserialize)]
pub(crate) struct LoggingOptions {
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
    #[cfg_attr(feature = "pcap", arg(long = "pcap-write"))]
    #[cfg_attr(
        not(feature = "pcap"),
        arg(long = "pcap-write", value_parser = unsupported_pcap_string, hide = true)
    )]
    pub pcap_write: Option<String>,
    /// Save a metrics snapshot to a JSON file.
    #[cfg_attr(feature = "metrics", arg(long = "metrics-json"))]
    #[cfg_attr(
        not(feature = "metrics"),
        arg(long = "metrics-json", value_parser = unsupported_metrics_string, hide = true)
    )]
    pub metrics_json: Option<String>,
    /// Prometheus bind address.
    #[cfg_attr(
        feature = "metrics",
        arg(long = "prometheus-bind", value_parser = socket_addr_validator)
    )]
    #[cfg_attr(
        not(feature = "metrics"),
        arg(long = "prometheus-bind", value_parser = unsupported_metrics_string, hide = true)
    )]
    pub prometheus_bind: Option<String>,
    /// Allow public access to metrics.
    #[cfg_attr(
        feature = "metrics",
        arg(
            long = "allow-public-metrics",
            action = clap::ArgAction::Set,
            value_parser = BoolishValueParser::new(),
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true"
        )
    )]
    #[cfg_attr(
        not(feature = "metrics"),
        arg(
            long = "allow-public-metrics",
            action = clap::ArgAction::Set,
            value_parser = unsupported_metrics_bool,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true",
            hide = true
        )
    )]
    pub allow_public_metrics: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct OneShotHarness {
        #[command(flatten)]
        options: OneShotOptions,
    }

    #[derive(Debug, Parser)]
    struct SafetyHarness {
        #[command(flatten)]
        options: SafetyOptions,
    }

    #[derive(Debug, Parser)]
    struct LoggingHarness {
        #[command(flatten)]
        options: LoggingOptions,
    }

    fn parse_oneshot(args: &[&str]) -> Result<OneShotHarness, clap::Error> {
        OneShotHarness::try_parse_from(std::iter::once("test").chain(args.iter().copied()))
    }

    fn parse_safety(args: &[&str]) -> Result<SafetyHarness, clap::Error> {
        SafetyHarness::try_parse_from(std::iter::once("test").chain(args.iter().copied()))
    }

    fn parse_logging(args: &[&str]) -> Result<LoggingHarness, clap::Error> {
        LoggingHarness::try_parse_from(std::iter::once("test").chain(args.iter().copied()))
    }

    #[test]
    fn boolish_ip_preference_flags_accept_missing_and_explicit_values() {
        let implicit = parse_oneshot(&["--prefer-ipv4"]).unwrap();
        let explicit_false = parse_oneshot(&["--prefer-ipv6=false"]).unwrap();
        let explicit_true = parse_oneshot(&["--prefer-ipv6=true"]).unwrap();

        assert_eq!(implicit.options.ip.prefer_ipv4, Some(true));
        assert_eq!(explicit_false.options.ip.prefer_ipv6, Some(false));
        assert_eq!(explicit_true.options.ip.prefer_ipv6, Some(true));
    }

    #[test]
    fn ip_preference_flags_conflict_even_when_values_are_explicit() {
        let err = parse_oneshot(&["--prefer-ipv4=true", "--prefer-ipv6=false"]).unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn fragment_control_flags_accept_boolish_values_and_reject_conflicts() {
        let mf = parse_oneshot(&["--mf-flag=false"]).unwrap();
        let df = parse_oneshot(&["--df-flag"]).unwrap();
        let err = parse_oneshot(&["--mf-flag", "--df-flag"]).unwrap_err();

        assert_eq!(mf.options.ip.more_fragments, Some(false));
        assert_eq!(df.options.ip.dont_fragment, Some(true));
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn fragmentation_profiles_conflict_with_named_fragment_modes() {
        let overlap_err =
            parse_oneshot(&["--frag-overlap", "--frag-profile", "overlap"]).unwrap_err();
        let teardrop_err =
            parse_oneshot(&["--teardrop", "--frag-profile", "teardrop"]).unwrap_err();

        assert_eq!(overlap_err.kind(), clap::error::ErrorKind::ArgumentConflict);
        assert_eq!(
            teardrop_err.kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn vlan_ranges_accept_protocol_boundaries() {
        let low = parse_oneshot(&["--vlan-id", "1", "--vlan-prio", "0"]).unwrap();
        let high = parse_oneshot(&["--vlan-id", "4094", "--vlan-prio", "7"]).unwrap();

        assert_eq!(low.options.layer2.vlan.id, Some(1));
        assert_eq!(low.options.layer2.vlan.priority, Some(0));
        assert_eq!(high.options.layer2.vlan.id, Some(4094));
        assert_eq!(high.options.layer2.vlan.priority, Some(7));
    }

    #[test]
    fn vlan_ranges_reject_reserved_ids_and_priority_overflow() {
        let low_id = parse_oneshot(&["--vlan-id", "0"]).unwrap_err();
        let high_id = parse_oneshot(&["--vlan-id", "4095"]).unwrap_err();
        let priority = parse_oneshot(&["--vlan-id", "10", "--vlan-prio", "8"]).unwrap_err();

        assert_eq!(low_id.kind(), clap::error::ErrorKind::ValueValidation);
        assert_eq!(high_id.kind(), clap::error::ErrorKind::ValueValidation);
        assert_eq!(priority.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn tcp_window_scale_accepts_legal_maximum_and_rejects_next_value() {
        let parsed = parse_oneshot(&["tcp", "--tcp-window-scale", "14"]).unwrap();
        let err = parse_oneshot(&["tcp", "--tcp-window-scale", "15"]).unwrap_err();

        let Some(TransportCommand::Tcp(tcp)) = parsed.options.transport.command else {
            panic!("expected TCP subcommand");
        };
        assert_eq!(tcp.window_scale, Some(14));
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn tcp_raw_options_conflict_with_structured_tcp_options() {
        let err = parse_oneshot(&["tcp", "--tcp-options-hex", "020405b4", "--tcp-mss", "1460"])
            .unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn payload_sources_are_mutually_exclusive() {
        let err = parse_oneshot(&["--data", "hello", "--data-hex", "6869"]).unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn dns_type_requires_dns_query_payload() {
        let err = parse_oneshot(&["--dns-type", "AAAA"]).unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn traffic_caps_reject_zero_values() {
        for flag in [
            "--traffic-max-targets",
            "--traffic-max-ports",
            "--traffic-max-packets",
            "--traffic-batch-size",
            "--traffic-rate",
        ] {
            let err = parse_safety(&[flag, "0"]).unwrap_err();
            assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        }
    }

    #[test]
    fn traffic_caps_accept_positive_values() {
        let parsed = parse_safety(&[
            "--traffic-max-targets",
            "1",
            "--traffic-max-ports",
            "2",
            "--traffic-max-packets",
            "3",
            "--traffic-batch-size",
            "4",
            "--traffic-rate",
            "5",
        ])
        .unwrap();

        assert_eq!(parsed.options.traffic_max_targets, Some(1));
        assert_eq!(parsed.options.traffic_max_ports, Some(2));
        assert_eq!(parsed.options.traffic_max_packets, Some(3));
        assert_eq!(parsed.options.traffic_batch_size, Some(4));
        assert_eq!(parsed.options.traffic_rate, Some(5));
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn prometheus_bind_uses_socket_address_validator() {
        let parsed = parse_logging(&["--prometheus-bind", "127.0.0.1:9898"]).unwrap();
        let err = parse_logging(&["--prometheus-bind", "127.0.0.1"]).unwrap_err();

        assert_eq!(
            parsed.options.prometheus_bind.as_deref(),
            Some("127.0.0.1:9898")
        );
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn logging_boolish_flags_accept_missing_and_explicit_values() {
        let structured = parse_logging(&["--log-structured"]).unwrap();

        assert_eq!(structured.options.structured, Some(true));
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_boolish_flags_accept_missing_and_explicit_values() {
        let public_metrics = parse_logging(&["--allow-public-metrics=false"]).unwrap();

        assert_eq!(public_metrics.options.allow_public_metrics, Some(false));
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn oneshot_parser_accepts_explicit_false_for_pcap_only_bool_flags() {
        let parsed = parse_oneshot(&[
            "--listen-reply=false",
            "--promisc=false",
            "--show-reply=false",
        ])
        .unwrap();

        assert_eq!(parsed.options.listen.listen, Some(false));
        assert_eq!(parsed.options.listen.promiscuous, Some(false));
        assert_eq!(parsed.options.listen.show_reply, Some(false));
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn oneshot_parser_rejects_pcap_only_flags_before_request_mapping() {
        for args in [
            ["--listen-reply"].as_slice(),
            ["--filter", "icmp"].as_slice(),
            ["--promisc"].as_slice(),
            ["--show-reply"].as_slice(),
            ["--pcap-save", "reply.pcap"].as_slice(),
            ["--queue-capacity", "64"].as_slice(),
        ] {
            let err = parse_oneshot(args).unwrap_err();

            assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
            assert!(err.to_string().contains("'pcap' feature"));
        }
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn logging_parser_rejects_pcap_write_before_request_mapping() {
        let err = parse_logging(&["--pcap-write", "sent.pcap"]).unwrap_err();

        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
        assert!(err.to_string().contains("'pcap' feature"));
    }

    #[cfg(not(feature = "metrics"))]
    #[test]
    fn logging_parser_accepts_explicit_false_for_metrics_only_bool_flags() {
        let parsed = parse_logging(&["--allow-public-metrics=false"]).unwrap();

        assert_eq!(parsed.options.allow_public_metrics, Some(false));
    }

    #[cfg(not(feature = "metrics"))]
    #[test]
    fn logging_parser_rejects_metrics_flags_before_request_mapping() {
        for args in [
            ["--metrics-json", "metrics.json"].as_slice(),
            ["--prometheus-bind", "127.0.0.1:9898"].as_slice(),
            ["--allow-public-metrics"].as_slice(),
        ] {
            let err = parse_logging(args).unwrap_err();

            assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
            assert!(err.to_string().contains("'metrics' feature"));
        }
    }
}
