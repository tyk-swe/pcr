// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::dns::QueryType;

use crate::command_options::{
    AddressFamily, CaptureLimitsArgs, HostnamePolicyArgs, RouteSelectionArgs,
};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr dns 192.0.2.53 example.test --type a
  packetcraftr dns 127.0.0.1 example.test --tcp
  packetcraftr --output json dns 192.0.2.53 _service._tcp.example.test --type srv
  packetcraftr dns 192.0.2.53 example.test --udp-only --help"#;

pub(crate) const LONG_ABOUT: &str = "Run bounded, policy-gated DNS queries. By default, each attempt starts over UDP and one validated matching truncated response may continue over TCP to the same reauthorized numeric server. --tcp queries directly over ordinary TCP sockets without raw capture. Both modes retain the --timeout-ms attempt window and bounded retries. --udp-only disables fallback and supports packet-oriented route overrides that kernel TCP cannot preserve. Text, JSON, and NDJSON identify each attempted phase and the accepted response transport; direct TCP reports fallback_attempted=false.";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Explicit DNS server IP address or hostname.
    #[arg(value_name = "SERVER")]
    pub(crate) server: String,
    /// Bounded ASCII DNS owner name to query.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
    /// DNS type alias, decimal code, or TYPE<n> (0..=65535; at most five digits).
    #[arg(long = "type", default_value_t = QueryType::A)]
    pub(crate) query_type: QueryType,
    /// Select the first authorized server address or one IP family.
    #[arg(long, value_enum, default_value_t = AddressFamily::Any)]
    pub(crate) family: AddressFamily,
    /// DNS server port for the selected UDP/TCP transport.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_SERVER_PORT)]
    pub(crate) port: u16,
    /// Explicit 16-bit transaction ID; a process-local value is generated when omitted.
    #[arg(long)]
    pub(crate) transaction_id: Option<u16>,
    /// First UDP source port; kernel TCP uses an OS-selected local port.
    #[arg(long)]
    pub(crate) source_port: Option<u16>,
    /// Disable the recursion-desired query flag.
    #[arg(long)]
    pub(crate) no_recursion: bool,
    /// Enable EDNS v0 with this advertised UDP response size (512..=65535).
    /// Capture and decoding limits remain independently configured.
    #[arg(long, value_parser = clap::value_parser!(u16).range(512..))]
    pub(crate) edns_udp_payload_size: Option<u16>,
    /// Request DNSSEC records via EDNS DO; does not validate signatures.
    #[arg(long, requires = "edns_udp_payload_size")]
    pub(crate) dnssec_ok: bool,
    /// Keep DNS attempts UDP-only and report validated truncation as terminal.
    #[arg(long)]
    pub(crate) udp_only: bool,
    /// Query over ordinary TCP sockets directly, without a UDP probe or raw capture.
    /// TCP uses an OS-selected local port and does not support packet route overrides.
    #[arg(long, conflicts_with_all = ["udp_only", "source_port"])]
    pub(crate) tcp: bool,
    /// Number of independently re-resolved and re-authorized attempts.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_ATTEMPTS)]
    pub(crate) attempts: u32,
    /// Response window for each attempt, shared with any TCP continuation.
    #[arg(long, default_value_t = 1_000)]
    pub(crate) timeout_ms: u64,
    /// Optional retry-rate ceiling; a UDP-to-TCP continuation is immediate.
    #[arg(long)]
    pub(crate) rate: Option<u32>,
    /// Maximum worst-case timeout plus intentional retry delay in milliseconds.
    #[arg(long, default_value_t = 3_600_000)]
    pub(crate) max_duration_ms: u64,
    /// Maximum complete DNS message bytes decoded.
    #[arg(long, default_value_t = packetcraftr::dns::MAX_MESSAGE_BYTES)]
    pub(crate) max_message_bytes: usize,
    /// Maximum total answer, authority, and additional records decoded.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_RECORDS)]
    pub(crate) max_records: usize,
    /// Maximum compression-pointer traversals for any decoded DNS name.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_NAME_POINTERS)]
    pub(crate) max_name_pointers: usize,
    /// Maximum TXT character strings in one record.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_TXT_STRINGS)]
    pub(crate) max_txt_strings: usize,
    /// Maximum aggregate TXT data bytes in one record.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_TXT_BYTES)]
    pub(crate) max_txt_bytes: usize,
    /// Maximum rejected-record metadata entries retained.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_REJECTED_RECORDS)]
    pub(crate) max_rejected_records: usize,
    /// Maximum undecodable exact frames retained across attempts.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_UNDECODED_FRAMES)]
    pub(crate) max_undecoded: usize,
    #[command(flatten)]
    pub(crate) route: RouteSelectionArgs,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) policy: HostnamePolicyArgs,
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::Cli;
    use crate::commands::Command;

    fn dns_args(extra: &[&str]) -> Args {
        let mut command = vec!["packetcraftr", "dns", "192.0.2.53", "example.test"];
        command.extend_from_slice(extra);
        let parsed = Cli::try_parse_from(command).expect("DNS arguments parse");
        let Command::Dns(arguments) = parsed.command else {
            panic!("fixture must select DNS")
        };
        arguments
    }

    #[test]
    fn tcp_fallback_is_default_and_udp_only_is_explicit() {
        assert!(!dns_args(&[]).udp_only);
        assert!(dns_args(&["--udp-only"]).udp_only);
    }

    #[test]
    fn query_types_parse_directly_into_the_workflow_model() {
        for (text, code) in [
            ("caa", 257),
            ("AAAA", 28),
            ("TYPE65000", 65000),
            ("0", 0),
            ("65535", 65535),
        ] {
            assert_eq!(dns_args(&["--type", text]).query_type, QueryType::new(code));
        }
        assert_eq!(dns_args(&[]).query_type, QueryType::A);
    }
    #[test]
    fn edns_is_explicit_and_dnssec_requires_a_payload_size() {
        assert_eq!(dns_args(&[]).edns_udp_payload_size, None);
        assert!(!dns_args(&[]).dnssec_ok);
        for size in ["512", "1232", "65535"] {
            let args = dns_args(&["--edns-udp-payload-size", size, "--dnssec-ok"]);
            assert_eq!(args.edns_udp_payload_size, Some(size.parse().unwrap()));
            assert!(args.dnssec_ok);
        }
        assert!(!dns_args(&["--edns-udp-payload-size", "1232"]).dnssec_ok);
        for extra in [
            vec!["--dnssec-ok"],
            vec!["--edns-udp-payload-size", "0"],
            vec!["--edns-udp-payload-size", "511"],
            vec!["--edns-udp-payload-size", "65536"],
            vec!["--edns-udp-payload-size", "-1"],
        ] {
            let mut command = vec!["packetcraftr", "dns", "192.0.2.53", "example.test"];
            command.extend(extra);
            assert!(Cli::try_parse_from(command).is_err());
        }
    }
}
