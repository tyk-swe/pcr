// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::dns::QueryType;

use crate::command_options::{
    AddressFamily, CaptureLimitsArgs, HostnamePolicyArgs, MaxDurationArgs, RouteSelectionArgs,
    RunTime, TimeoutArgs, Window,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr dns 192.0.2.53 example.test --type a
  packetcraftr dns 127.0.0.1 example.test --tcp
  packetcraftr --output json dns 192.0.2.53 _service._tcp.example.test --type srv
  packetcraftr dns 192.0.2.53 example.test other.test --reverse 192.0.2.1 --reverse 2001:db8::1
  packetcraftr dns 192.0.2.53 example.test --udp-only";

pub(crate) const LONG_ABOUT: &str = "Run bounded, policy-gated DNS queries. By default, each attempt starts over UDP and one validated matching truncated response may continue over TCP to the same reauthorized numeric server. --tcp queries directly over ordinary TCP sockets without raw capture. Both modes retain the --timeout-ms attempt window and bounded retries. --udp-only disables fallback and supports packet-oriented route overrides that kernel TCP cannot preserve. Text, JSON, and NDJSON identify each attempted phase and the accepted response transport; direct TCP reports fallback_attempted=false.

Several NAMEs plus repeatable --reverse ADDRESS (PTR under in-addr.arpa/ip6.arpa) form one bounded batch of at most 256 questions sharing the explicit server, transport selection, and --max-duration-ms deadline. Each question reports completed/failed/unattempted in input order; a question's own attempts keep --timeout-ms and --attempts.";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Explicit DNS server IP address or hostname.
    #[arg(value_name = "SERVER")]
    pub(crate) server: String,
    /// Bounded ASCII DNS owner names to query as one batch.
    #[arg(value_name = "NAME", required_unless_present = "reverse")]
    pub(crate) names: Vec<String>,
    /// Append a PTR question for this address (in-addr.arpa/ip6.arpa); repeatable.
    #[arg(long = "reverse", value_name = "ADDRESS")]
    pub(crate) reverse: Vec<std::net::IpAddr>,
    /// DNS type alias, decimal code, or TYPE<n> (0..=65535; at most five digits).
    #[arg(long = "type", default_value_t = QueryType::A)]
    // clap prints this doc comment verbatim as --help text, so it is not rustdoc markup.
    #[allow(rustdoc::invalid_html_tags)]
    pub(crate) query_type: QueryType,
    /// Select the first authorized server address or one IP family.
    #[arg(long, value_enum, default_value_t = AddressFamily::Any)]
    pub(crate) family: AddressFamily,
    /// DNS server port for the selected UDP/TCP transport.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_SERVER_PORT)]
    pub(crate) port: u16,
    /// Explicit 16-bit transaction ID; only valid for a single-question batch.
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
    #[command(flatten)]
    pub(crate) timeout: TimeoutArgs<AttemptWindow>,
    /// Optional retry-rate ceiling; a UDP-to-TCP continuation is immediate.
    #[arg(long)]
    pub(crate) rate: Option<u32>,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs<Resolution>,
    /// Maximum complete DNS message bytes decoded.
    #[arg(long, default_value_t = packetcraftr::dns::MessageLimits::default().max_message_bytes)]
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

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AttemptWindow;

impl Window for AttemptWindow {
    const DEFAULT_MILLISECONDS: &'static str = "1000";
    const HELP: &'static str = "Response window for each attempt, shared with any TCP continuation";
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Resolution;

impl RunTime for Resolution {
    const HELP: &'static str =
        "Maximum worst-case timeout plus intentional retry delay in milliseconds";
}
