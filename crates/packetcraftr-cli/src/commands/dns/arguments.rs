// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::ValueEnum;

use crate::command_options::{
    AddressFamily, CaptureLimitsArgs, HostnameTrafficPolicyArgs, RouteSelectionArgs,
};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr dns 192.0.2.53 example.test --type a
  packetcraftr --output json dns 192.0.2.53 _service._tcp.example.test --type srv"#;

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum QueryType {
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

impl From<QueryType> for packetcraftr::dns::QueryType {
    fn from(value: QueryType) -> Self {
        match value {
            QueryType::A => Self::A,
            QueryType::Aaaa => Self::Aaaa,
            QueryType::Cname => Self::Cname,
            QueryType::Mx => Self::Mx,
            QueryType::Ns => Self::Ns,
            QueryType::Ptr => Self::Ptr,
            QueryType::Soa => Self::Soa,
            QueryType::Srv => Self::Srv,
            QueryType::Txt => Self::Txt,
            QueryType::Any => Self::Any,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Explicit DNS server IP address or hostname.
    #[arg(value_name = "SERVER")]
    pub(crate) server: String,
    /// Bounded ASCII DNS owner name to query.
    #[arg(value_name = "NAME")]
    pub(crate) name: String,
    /// DNS question type.
    #[arg(long = "type", value_enum, default_value_t = QueryType::A)]
    pub(crate) query_type: QueryType,
    /// Select the first authorized server address or one IP family.
    #[arg(long, value_enum, default_value_t = AddressFamily::Any)]
    pub(crate) family: AddressFamily,
    /// DNS server UDP port.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_DNS_SERVER_PORT)]
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
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_DNS_ATTEMPTS)]
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
    #[arg(long, default_value_t = packetcraftr::dns::MAX_DNS_MESSAGE_BYTES)]
    pub(crate) max_message_bytes: usize,
    /// Maximum total answer, authority, and additional records decoded.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_DNS_RECORDS)]
    pub(crate) max_records: usize,
    /// Maximum compression-pointer traversals for any decoded DNS name.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_DNS_NAME_POINTERS)]
    pub(crate) max_name_pointers: usize,
    /// Maximum TXT character strings in one record.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_DNS_TXT_STRINGS)]
    pub(crate) max_txt_strings: usize,
    /// Maximum aggregate TXT data bytes in one record.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_DNS_TXT_BYTES)]
    pub(crate) max_txt_bytes: usize,
    /// Maximum rejected-record metadata entries retained.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_REJECTED_DNS_RECORDS)]
    pub(crate) max_rejected_records: usize,
    /// Maximum undecodable exact frames retained across attempts.
    #[arg(long, default_value_t = packetcraftr::dns::DEFAULT_MAX_UNDECODED_DNS_FRAMES)]
    pub(crate) max_undecoded: usize,
    #[command(flatten)]
    pub(crate) route: RouteSelectionArgs,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) policy: HostnameTrafficPolicyArgs,
}
