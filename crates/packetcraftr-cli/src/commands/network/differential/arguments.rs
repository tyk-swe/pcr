// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use packetcraftr::differential as lib;

use crate::command_options::{
    CaptureLimitsArgs, LongTimeoutArgs, MaxDurationArgs, NumericPolicyArgs, RouteSelectionArgs,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Runs a differential Campaign: one IPv4/UDP Intent carrying a Canary payload is sent to a cooperating Responder under each Variant in the catalog, and every Variant gets a proven Verdict (accepted, unanswered, flaky, not_run). A plan-only run prints the targets, Variant table, budgets, campaign token, and plan digest without sending. A live run must present that digest and token. Public destinations and source spoofing stay denied unless the matching policy opt-in flags are given. Spoofed Campaigns stay provisional until differential-join merges the Responder reception log.

Examples:
  packetcraftr network differential 192.0.2.10 --responder-port 40101 --plan-only
  packetcraftr network differential 192.0.2.10 --responder-port 40101 --token <32 hex chars> --plan-digest <digest from the plan-only run>";

#[derive(Debug, clap::Args)]
#[command(mut_arg("plan_digest", |arg| arg.conflicts_with("plan_only")))]
pub(crate) struct Args {
    /// Numeric IPv4 address of the host running the Responder.
    pub(crate) target: Ipv4Addr,
    /// UDP port the Responder listens on.
    #[arg(long, default_value_t = 40101, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) responder_port: u16,
    /// UDP source port for every attempt.
    #[arg(long, default_value_t = lib::DEFAULT_SOURCE_PORT, value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) source_port: u16,
    /// Send attempts with this outer IPv4 source instead of the route source.
    /// Requires --allow-source-spoofing and keeps Verdicts provisional until join.
    #[arg(long)]
    pub(crate) spoof_source: Option<Ipv4Addr>,
    /// Campaign token as 32 hex characters. A plan-only run generates and
    /// prints one when omitted; the live run and the Responder must use the same token.
    #[arg(long, value_name = "HEX")]
    pub(crate) token: Option<String>,
    /// Print the plan and its digest without sending any packet.
    #[arg(long)]
    pub(crate) plan_only: bool,
    /// Digest printed by the plan-only run; required for a live run.
    #[arg(long)]
    pub(crate) plan_digest: Option<String>,
    /// Attempts per Variant backing each Verdict.
    #[arg(long, default_value_t = lib::DEFAULT_REPEATS, value_parser = clap::value_parser!(u32).range(1..=10))]
    pub(crate) repeats: u32,
    /// Canary payload length in bytes.
    #[arg(long, default_value_t = lib::DEFAULT_PAYLOAD_LEN as u64, value_parser = clap::value_parser!(u64).range(62..=1468))]
    pub(crate) payload_len: u64,
    #[command(flatten)]
    pub(crate) timeout: LongTimeoutArgs,
    #[command(flatten)]
    pub(crate) duration: MaxDurationArgs,
    #[command(flatten)]
    pub(crate) route: RouteSelectionArgs,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) policy: NumericPolicyArgs,
}
