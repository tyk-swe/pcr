// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::ArgAction;

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Two captures are analyzed independently: each side's filter selects only its own frames, and identity, preservation, and expectation rules name packet fields. The verdict is evidence, not device attribution — an unmatched ingress observation is not proof of loss, an unmatched egress observation is not proof of duplication, and timestamp differences between captures are not latency. An empty selection is always inconclusive, never a pass.

Value preservation requires readable values on both sides; two absent fields are unevaluable. Use --preserve-presence or --expect-absent only for explicit assertions about the declared decoder view.

Identity matching is exact equality of the declared field values. Groups that are not one-to-one stay ambiguous and are never paired by position or timestamp. Exit status is 0 for verdict pass, 1 for fail or inconclusive; the verdict field distinguishes them.

Examples:
  packetcraftr verify-forwarding pre.pcap post.pcap --identity ipv4.identification --identity udp.source_port
  packetcraftr verify-forwarding pre.pcap post.pcap --identity raw.bytes --preserve ipv4.payload_length
  packetcraftr verify-forwarding pre.pcap post.pcap --identity ipv4.identification --expect ipv4.destination=198.51.100.2
  packetcraftr verify-forwarding pre.pcap post.pcap --identity raw.bytes --ingress-filter 'udp.destination_port == 9000'
  packetcraftr --output json verify-forwarding pre.pcap post.pcap --identity raw.bytes";

/// Bounded comparison of an ingress and an egress capture.
#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG ingress (pre-forwarding) capture; - reads
    /// redirected stdin. Stdin may serve at most one side.
    pub(crate) ingress: PathBuf,
    /// Classic PCAP or PCAPNG egress (post-forwarding) capture.
    pub(crate) egress: PathBuf,
    /// Display filter selecting ingress observations; stream-capable.
    #[arg(long, value_name = "EXPR")]
    pub(crate) ingress_filter: Option<String>,
    /// Display filter selecting egress observations; stream-capable.
    #[arg(long, value_name = "EXPR")]
    pub(crate) egress_filter: Option<String>,
    /// Packet field identifying an observation across captures; repeatable,
    /// at least one required. Identity is exact value equality; capture-local
    /// positions such as frame.number or tcp.stream are not packet fields.
    #[arg(
        long = "identity",
        value_name = "FIELD",
        action = ArgAction::Append,
        required = true
    )]
    pub(crate) identity: Vec<String>,
    /// Field that must compare equal on a uniquely matched pair with readable values; repeatable.
    #[arg(long = "preserve", value_name = "FIELD", action = ArgAction::Append)]
    pub(crate) preserve: Vec<String>,
    /// Preserve presence/absence in the declared decoder view, not value equality.
    #[arg(long, value_name = "FIELD", action = ArgAction::Append)]
    pub(crate) preserve_presence: Vec<String>,
    /// Require absence in the complete declared decoder view; unknown evidence
    /// is unevaluable, not proof that a field is absent on the wire.
    #[arg(long, value_name = "FIELD", action = ArgAction::Append)]
    pub(crate) expect_absent: Vec<String>,
    /// Value every selected egress observation's field must carry, declared
    /// as FIELD=VALUE with display-filter literal syntax; repeatable.
    #[arg(long = "expect", value_name = "FIELD=VALUE", action = ArgAction::Append)]
    pub(crate) expect: Vec<String>,
    /// Per-observation projected field byte budget; exceeding it flags the
    /// observation incomplete rather than dropping it.
    #[arg(long, default_value_t = 64 * 1024)]
    pub(crate) max_field_bytes: usize,
    /// Total retained observation-evidence budget in bytes per capture.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    pub(crate) max_evidence_bytes: usize,
    /// Maximum entries in each report detail list; omitted entries are
    /// counted in `omitted`.
    #[arg(long, default_value_t = 256)]
    pub(crate) max_details: usize,
    /// Shared conservative JSON-sized detail charge across every report list
    /// (0..=8388608). Omission never changes counters or the verdict.
    #[arg(long, default_value_t = 4 * 1024 * 1024, value_parser = detail_bytes)]
    pub(crate) max_detail_bytes: usize,
    /// Additional canonical-key/index scratch charge; not a process RSS cap.
    #[arg(long, default_value_t = 128 * 1024 * 1024)]
    pub(crate) max_scratch_bytes: usize,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}

fn detail_bytes(value: &str) -> Result<usize, String> {
    let parsed = value.parse::<usize>().map_err(|error| error.to_string())?;
    if parsed > 8 * 1024 * 1024 {
        return Err(
            "--max-detail-bytes must be at most 8388608; the terminal summary needs separate space"
                .to_owned(),
        );
    }
    Ok(parsed)
}
