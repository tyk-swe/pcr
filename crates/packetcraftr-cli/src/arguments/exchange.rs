// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;
use packetcraftr::client;

use super::capture_limits::CaptureLimitArgs;
use super::send::SendArgs;

pub(super) const AFTER_LONG_HELP: &str = r#"Live exchange is policy-gated and may require native features, dependencies, and privileges.

Example:
  packetcraftr exchange --packet 'ipv4(dst=192.0.2.1)/icmpv4(type=8,code=0)' --timeout-ms 1000"#;

#[derive(Debug, Args)]
pub(crate) struct ExchangeArgs {
    #[command(flatten)]
    pub(crate) send: SendArgs,
    /// Overall response window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    pub(crate) timeout_ms: u64,
    /// Maximum matched responses retained across the exchange.
    #[arg(long, default_value_t = client::exchange::DEFAULT_MAX_UNSOLICITED_FRAMES)]
    pub(crate) max_responses: usize,
    /// Maximum unsolicited decoded frames retained across the exchange.
    #[arg(long, default_value_t = client::exchange::DEFAULT_MAX_UNSOLICITED_FRAMES)]
    pub(crate) max_unsolicited: usize,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitArgs,
}
