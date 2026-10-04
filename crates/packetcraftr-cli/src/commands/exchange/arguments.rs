// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{CaptureLimitsArgs, LongTimeoutArgs, SendArgs, TemplateArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Live exchange is policy-gated and may require native features, dependencies, and privileges. NDJSON publishes provider-confirmed sends and definitively classified capture evidence during the single exchange; unanswered records follow capture completion and one complete record terminates success.

Example:
  packetcraftr --output ndjson exchange --packet 'ipv4(dst=192.0.2.1)/icmpv4(type=8,code=0)' --timeout-ms 1000";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) send: SendArgs,
    #[command(flatten)]
    pub(crate) template: TemplateArgs,
    #[command(flatten)]
    pub(crate) timeout: LongTimeoutArgs,
    /// End the response window as soon as every request has at least one
    /// retained response, instead of waiting out the full --timeout-ms.
    #[arg(long)]
    pub(crate) stop_when_answered: bool,
    /// Maximum matched responses retained across the exchange.
    #[arg(long, default_value_t = packetcraftr::exchange::DEFAULT_MAX_RESPONSES)]
    pub(crate) max_responses: usize,
    /// Maximum unsolicited frames (unmatched decoded or undecodable) retained
    /// across the exchange.
    #[arg(
        long = "max-unsolicited",
        value_name = "COUNT",
        default_value_t = packetcraftr::exchange::DEFAULT_MAX_UNMATCHED_FRAMES
    )]
    pub(crate) max_unmatched_frames: usize,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitsArgs,
}

impl Args {
    pub(crate) fn stop(&self) -> packetcraftr::exchange::StopCondition {
        if self.stop_when_answered {
            packetcraftr::exchange::StopCondition::AllAnswered
        } else {
            packetcraftr::exchange::StopCondition::Window
        }
    }
}
