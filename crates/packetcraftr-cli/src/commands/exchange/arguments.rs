// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{CaptureLimitsArgs, SendArgs, TemplateArgs, TimeoutArgs, Window};

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
    pub(crate) timeout: TimeoutArgs<ResponseWindow>,
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

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ResponseWindow;

impl Window for ResponseWindow {
    const DEFAULT_MILLISECONDS: &'static str = "3000";
    const HELP: &'static str = "Overall response window in milliseconds";
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use packetcraftr::exchange::StopCondition;

    use super::Args;
    use crate::{cli::Cli, commands::CommandLine};

    fn arguments(extra: &[&str]) -> Args {
        let values = ["packetcraftr", "exchange", "--packet", "raw(hex=00)"]
            .into_iter()
            .chain(extra.iter().copied());
        let cli = Cli::try_parse_from(values).expect("fixture exchange arguments must parse");
        let CommandLine::Exchange(arguments) = cli.command else {
            panic!("fixture must parse as exchange");
        };
        arguments
    }

    #[test]
    fn the_response_window_is_collected_in_full_unless_answers_are_awaited() {
        assert_eq!(arguments(&[]).stop(), StopCondition::Window);
        assert_eq!(
            arguments(&["--stop-when-answered"]).stop(),
            StopCondition::AllAnswered
        );
    }
}
