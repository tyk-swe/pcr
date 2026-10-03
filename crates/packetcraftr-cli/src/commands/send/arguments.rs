// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{SendArgs, TemplateArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Live transmission is policy-gated and may require native features, dependencies, and privileges.

--axis expands the recipe into a packet set and --repeat repeats the whole set in expansion order; --rate bounds transmission starts across the operation. The complete expansion times repetition is admitted against one packet budget before provider work; exact wire bytes accumulate against one byte budget before each transmission.

Example:
  packetcraftr send --packet 'ipv4(dst=192.0.2.1)/icmpv4(type=8,code=0)'";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) send: SendArgs,
    #[command(flatten)]
    pub(crate) template: TemplateArgs,
    /// Complete passes over the packet set, in expansion order.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    pub(crate) repeat: u32,
    /// Ceiling on transmission starts in packets per second; unpaced when omitted.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    pub(crate) rate: Option<u32>,
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use crate::cli::Cli;

    #[test]
    fn send_rejects_zero_repeat_and_rate() {
        for option in ["--repeat", "--rate"] {
            assert!(
                Cli::try_parse_from(["packetcraftr", "send", "--packet", "ipv4()", option, "0",])
                    .is_err(),
                "{option} 0 must be rejected"
            );
        }
    }
}
