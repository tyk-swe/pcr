// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

pub mod commands;
pub mod enums;
pub mod options;
#[cfg(feature = "repl")]
pub(crate) mod repl;
mod request;
pub mod validators;

use clap::Parser;

/// Top-level CLI arguments for PacketcraftR.
#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Modular packet crafting, transmission, and automation toolkit",
    long_about = "PacketcraftR builds packets layer-by-layer (Ethernet -> IP -> Transport -> Payload) for authorized lab, protocol-development, and network-testing work. \
The stable rescue surface focuses on safe dry-run previews, packet validation, and finite packet transmission planning. \
Advanced operational tools are experimental and appear only when their Cargo features are enabled.",
    after_help = "EXAMPLES:

  1. Preview a UDP payload to loopback without transmitting:
     packetcraftr dry-run -d 127.0.0.1 --data hello udp --dport 9

  2. Preview JSON output for automation:
     packetcraftr --output-format json dry-run -d 127.0.0.1 --data hello udp --dport 9

  3. Build an ICMP Echo Request preview:
     packetcraftr dry-run -d 127.0.0.1 icmp --icmp-type 8 --icmp-code 0

  4. Preview a raw payload from hex:
     packetcraftr dry-run -d 127.0.0.1 --data-hex \"aa bb cc\" udp --dport 9"
)]
pub struct PacketcraftArgs {
    /// Set the verbosity level (-v: info, -vv: debug, -vvv: trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Set the output format for display and logging.
    #[arg(long, value_enum)]
    pub output_format: Option<enums::OutputFormat>,
    /// Preview what would be sent without transmitting any packets.
    #[arg(
        long,
        global = true,
        help = "Preview what would be sent without transmitting any packets"
    )]
    pub dry_run: bool,
    #[command(flatten, next_help_heading = "Safety")]
    pub safety: options::SafetyOptions,
    /// Select an operation mode.
    #[command(subcommand)]
    pub command: commands::PacketcraftCommand,
}

impl PacketcraftArgs {
    pub fn one_shot_options(&self) -> Option<&options::OneShotOptions> {
        match &self.command {
            commands::PacketcraftCommand::Send(options)
            | commands::PacketcraftCommand::DryRun(options) => Some(&options.oneshot),
            _ => None,
        }
    }

    pub fn effective_dry_run(&self) -> bool {
        self.dry_run || matches!(&self.command, commands::PacketcraftCommand::DryRun(_))
    }
}
