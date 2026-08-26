// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{CaptureLimitsArgs, Captured, TrafficBudgetArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Live capture may require native features, dependencies, and privileges.

--capture-filter <BPF> uses the stable resolver-free core of libpcap/Npcap BPF syntax and narrows what reaches PacketcraftR. Frames it rejects never enter PacketcraftR's capture queue and do not consume queue capacity or operation frame and byte budgets.

Use core BPF keywords and numeric address, network, port, and protocol operands. Other symbolic tokens are rejected before native compilation so capture filters cannot perform hidden hostname or name-database resolution.

--filter <EXPR> uses PacketcraftR's display-filter language after capture. Frames it rejects have already occupied PacketcraftR's capture queue and passed the native BPF filter, so they still consume operation frame and byte budgets.

The two filters use different languages and may be combined.

Text and NDJSON frame records use the one-based post-BPF source frame position.
Display-filter rejection does not renumber later source_frame values; NDJSON envelope
sequence remains the zero-based emitted-record position.

Examples:
  packetcraftr capture --interface 1 --timeout-ms 1000
  packetcraftr capture --interface 1 --promiscuous \
    --capture-filter 'udp port 53' \
    --filter 'udp.source_port == 53'"#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Interface name or numeric index to capture from.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(crate) interface: String,
    /// Enable promiscuous capture mode.
    #[arg(long)]
    pub(crate) promiscuous: bool,
    /// Overall capture window in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    pub(crate) timeout_ms: u64,
    /// Resolver-free core libpcap/Npcap BPF, applied before capture.
    #[arg(long, value_name = "BPF")]
    pub(crate) capture_filter: Option<String>,
    /// Keep only frames matching PacketcraftR's post-capture display filter.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    #[command(flatten)]
    pub(crate) limits: CaptureLimitsArgs,
    #[command(flatten)]
    pub(crate) budgets: TrafficBudgetArgs<Captured>,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::{cli::Cli, commands::Command};

    #[test]
    fn capture_requires_only_an_interface_and_opts_into_promiscuous_mode() {
        let cli = Cli::try_parse_from(["packetcraftr", "capture", "--interface", "7"])
            .expect("interface-only capture must parse");
        let Command::Capture(arguments) = cli.command else {
            panic!("capture command expected");
        };
        assert_eq!(arguments.interface, "7");
        assert!(!arguments.promiscuous);

        let cli = Cli::try_parse_from([
            "packetcraftr",
            "capture",
            "--interface",
            "fixture0",
            "--promiscuous",
        ])
        .expect("promiscuous capture must parse");
        let Command::Capture(arguments) = cli.command else {
            panic!("capture command expected");
        };
        assert!(arguments.promiscuous);

        assert!(Cli::try_parse_from(["packetcraftr", "capture"]).is_err());
        assert!(
            Cli::try_parse_from([
                "packetcraftr",
                "capture",
                "--interface",
                "7",
                "--packet",
                "raw(hex=00)",
            ])
            .is_err()
        );
    }
}
