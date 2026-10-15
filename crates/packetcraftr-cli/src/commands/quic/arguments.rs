// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::analysis::StreamRef;

use crate::command_options::{
    ApplicationLimitsArgs, DecodeArgs, OfflineLimitsArgs, Selector, stream_selector,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Offline QUIC packet inspection over UDP on port 443 and each --quic-port,
without decryption: packet counts by header form, connection IDs, versions seen,
version-negotiation offers, and the first Initial's IDs. Coalesced packets in one
datagram are each counted. Header-protection and AEAD bytes stay opaque.

Examples:
  packetcraftr analyze quic capture.pcapng
  packetcraftr analyze quic capture.pcapng --quic-port 853 --stream udp:0
  packetcraftr --output ndjson analyze quic - < capture.pcapng";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// PCAP/PCAPNG input; - reads redirected stdin. gzip and Zstd are detected.
    pub(crate) path: PathBuf,
    /// Keep one whole conversation: udp:INDEX.
    #[arg(long, value_name = "TRANSPORT:INDEX", value_parser = stream_selector)]
    pub(crate) stream: Option<Selector<StreamRef>>,
    /// Additional QUIC service ports; repeat to add services. Port 443 is always analyzed.
    #[arg(long = "quic-port", value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) quic_ports: Vec<u16>,
    /// Maximum distinct UDP conversations retained over the whole run.
    #[arg(long, default_value_t = packetcraftr_core::analysis::quic::Limits::default().max_conversations)]
    pub(crate) max_quic_conversations: usize,
    /// Maximum parsed QUIC packets charged across all conversations.
    #[arg(long, default_value_t = packetcraftr_core::analysis::quic::Limits::default().max_packets)]
    pub(crate) max_quic_packets: u64,
    #[command(flatten)]
    pub(crate) application: ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}

impl Args {
    pub(crate) fn limits(&self) -> packetcraftr_core::analysis::quic::Limits {
        packetcraftr_core::analysis::quic::Limits {
            max_conversations: self.max_quic_conversations,
            max_packets: self.max_quic_packets,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use crate::cli::Cli;
    use crate::commands::CommandLine;

    fn parse(extra: &[&str]) -> Result<super::Args, clap::Error> {
        let mut command = vec!["packetcraftr", "quic", "capture.pcap"];
        command.extend_from_slice(extra);
        Cli::try_parse_from(command).map(|cli| match cli.command {
            CommandLine::Quic(arguments) => arguments,
            _ => panic!("fixture must select quic"),
        })
    }

    #[test]
    fn quic_rejects_port_zero_while_parsing() {
        let error = parse(&["--quic-port", "0"]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert!(error.to_string().contains("--quic-port"));
        assert_eq!(
            parse(&["--quic-port", "853", "--quic-port", "65535"])
                .unwrap()
                .quic_ports,
            [853, 65535]
        );
    }
}
