// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::analysis::StreamRef;

use crate::command_options::{
    ApplicationLimitsArgs, DecodeArgs, OfflineLimitsArgs, Selector, stream_selector,
};

pub(crate) const AFTER_LONG_HELP: &str = r"DNS messages are read offline from a capture file; nothing is transmitted. UDP datagrams and reassembled TCP streams on port 53 and every --dns-port are framed into messages, and each query is paired with its response by flow and DNS ID into a transaction that is matched, unanswered, an orphan response, or a duplicate response.

--stream keeps one whole conversation, as tcp:INDEX or udp:INDEX, using the indices stats reports and stream filters match. Text prints captured names escaped; JSON and NDJSON keep each message's exact wire bytes as hex.

Examples:
  packetcraftr dns-read capture.pcapng
  packetcraftr dns-read capture.pcapng --dns-port 5353 --stream udp:3
  packetcraftr --output ndjson dns-read - < capture.pcapng";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// PCAP/PCAPNG input; - reads redirected stdin. gzip and Zstd are detected.
    pub(crate) path: PathBuf,
    /// Keep one whole conversation: tcp:INDEX or udp:INDEX.
    #[arg(long, value_name = "TRANSPORT:INDEX", value_parser = stream_selector)]
    pub(crate) stream: Option<Selector<StreamRef>>,
    /// Additional DNS service ports; repeat to add services. Port 53 is always analyzed.
    #[arg(long = "dns-port", value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) dns_ports: Vec<u16>,
    #[command(flatten)]
    pub(crate) application: ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use crate::cli::Cli;
    use crate::commands::CommandLine;

    fn parse(extra: &[&str]) -> Result<super::Args, clap::Error> {
        let mut command = vec!["packetcraftr", "dns-read", "capture.pcap"];
        command.extend_from_slice(extra);
        Cli::try_parse_from(command).map(|cli| match cli.command {
            CommandLine::DnsRead(arguments) => arguments,
            _ => panic!("fixture must select dns-read"),
        })
    }

    #[test]
    fn dns_read_rejects_port_zero_while_parsing() {
        let error = parse(&["--dns-port", "0"]).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert!(error.to_string().contains("--dns-port"));
        assert_eq!(
            parse(&["--dns-port", "5353", "--dns-port", "65535"])
                .unwrap()
                .dns_ports,
            [5353, 65535]
        );
    }
}
