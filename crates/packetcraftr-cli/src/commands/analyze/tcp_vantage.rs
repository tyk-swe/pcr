// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::path::PathBuf;

use clap::Args;
use packetcraftr::differential::tcp_vantage;
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::error::Kind;
use packetcraftr_core::protocol::identity;
use packetcraftr_core::protocol::transport::Tcp;
use sha2::{Digest, Sha256};

use crate::command_options::OfflineCaptureLimitsArgs;
use crate::commands::{CommandExit, Generate};
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Classify TCP SYN segments in a responder-side capture by the differential sequence Canary. This is the capture-side spike harness from ADR 0011: it proves which crafted attempts were seen on that wire and whether their TCP options changed, and it sends nothing. Attempt sequences use base + variant * 4096 + attempt.

Example:
  packetcraftr analyze tcp-vantage responder.pcapng --base-sequence 100000";

#[derive(Debug, Args)]
pub(crate) struct TcpVantage {
    /// Responder-side PCAP or PCAPNG capture; - reads redirected stdin.
    path: PathBuf,
    /// Sequence number of variant 0 attempt 0.
    #[arg(long)]
    base_sequence: u32,
    /// Only count SYNs from this source IP.
    #[arg(long)]
    source: Option<IpAddr>,
    /// Only count SYNs to this destination IP.
    #[arg(long)]
    destination: Option<IpAddr>,
    #[command(flatten)]
    limits: OfflineCaptureLimitsArgs,
}

impl Generate for TcpVantage {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<CommandExit, CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("tcp-vantage prints text only, not --output {format}"),
            ));
        }
        let frames = super::frames::read_frames(invocation, &self.path, self.limits)?;
        let dissector = Dissector::new(packetcraftr_core::protocol::builtin::registry());
        let mut observations = Vec::new();
        for frame in &frames {
            let Ok(decoded) = dissector.decode(frame.clone(), DecodeOptions::default()) else {
                continue;
            };
            let Some(tcp) = decoded.packet.get::<Tcp>() else {
                continue;
            };
            // SYN without ACK or RST is the crafted opening segment shape.
            if tcp.flags & 0x012 != 0x002 || tcp.flags & 0x004 != 0 {
                continue;
            }
            let endpoints = decoded
                .packet
                .iter()
                .rev()
                .find_map(identity::network_endpoints);
            if let Some(source) = self.source
                && endpoints.is_none_or(|(actual, _)| actual != source)
            {
                continue;
            }
            if let Some(destination) = self.destination
                && endpoints.is_none_or(|(_, actual)| actual != destination)
            {
                continue;
            }
            let (variant_index, attempt_seq) =
                tcp_vantage::decode_sequence(self.base_sequence, tcp.sequence);
            observations.push(tcp_vantage::Observation {
                variant_index,
                attempt_seq,
                options_sha256: packetcraftr_core::field::hex::compact_hex(&Sha256::digest(
                    format!("{:?}", tcp.options).as_bytes(),
                )),
            });
        }
        let rows = tcp_vantage::classify(&observations);
        let mut text = format!(
            "frames_read={} syn_observations={} variants_seen={}\n",
            frames.len(),
            observations.len(),
            rows.len(),
        );
        for row in &rows {
            text.push_str(&format!(
                "variant={} attempts_seen={} distinct_attempts={} option_digests={}\n",
                row.variant_index,
                row.attempts_seen,
                row.distinct_attempts,
                row.option_digests.join(","),
            ));
        }
        emit_stdout_document(invocation, &text)?;
        Ok(CommandExit::SUCCESS)
    }
}
