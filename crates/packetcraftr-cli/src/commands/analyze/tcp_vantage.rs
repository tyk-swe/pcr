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

pub(crate) const AFTER_LONG_HELP: &str = r"Classify TCP SYN segments in a responder-side capture by the differential sequence Canary. Only SYNs matching the planned source, destination, variant range, and attempt range are counted. This is the capture-side spike harness from ADR 0011: it reports which planned attempts were seen on that wire and whether their TCP options changed, and it sends nothing. A sequence number is a correlation marker, not authentication. Attempt sequences use base + variant * 4096 + attempt.

Example:
  packetcraftr analyze tcp-vantage responder.pcapng --base-sequence 100000 --source 192.0.2.10 --endpoint 198.51.100.20:443 --variants 4 --repeats 3";

#[derive(Debug, Args)]
pub(crate) struct TcpVantage {
    /// Responder-side PCAP or PCAPNG capture; - reads redirected stdin.
    path: PathBuf,
    /// Sequence number of variant 0 attempt 0.
    #[arg(long)]
    base_sequence: u32,
    /// Planned source IP for every counted SYN.
    #[arg(long)]
    source: IpAddr,
    /// Planned destination IP:PORT for every counted SYN.
    #[arg(long)]
    endpoint: std::net::SocketAddr,
    /// Number of variants in the plan.
    #[arg(long)]
    variants: usize,
    /// Attempts per variant in the plan (1..=4096).
    #[arg(long)]
    repeats: u32,
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
        if self.variants == 0 || !(1..=tcp_vantage::ATTEMPTS_PER_VARIANT).contains(&self.repeats) {
            return Err(CliError::new(
                Kind::Usage,
                "--variants must be non-zero and --repeats must be within 1..=4096",
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
            if endpoints != Some((self.source, self.endpoint.ip()))
                || tcp.destination_port != self.endpoint.port()
            {
                continue;
            }
            let (variant_index, attempt_seq) =
                tcp_vantage::decode_sequence(self.base_sequence, tcp.sequence);
            if variant_index >= self.variants || attempt_seq >= self.repeats {
                continue;
            }
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
