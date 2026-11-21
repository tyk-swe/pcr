// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use clap::Args;
use packetcraftr_core::analysis;
use packetcraftr_core::error::Kind;

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};
use crate::commands::Generate;
use crate::commands::offline_analysis::prepare;
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Show the TCP TLS detection surface available without key logs. Sessions are assembled exactly as analyze tls assembles them, then reduced to the metadata a defender can still use: SNI presence and Encrypted ClientHello outer-name status, offered and selected ALPN, versions, cipher suites, and JA3, JA3S and JA4 fingerprints. No key log is accepted, no application data is decrypted, and QUIC stays with analyze quic and analyze http3.

Example:
  packetcraftr analyze defender-view capture.pcapng";

#[derive(Debug, Args)]
pub(crate) struct DefenderView {
    /// Classic PCAP or PCAPNG input path; - reads redirected stdin.
    path: PathBuf,
    #[command(flatten)]
    decode: DecodeArgs,
    /// Maximum handshake bytes buffered across every tracked conversation.
    #[arg(long, default_value_t = analysis::tls::Limits::default().max_buffered_bytes)]
    max_tls_buffer_bytes: usize,
    /// Maximum TLS conversations tracked concurrently.
    #[arg(long, default_value_t = analysis::tls::Limits::default().max_sessions)]
    max_tls_sessions: usize,
    #[command(flatten)]
    limits: OfflineLimitsArgs,
}

#[derive(Default)]
struct Aggregate {
    sessions: u64,
    with_client: u64,
    with_server: u64,
    with_sni: u64,
    without_sni: u64,
    outer_sni: u64,
    ech: u64,
    ja3: BTreeSet<String>,
    ja4: BTreeSet<String>,
    ja3s: BTreeSet<String>,
    sni: BTreeSet<String>,
    alpn: BTreeSet<String>,
    selected_versions: BTreeMap<u16, u64>,
    cipher_suites: BTreeMap<u16, u64>,
}

impl Aggregate {
    fn observe(&mut self, session: &analysis::tls::Session) {
        self.sessions += 1;
        if let Some(client) = &session.client {
            self.with_client += 1;
            match &client.sni {
                Some(sni) => {
                    self.with_sni += 1;
                    self.sni.insert(sni.clone());
                }
                None => self.without_sni += 1,
            }
            if client.sni_is_outer {
                self.outer_sni += 1;
            }
            if client.ech {
                self.ech += 1;
            }
            self.ja3.insert(client.ja3.clone());
            self.ja4.insert(client.ja4.clone());
            self.alpn.extend(client.alpn.iter().cloned());
        }
        if let Some(server) = &session.server {
            self.with_server += 1;
            self.ja3s.insert(server.ja3s.clone());
            *self
                .selected_versions
                .entry(server.selected_version)
                .or_default() += 1;
            *self.cipher_suites.entry(server.cipher_suite).or_default() += 1;
            if let Some(alpn) = &server.alpn {
                self.alpn.insert(alpn.clone());
            }
        }
    }
}

impl Generate for DefenderView {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<(), CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("defender-view prints text only, not --output {format}"),
            ));
        }
        if self.max_tls_buffer_bytes < analysis::tls::MAX_DIRECTION_BUFFER {
            return Err(CliError::classified(analysis::Error::InvalidLimit {
                field: "--max-tls-buffer-bytes",
                value: u64::try_from(self.max_tls_buffer_bytes).unwrap_or(u64::MAX),
                reason: analysis::Constraint::AtLeastTlsDirectionBuffer,
            }));
        }
        let collector = analysis::tls::Collector::new(analysis::tls::Limits {
            max_sessions: self.max_tls_sessions,
            max_buffered_bytes: self.max_tls_buffer_bytes,
        })
        .map_err(CliError::classified)?;
        let prepared = prepare(self.limits, None, &self.decode)?;
        let session = prepared.session(invocation, collector, None);
        let mut reader = prepared.open(invocation, &self.path)?;
        let mut aggregate = Aggregate::default();
        let outcome = session
            .run(
                &mut reader,
                crate::commands::offline_analysis::ip_event_sink(Format::Text, &invocation.output),
                |event| {
                    aggregate.observe(&event.session);
                    Ok(())
                },
            )
            .map_err(CliError::classified)?;

        let mut text = format!(
            "frames_read={} frames_matched={} tcp_streams={} sessions={} with_client={} with_server={} with_sni={} without_sni={} outer_sni={} ech={} distinct_ja3={} distinct_ja4={} distinct_ja3s={} distinct_sni={} distinct_alpn={}\n",
            outcome.run.frames_read,
            outcome.run.frames_matched,
            outcome.summary.tcp_streams,
            aggregate.sessions,
            aggregate.with_client,
            aggregate.with_server,
            aggregate.with_sni,
            aggregate.without_sni,
            aggregate.outer_sni,
            aggregate.ech,
            aggregate.ja3.len(),
            aggregate.ja4.len(),
            aggregate.ja3s.len(),
            aggregate.sni.len(),
            aggregate.alpn.len(),
        );
        for value in &aggregate.sni {
            text.push_str(&format!("sni {value}\n"));
        }
        for value in &aggregate.alpn {
            text.push_str(&format!("alpn {value}\n"));
        }
        for value in &aggregate.ja3 {
            text.push_str(&format!("ja3 {value}\n"));
        }
        for value in &aggregate.ja4 {
            text.push_str(&format!("ja4 {value}\n"));
        }
        for value in &aggregate.ja3s {
            text.push_str(&format!("ja3s {value}\n"));
        }
        for (version, count) in &aggregate.selected_versions {
            text.push_str(&format!("selected_version 0x{version:04x} count={count}\n"));
        }
        for (cipher, count) in &aggregate.cipher_suites {
            text.push_str(&format!("cipher_suite 0x{cipher:04x} count={count}\n"));
        }
        emit_stdout_document(invocation, &text)
    }
}
