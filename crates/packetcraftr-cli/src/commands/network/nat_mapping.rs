// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Args;
use packetcraftr::differential as lib;
use packetcraftr_core::error::Kind;

use crate::commands::Generate;
use crate::commands::security::read;
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::terminal::emit_stdout_document;

pub(crate) const AFTER_LONG_HELP: &str = r"Classify NAT source-tuple stability from a differential Responder reception log. With --expected-source, a single matching tuple is reported as preserved; otherwise stable, port-varying, and address-varying mappings are distinguished. This observes one responder destination only, so stability here does not prove endpoint-independent mapping to other destinations.

Example:
  packetcraftr network nat-mapping responder-log.jsonl --expected-source 192.0.2.10:53210";

const MAX_LOG_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000;

#[derive(Debug, Args)]
pub(crate) struct NatMapping {
    /// Differential Responder reception log in JSON lines.
    log: PathBuf,
    /// Intended source IP:PORT before any NAT rewrite.
    #[arg(long)]
    expected_source: Option<SocketAddr>,
}

impl Generate for NatMapping {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<(), CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("nat-mapping prints text only, not --output {format}"),
            ));
        }
        let bytes = read(invocation, &self.log, MAX_LOG_BYTES)?;
        let text = String::from_utf8(bytes)
            .map_err(|_| CliError::new(Kind::Usage, "responder log is not valid UTF-8"))?;
        let mut records = Vec::new();
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            if records.len() >= MAX_RECORDS {
                return Err(CliError::new(
                    Kind::Usage,
                    format!("responder log exceeds {MAX_RECORDS} records"),
                ));
            }
            records.push(
                serde_json::from_str::<lib::ReceptionRecord>(line).map_err(|error| {
                    CliError::new(
                        Kind::Usage,
                        format!("invalid responder log record: {error}"),
                    )
                })?,
            );
            if records.len() == MAX_RECORDS
                && text
                    .lines()
                    .skip(records.len())
                    .any(|line| !line.is_empty())
            {
                return Err(CliError::new(
                    Kind::Usage,
                    format!("responder log exceeds {MAX_RECORDS} records"),
                ));
            }
        }
        let mapping = lib::nat_mapping(&records, self.expected_source);
        let mut text = format!(
            "records={} sources={} behavior={}\n",
            mapping.records,
            mapping.sources.len(),
            mapping.behavior.as_str(),
        );
        for source in &mapping.sources {
            text.push_str(&format!("source {source}\n"));
        }
        emit_stdout_document(invocation, &text)
    }
}
