// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use packetcraftr::differential as lib;
use packetcraftr_core::error::Kind;

use crate::command_options::{Bounded as _, MaxDurationArgs};
use crate::commands::Generate;
use crate::errors::CliError;
use crate::output::contract::Format;
use crate::staged_output::StagedFile;
use crate::terminal::emit_stdout_document;

use super::parse_token;

pub(crate) const AFTER_LONG_HELP: &str = r"Run the cooperating DNS Responder for a DNS differential Campaign. It bind an ordinary UDP socket, records only query names bearing the campaign token, and answers each with an authoritative empty DNS response. The reception log uses the differential JSON-lines record shape and is written no-clobber at a clean stop.

Example:
  packetcraftr network dns-differential-responder --port 5353 --token <32 hex chars> --log-file dns-responder.jsonl";

#[derive(Debug, Args)]
pub(crate) struct DnsResponder {
    /// IPv4 address to bind.
    #[arg(long, default_value_t = Ipv4Addr::UNSPECIFIED)]
    bind: Ipv4Addr,
    /// UDP port to listen on.
    #[arg(long, default_value_t = 5353, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,
    /// Campaign token as 32 hex characters.
    #[arg(long)]
    token: String,
    /// Stop this many milliseconds after the first matching query; 0 uses the duration bound.
    #[arg(long, default_value_t = 30_000)]
    idle_ms: u64,
    /// Maximum datagrams processed before stopping.
    #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u64).range(1..))]
    max_datagrams: u64,
    /// Write the reception log as JSON lines to this new file.
    #[arg(long)]
    log_file: Option<PathBuf>,
    #[command(flatten)]
    duration: MaxDurationArgs,
}

impl Generate for DnsResponder {
    fn generate(
        self,
        invocation: &crate::invocation::Invocation,
        format: Format,
    ) -> Result<(), CliError> {
        if format != Format::Text {
            return Err(CliError::new(
                Kind::Usage,
                format!("dns-differential-responder prints text only, not --output {format}"),
            ));
        }
        let token = parse_token(&self.token)?;
        let mut staged = self
            .log_file
            .as_deref()
            .map(|path| StagedFile::stage(&invocation.terminal(), path))
            .transpose()?;
        let mut request = lib::dns::ResponderRequest::new(self.bind, self.port, token);
        request.max_duration = self.duration.max_duration();
        request.idle_after_first = (self.idle_ms > 0).then(|| Duration::from_millis(self.idle_ms));
        request.max_datagrams = self.max_datagrams as usize;
        request.cancellation = Some(invocation.control.cancellation.clone());
        let collector = lib::ResponderCollector::default();
        let outcome = lib::dns::respond(request, collector.clone());
        let records = collector.into_records();
        if let Some(staged_file) = &mut staged {
            for record in &records {
                let line = serde_json::to_string(record).map_err(|source| {
                    CliError::new(
                        Kind::Internal,
                        format!("DNS responder log record does not serialize: {source}"),
                    )
                })?;
                staged_file
                    .as_file_mut()
                    .write_all(line.as_bytes())
                    .and_then(|()| staged_file.as_file_mut().write_all(b"\n"))
                    .map_err(|source| {
                        CliError::new(
                            Kind::Io,
                            format!("DNS responder log write failed: {source}"),
                        )
                    })?;
            }
        }
        let report = outcome.map_err(CliError::classified)?;
        if let Some(staged_file) = staged {
            staged_file.sync()?;
            staged_file.persist()?;
        }
        emit_stdout_document(
            invocation,
            &format!(
                "received={} ignored={} replies_sent={} records={}\n",
                report.received,
                report.ignored,
                report.replies_sent,
                records.len(),
            ),
        )
    }
}
