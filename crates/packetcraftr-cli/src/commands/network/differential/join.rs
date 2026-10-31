// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Read as _;
use std::path::{Path, PathBuf};

use packetcraftr::differential as lib;
use packetcraftr_core::error::Kind;
use serde::Deserialize;

use crate::errors::CliError;
use crate::output;
use crate::output::contract::Format;

use super::rendering;

pub(crate) const AFTER_LONG_HELP: &str = r"Finalize a provisional (spoofed) differential Campaign offline. Reads the Campaign aggregate JSON published by `network differential --output json` and the Responder reception log written by `network differential-responder --log-file`, answers every attempt whose Variant, attempt sequence, and payload digest all match a reception record, and republishes the matrix. Reply frames stay in the original Campaign report; the joined report carries Verdicts and attempt identities.

Example:
  packetcraftr network differential-join campaign.json --responder-log responder-log.jsonl";

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Campaign aggregate JSON from a differential run.
    pub(crate) campaign: PathBuf,
    /// Responder reception log in JSON lines.
    #[arg(long)]
    pub(crate) responder_log: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    result: CampaignResult,
}

#[derive(Debug, Deserialize)]
struct CampaignResult {
    provisional: bool,
    plan_digest: String,
    #[serde(default)]
    source_port: u16,
    #[serde(default)]
    spoof_source: Option<std::net::Ipv4Addr>,
    attempts: Vec<AttemptInput>,
}

#[derive(Debug, Deserialize)]
struct AttemptInput {
    variant: String,
    attempt_seq: u64,
    answered: bool,
    packets_sent: u64,
    payload_sha256: String,
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, CliError> {
    let file = std::fs::File::open(path).map_err(|source| {
        CliError::new(
            Kind::Io,
            format!("cannot open {}: {source}", path.display()),
        )
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            CliError::new(
                Kind::Io,
                format!("cannot read {}: {source}", path.display()),
            )
        })?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(CliError::new(
            Kind::Usage,
            format!(
                "{} exceeds the {MAX_INPUT_BYTES} byte input bound",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

fn parse_hash(value: &str) -> Result<[u8; 32], CliError> {
    if value.len() != 64 {
        return Err(CliError::new(
            Kind::Usage,
            "campaign payload_sha256 must be 64 hex characters",
        ));
    }
    let mut hash = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let text = std::str::from_utf8(pair)
            .map_err(|_| CliError::new(Kind::Usage, "campaign payload_sha256 must be hex"))?;
        hash[index] = u8::from_str_radix(text, 16)
            .map_err(|_| CliError::new(Kind::Usage, "campaign payload_sha256 must be hex"))?;
    }
    Ok(hash)
}

impl crate::commands::Spec for Args {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json];
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

fn run(invocation: &crate::invocation::Invocation, arguments: Args) -> Result<(), CliError> {
    let campaign_bytes = read_bounded(&arguments.campaign)?;
    invocation.check()?;
    let envelope: Envelope = serde_json::from_slice(&campaign_bytes).map_err(|source| {
        CliError::new(
            Kind::Usage,
            format!("campaign input is not differential aggregate JSON: {source}"),
        )
    })?;
    let mut attempts = Vec::new();
    for attempt in envelope.result.attempts {
        let variant_index = lib::catalog::catalog()
            .iter()
            .position(|variant| variant.id == attempt.variant)
            .ok_or_else(|| {
                CliError::new(
                    Kind::Usage,
                    format!("campaign names unknown variant {}", attempt.variant),
                )
            })?;
        attempts.push(lib::AttemptEvidence {
            variant_index,
            attempt_seq: u32::try_from(attempt.attempt_seq).unwrap_or(u32::MAX),
            answered: attempt.answered,
            packets_sent: attempt.packets_sent as usize,
            payload_sha256: parse_hash(&attempt.payload_sha256)?,
            reply: None,
        });
    }
    let aggregate = lib::Aggregate {
        valid: false,
        provisional: envelope.result.provisional,
        plan_digest: envelope.result.plan_digest,
        source_port: envelope.result.source_port,
        spoof_source: envelope.result.spoof_source,
        rows: lib::rows_for(&attempts),
        attempts,
        diagnostics: Vec::new(),
        stats: Default::default(),
    };

    let log_bytes = read_bounded(&arguments.responder_log)?;
    invocation.check()?;
    let log_text = String::from_utf8(log_bytes)
        .map_err(|_| CliError::new(Kind::Usage, "responder log is not UTF-8 JSON lines"))?;
    let mut records = Vec::new();
    for line in log_text.lines().filter(|line| !line.trim().is_empty()) {
        records.push(
            serde_json::from_str::<lib::ReceptionRecord>(line).map_err(|source| {
                CliError::new(
                    Kind::Usage,
                    format!("responder log line is not a reception record: {source}"),
                )
            })?,
        );
    }

    let joined = lib::join_receptions(aggregate, &records);
    invocation.check()?;
    let published = output::envelope::Published::<output::differential::Report>::try_from(joined)
        .map_err(CliError::classified)?;
    match invocation.format {
        Format::Text => rendering::render_report_text(invocation, &published.result),
        Format::Json => crate::rendering::emit_published(
            invocation,
            output::contract::Command::DifferentialJoin,
            published,
        ),
        other => other.unreachable(),
    }
}
