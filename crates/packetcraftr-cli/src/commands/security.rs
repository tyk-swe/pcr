// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared security bounds, input handling, and result publication.

pub(super) mod input;
mod options;
pub(in crate::commands) mod output;
pub(super) mod rendering;

use self::output::FindingRecord;
use super::CommandExit;
use crate::output::envelope::Published;
use crate::{
    errors::CliError,
    invocation::Invocation,
    output::contract::{Command, Format},
};
pub(super) use input::{read, source};
pub(super) use options::Bounds;
use packetcraftr_core::{
    error::Kind,
    security::{self, Report},
};

pub(super) fn invalid(message: impl Into<String>) -> CliError {
    CliError::new(Kind::Usage, message)
}

pub(super) fn check_result_size(
    format: Format,
    report: &output::Report<'_>,
    limit: usize,
    message: &'static str,
) -> Result<(), CliError> {
    let size = match format {
        Format::Json => crate::publication::bounded_pretty_field_len(report, limit),
        Format::Text | Format::Ndjson => {
            crate::publication::bounded_json_len(report, limit, serde_json::ser::CompactFormatter)
        }
        other => other.unreachable(),
    };
    size.map(|_| ())
        .map_err(|error| error.into_cli_error(|| invalid(message)))
}

pub(super) fn publish(
    i: &Invocation,
    command: Command,
    report: Report,
    bounds: Bounds,
) -> Result<CommandExit, CliError> {
    i.check()?;
    let limits = bounds.core()?;
    if report.findings.len() > limits.max_findings {
        return Err(CliError::classified(security::Error::Limit {
            field: "max_findings",
            limit: limits.max_findings,
        }));
    }
    let fail = bounds.fails(&report);
    let report = output::Report::from(&report);
    check_result_size(
        i.format,
        &report,
        bounds.max_result_bytes,
        "security result exceeds --max-result-bytes",
    )?;
    match i.format {
        Format::Json => {
            crate::publication::emit_published(i, command, Published::new(report, Vec::new()))?;
        }
        Format::Ndjson => {
            for finding in &report.findings {
                i.check()?;
                i.output
                    .emit_published(Published::new(FindingRecord(finding), Vec::new()))?;
            }
            i.output
                .complete_published(Published::new(report, Vec::new()))?;
        }
        Format::Text => rendering::text(i, &report)?,
        other => other.unreachable(),
    }
    Ok(CommandExit::status(u8::from(fail)))
}
