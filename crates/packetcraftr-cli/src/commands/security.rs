// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared security bounds, input handling, and result publication.

pub(super) mod input;
mod options;

use super::CommandExit;
use crate::{
    errors::CliError,
    invocation::Invocation,
    output::{
        contract::{Command, Format},
        security::FindingRecord,
    },
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
    let report = crate::output::security::Report::from(&report);
    crate::rendering::bounded_json_len(&report, bounds.max_result_bytes)
        .map_err(|e| e.into_cli_error(|| invalid("security result exceeds --max-result-bytes")))?;
    match i.format {
        Format::Json => crate::rendering::emit_aggregate(i, command, report, Vec::new())?,
        Format::Ndjson => {
            for finding in &report.findings {
                i.check()?;
                i.output.emit_data(FindingRecord(finding), Vec::new())?;
            }
            i.output.complete(report, Vec::new())?;
        }
        Format::Text => crate::rendering::security::text(i, &report)?,
        other => other.unreachable(),
    }
    Ok(CommandExit::status(u8::from(fail)))
}
