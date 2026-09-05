// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output::contract::Format;

use std::collections::BTreeMap;

use packetcraftr::{analysis, output};

use crate::commands::offline_analysis::{Retained, omitted_diagnostic};
use crate::errors::CliError;
use crate::rendering::{StreamEncoder, emit_aggregate, write_stdout_line};

pub(super) struct State {
    findings: u64,
    errors: u64,
    warnings: u64,
    notes: u64,
    codes: BTreeMap<String, u64>,
    retained: Retained<output::expert::Finding>,
}

impl State {
    /// `max_findings` bounds only the aggregate JSON document, which holds
    /// every finding at once. One frame can produce several findings, so the
    /// frame ceiling alone does not bound the document.
    pub(super) const fn new(max_findings: usize) -> Self {
        Self {
            findings: 0,
            errors: 0,
            warnings: 0,
            notes: 0,
            codes: BTreeMap::new(),
            retained: Retained::new(max_findings),
        }
    }

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "u64 severity counters cannot reach u64::MAX from a bounded finding count"
    )]
    pub(super) fn count(&mut self, finding: &analysis::expert::Finding) {
        self.findings += 1;
        match finding.severity {
            packetcraftr::core::diagnostic::Severity::Error => self.errors += 1,
            packetcraftr::core::diagnostic::Severity::Warning => self.warnings += 1,
            packetcraftr::core::diagnostic::Severity::Info => self.notes += 1,
        }
        *self.codes.entry(finding.code.clone()).or_default() += 1;
    }
}

pub(super) fn render_record(
    format: Format,
    finding: output::expert::Finding,
    state: &mut State,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    match format {
        Format::Text => match (finding.transport, finding.stream) {
            (Some(transport), Some(stream)) => write_stdout_line(format_args!(
                "#{} {} {} ({} stream {stream}): {}",
                finding.frame,
                finding.severity.as_str(),
                finding.code,
                transport.as_str(),
                finding.message
            )),
            _ => write_stdout_line(format_args!(
                "#{} {} {}: {}",
                finding.frame,
                finding.severity.as_str(),
                finding.code,
                finding.message
            )),
        },
        Format::Json => {
            state.retained.push(finding);
            Ok(())
        }
        Format::Ndjson => Ok(stream.emit_data(finding, Vec::new())?),
        _ => unreachable!("command dispatch validated the output format"),
    }
}

pub(super) fn render_text(summary: &analysis::Summary, state: &State) -> Result<(), CliError> {
    // BTreeMap iteration is code order, so the per-code lines are deterministic.
    for (code, findings) in &state.codes {
        write_stdout_line(format_args!("code={code} findings={findings}"))?;
    }
    write_stdout_line(format_args!(
        "found {} finding(s) ({} error(s), {} warning(s), {} note(s)) in {} of {} frame(s)",
        state.findings,
        state.errors,
        state.warnings,
        state.notes,
        summary.frames_matched,
        summary.frames_read,
    ))
}

pub(super) fn render_aggregate(summary: &analysis::Summary, state: State) -> Result<(), CliError> {
    let diagnostics = omitted_diagnostic(
        "expert.findings_omitted",
        "finding(s)",
        state.retained.omitted(),
        "--max-frames",
    );
    emit_aggregate(
        output::contract::Command::Expert,
        result(summary, state, true),
        diagnostics,
    )
}

pub(super) fn render_stream(
    summary: &analysis::Summary,
    state: State,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    Ok(stream.complete(result(summary, state, false), Vec::new())?)
}

fn result(
    summary: &analysis::Summary,
    state: State,
    include_findings: bool,
) -> output::expert::Report {
    output::expert::Report {
        frames_read: summary.frames_read,
        frames_matched: summary.frames_matched,
        errors: state.errors,
        warnings: state.warnings,
        notes: state.notes,
        codes: state
            .codes
            .into_iter()
            .map(|(code, findings)| output::expert::CodeCount { code, findings })
            .collect(),
        findings: if include_findings {
            state.retained.into_items()
        } else {
            Vec::new()
        },
        ip_reassembly: output::reassembly::Report::from_analysis(&summary.ip_reassembly),
    }
}
