// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::ToolFormat;

use packetcraftr_core::analysis;

use crate::output;

use crate::commands::offline_analysis::{Retained, omitted_diagnostic};
use crate::errors::CliError;
use crate::rendering::{StreamEncoder, emit_aggregate, write_stdout_line};

pub(super) struct State {
    /// Totals over the findings the selectors kept.
    selected: analysis::expert::Summary,
    retained: Retained<output::expert::Finding>,
}

impl State {
    /// `max_findings` bounds only the aggregate JSON document, which holds
    /// every finding at once. One frame can produce several findings, so the
    /// frame ceiling alone does not bound the document.
    pub(super) fn new(max_findings: usize) -> Self {
        Self {
            selected: analysis::expert::Summary::default(),
            retained: Retained::new(max_findings),
        }
    }

    // u64 severity counters cannot reach u64::MAX from a bounded finding count
    pub(super) fn count(&mut self, finding: &analysis::expert::Finding) {
        let selected = &mut self.selected;
        selected.findings += 1;
        match finding.severity {
            packetcraftr_core::diagnostic::Severity::Error => selected.errors += 1,
            packetcraftr_core::diagnostic::Severity::Warning => selected.warnings += 1,
            packetcraftr_core::diagnostic::Severity::Info => selected.notes += 1,
        }
        *selected.codes.entry(finding.code).or_default() += 1;
    }
}

pub(super) fn render_record(
    format: ToolFormat,
    finding: output::expert::Finding,
    state: &mut State,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    match format {
        ToolFormat::Text => match (finding.transport, finding.stream) {
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
        ToolFormat::Json => {
            state.retained.push(|| finding);
            Ok(())
        }
        ToolFormat::Ndjson => Ok(stream.emit_data(finding, Vec::new())?),
    }
}

pub(super) fn render_text(summary: &analysis::Summary, state: &State) -> Result<(), CliError> {
    crate::commands::offline_analysis::render_clock(&summary.clock)?;
    let selected = &state.selected;
    // BTreeMap iteration is code order, so the per-code lines are deterministic.
    for (code, findings) in &selected.codes {
        write_stdout_line(format_args!("code={code} findings={findings}"))?;
    }
    write_stdout_line(format_args!(
        "found {} finding(s) ({} error(s), {} warning(s), {} note(s)) in {} of {} frame(s)",
        selected.findings,
        selected.errors,
        selected.warnings,
        selected.notes,
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
    let State {
        mut selected,
        retained,
    } = state;
    selected.clock = summary.clock.clone();
    let findings = if include_findings {
        retained.into_items()
    } else {
        Vec::new()
    };
    output::expert::Report::from((
        selected,
        summary.frames_read,
        summary.frames_matched,
        findings,
        &summary.ip_reassembly,
    ))
}
