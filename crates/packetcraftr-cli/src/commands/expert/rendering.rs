// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::ToolFormat;

use packetcraftr_core::analysis;

use crate::output;

use crate::errors::CliError;
use crate::rendering::{Retained, omitted_diagnostic};
use crate::rendering::{StreamEncoder, emit_aggregate, write_stdout_line};

pub(super) struct State {
    selected: analysis::expert::Summary,
    retained: Retained<output::expert::Finding>,
}

impl State {
    /// `max_findings` bounds only the aggregate JSON document.
    pub(super) fn new(max_findings: usize) -> Self {
        Self {
            selected: analysis::expert::Summary::default(),
            retained: Retained::new(max_findings),
        }
    }

    pub(super) fn count(&mut self, finding: &analysis::expert::Finding) {
        self.selected.record(finding);
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
    crate::rendering::render_clock(&summary.clock)?;
    let selected = &state.selected;
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
        result(summary, state),
        diagnostics,
    )
}

pub(super) fn render_stream(
    summary: &analysis::Summary,
    state: State,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    Ok(stream.complete(result(summary, state), Vec::new())?)
}

fn result(summary: &analysis::Summary, state: State) -> output::expert::Report {
    let State {
        mut selected,
        retained,
    } = state;
    selected.clock = summary.clock.clone();
    output::expert::Report::from((
        selected,
        summary.frames_read,
        summary.frames_matched,
        retained.into_items(),
        &summary.ip_reassembly,
    ))
}
