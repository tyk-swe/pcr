// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use packetcraftr::{analysis, output};

use crate::errors::CliError;
use crate::rendering::{emit, emit_aggregate, emit_next, write_stdout_line};

#[derive(Debug, Default)]
pub(super) struct State {
    findings: u64,
    errors: u64,
    warnings: u64,
    notes: u64,
    codes: BTreeMap<String, u64>,
    retained: Vec<output::expert::Finding>,
    pub(super) sequence: u64,
}

impl State {
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
    format: output::contract::Format,
    finding: output::expert::Finding,
    state: &mut State,
) -> Result<(), CliError> {
    match format {
        output::contract::Format::Text => match (finding.transport, finding.stream) {
            (Some(transport), Some(stream)) => write_stdout_line(format_args!(
                "#{} {:?} {} ({} stream {stream}): {}",
                finding.frame,
                finding.severity,
                finding.code,
                transport.as_str(),
                finding.message
            )),
            _ => write_stdout_line(format_args!(
                "#{} {:?} {}: {}",
                finding.frame, finding.severity, finding.code, finding.message
            )),
        },
        output::contract::Format::Json => {
            state.retained.push(finding);
            Ok(())
        }
        output::contract::Format::Ndjson => emit_next(
            output::contract::Command::Expert,
            &mut state.sequence,
            finding,
        ),
        _ => unreachable!("the format contract admits only text, json, and ndjson"),
    }
}

pub(super) fn render_text(summary: &analysis::Summary, state: &State) -> Result<(), CliError> {
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
    emit_aggregate(
        output::contract::Command::Expert,
        result(summary, state, true),
        Vec::new(),
    )
}

pub(super) fn render_stream(summary: &analysis::Summary, state: State) -> Result<(), CliError> {
    let sequence = state.sequence;
    emit(
        output::contract::Command::Expert,
        sequence,
        result(summary, state, false),
        Vec::new(),
    )
}

fn result(
    summary: &analysis::Summary,
    state: State,
    include_findings: bool,
) -> output::expert::Result {
    output::expert::Result {
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
            state.retained
        } else {
            Vec::new()
        },
    }
}
