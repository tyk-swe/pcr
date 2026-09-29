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

#[cfg(test)]
mod tests {
    use packetcraftr_core::diagnostic::Severity;

    use super::*;
    use crate::test_support::stream;

    const MIXED: [(Severity, &str); 6] = [
        (Severity::Error, "tcp.reset"),
        (Severity::Warning, "tcp.zero_window"),
        (Severity::Warning, "tcp.zero_window"),
        (Severity::Info, "capture.note"),
        (Severity::Error, "tcp.reset"),
        (Severity::Error, "tcp.retransmission_conflicting"),
    ];

    const TALLY: [(&str, u64); 4] = [
        ("capture.note", 1),
        ("tcp.reset", 2),
        ("tcp.retransmission_conflicting", 1),
        ("tcp.zero_window", 2),
    ];

    fn selected_state(format: ToolFormat, stream: &StreamEncoder) -> State {
        let mut state = State::new(MIXED.len());
        for (number, (severity, code)) in (1..).zip(MIXED) {
            let finding = analysis::expert::Finding {
                severity,
                code,
                number,
                stream: None,
                message: String::new(),
            };
            state.count(&finding);
            render_record(format, finding.into(), &mut state, stream).unwrap();
        }
        state
    }

    fn summary() -> analysis::Summary {
        analysis::Summary {
            frames_read: 9,
            frames_matched: 7,
            ..analysis::Summary::default()
        }
    }

    fn tally(report: &output::expert::Report) -> (u64, u64, u64, Vec<(&'static str, u64)>) {
        (
            report.errors,
            report.warnings,
            report.notes,
            report
                .codes
                .iter()
                .map(|entry| (entry.code, entry.findings))
                .collect(),
        )
    }

    #[test]
    fn aggregate_report_tallies_every_selected_finding_and_lists_the_retained_ones() {
        let (stream, _) = stream(output::contract::Command::Expert);
        let report = result(&summary(), selected_state(ToolFormat::Json, &stream));

        assert_eq!(tally(&report), (3, 2, 1, TALLY.to_vec()));
        assert_eq!((report.frames_read, report.frames_matched), (9, 7));
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.frame)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn stream_terminal_keeps_the_tally_but_carries_no_findings() {
        let (stream, buffer) = stream(output::contract::Command::Expert);
        let state = selected_state(ToolFormat::Ndjson, &stream);
        render_stream(&summary(), state, &stream).unwrap();

        let records = buffer.records();
        assert_eq!(records.len(), MIXED.len() + 1);
        assert!(
            records[..MIXED.len()]
                .iter()
                .all(|record| record["event"] == "finding")
        );
        let terminal = &records[MIXED.len()]["result"];
        assert_eq!(terminal["errors"], 3);
        assert_eq!(terminal["warnings"], 2);
        assert_eq!(terminal["notes"], 1);
        assert_eq!(
            terminal["codes"],
            serde_json::json!([
                {"code": "capture.note", "findings": 1},
                {"code": "tcp.reset", "findings": 2},
                {"code": "tcp.retransmission_conflicting", "findings": 1},
                {"code": "tcp.zero_window", "findings": 2},
            ])
        );
        assert_eq!(terminal["findings"], serde_json::json!([]));
    }
}
