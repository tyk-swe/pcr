// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use packetcraftr::packet::diagnostic::DiagnosticSeverity;
use packetcraftr::{analysis, output};

use super::super::arguments::{CliExpertSeverity, ExpertArgs};
use super::super::errors::CliError;
use super::super::rendering::{emit_json, emit_json_compact, write_stdout_line};
use super::offline_analysis::{
    PreparedOfflineAnalysis, open_offline_reader, prepare_offline_analysis,
};

#[derive(Debug, Default)]
struct SelectedExpertSummary {
    findings: u64,
    errors: u64,
    warnings: u64,
    notes: u64,
    codes: BTreeMap<String, u64>,
}

impl SelectedExpertSummary {
    fn count(&mut self, finding: &analysis::expert::Finding) {
        self.findings += 1;
        match finding.severity {
            DiagnosticSeverity::Error => self.errors += 1,
            DiagnosticSeverity::Warning => self.warnings += 1,
            DiagnosticSeverity::Info => self.notes += 1,
        }
        *self.codes.entry(finding.code.clone()).or_default() += 1;
    }
}

fn matches_selector(
    finding: &analysis::expert::Finding,
    min_severity: CliExpertSeverity,
    codes: &[String],
) -> bool {
    let finding_rank = match finding.severity {
        DiagnosticSeverity::Info => 1,
        DiagnosticSeverity::Warning => 2,
        DiagnosticSeverity::Error => 3,
    };
    if finding_rank < min_severity.rank() {
        return false;
    }
    if !codes.is_empty() && !codes.iter().any(|c| c == &finding.code) {
        return false;
    }
    true
}

pub(crate) fn run_expert(
    arguments: ExpertArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    output::contract::Command::Expert
        .require_format(output)
        .map_err(CliError::classified)?;
    let PreparedOfflineAnalysis {
        registry,
        filter,
        limits,
    } = prepare_offline_analysis(arguments.limits, arguments.filter.as_deref())?;
    let mut reader = open_offline_reader(&arguments.path, arguments.limits.capture)?;

    let options = analysis::Options {
        filter: filter.as_ref(),
        // Expert needs the reassembler's byte-exact retransmission evidence.
        tcp_events: true,
        limits,
    };
    let mut collector = analysis::expert::ExpertCollector::new();
    let mut selected_summary = SelectedExpertSummary::default();
    let mut sequence = 0_u64;
    let mut retained: Vec<output::expert::Finding> = Vec::new();
    let outcome = analysis::run(&mut reader, registry, &options, |record| {
        for finding in collector.observe(&record) {
            if matches_selector(&finding, arguments.min_severity, &arguments.codes) {
                selected_summary.count(&finding);
                emit_finding(output, finding.into(), &mut sequence, &mut retained)
                    .map_err(CliError::into_boundary_error)?;
            }
        }
        Ok(())
    });
    let summary = outcome.map_err(|error| {
        let error = CliError::classified(error);
        // Streamed records are numbered by emission, not by capture frame,
        // so a terminal stream error continues that numbering.
        if matches!(output, output::contract::Format::Ndjson) {
            error.at_sequence(sequence)
        } else {
            error
        }
    })?;
    let (trailing, _expert_summary) =
        collector.finish(&summary.trailing_tcp_events, summary.frames_read);
    for finding in trailing {
        if matches_selector(&finding, arguments.min_severity, &arguments.codes) {
            selected_summary.count(&finding);
            emit_finding(output, finding.into(), &mut sequence, &mut retained)?;
        }
    }

    match output {
        output::contract::Format::Text => write_stdout_line(format_args!(
            "found {} finding(s) ({} error(s), {} warning(s), {} note(s)) in {} of {} frame(s)",
            selected_summary.findings,
            selected_summary.errors,
            selected_summary.warnings,
            selected_summary.notes,
            summary.frames_matched,
            summary.frames_read,
        )),
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Expert,
            output::expert::Result {
                frames_read: summary.frames_read,
                frames_matched: summary.frames_matched,
                errors: selected_summary.errors,
                warnings: selected_summary.warnings,
                notes: selected_summary.notes,
                codes: selected_summary
                    .codes
                    .into_iter()
                    .map(|(code, findings)| output::expert::CodeCount { code, findings })
                    .collect(),
                findings: retained,
            },
            Vec::new(),
        )),
        output::contract::Format::Ndjson => {
            // Every finding was already streamed; the terminal record
            // carries only the totals.
            emit_json_compact(&output::envelope::Stream::success(
                output::contract::Command::Expert,
                sequence,
                output::expert::Result {
                    frames_read: summary.frames_read,
                    frames_matched: summary.frames_matched,
                    errors: selected_summary.errors,
                    warnings: selected_summary.warnings,
                    notes: selected_summary.notes,
                    codes: selected_summary
                        .codes
                        .into_iter()
                        .map(|(code, findings)| output::expert::CodeCount { code, findings })
                        .collect(),
                    findings: Vec::new(),
                },
                Vec::new(),
            ))
            .map_err(|error| error.at_sequence(sequence))
        }
        _ => unreachable!("the format contract admits only text, json, and ndjson"),
    }
}

/// Streams or retains one finding, depending on the output format.
fn emit_finding(
    output: output::contract::Format,
    finding: output::expert::Finding,
    sequence: &mut u64,
    retained: &mut Vec<output::expert::Finding>,
) -> Result<(), CliError> {
    match output {
        output::contract::Format::Text => {
            match (finding.transport, finding.stream) {
                (Some(transport), Some(stream)) => write_stdout_line(format_args!(
                    "#{} {:?} {} ({} stream {stream}): {}",
                    finding.frame,
                    finding.severity,
                    finding.code,
                    transport.as_str(),
                    finding.message
                ))?,
                _ => write_stdout_line(format_args!(
                    "#{} {:?} {}: {}",
                    finding.frame, finding.severity, finding.code, finding.message
                ))?,
            }
            Ok(())
        }
        output::contract::Format::Json => {
            retained.push(finding);
            Ok(())
        }
        output::contract::Format::Ndjson => {
            emit_json_compact(&output::envelope::Stream::success(
                output::contract::Command::Expert,
                *sequence,
                finding,
                Vec::new(),
            ))
            .map_err(|error| error.at_sequence(*sequence))?;
            *sequence = sequence
                .checked_add(1)
                .ok_or_else(|| CliError::classified(output::contract::Error::SequenceOverflow))?;
            Ok(())
        }
        _ => unreachable!("the format contract admits only text, json, and ndjson"),
    }
}
