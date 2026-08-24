// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{core, output};

use crate::errors::CliError;
use crate::rendering::{
    NdjsonStream, captured_frame_text, render_diagnostics_text, render_output_diagnostics_text,
    spaced_hex, write_stdout_line,
};

pub(super) fn render_text(
    result: output::fuzz::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "mode={} seed={} first_case={} generated={} built={} rejected={}",
        mode_name(result.mode),
        result.seed,
        result.first_case,
        result.cases_generated,
        result.cases_built,
        result.cases_rejected,
    ))?;
    for case in &result.cases {
        write_stdout_line(format_args!(
            "case={} seed={} strategy={} target={}.{} outcome={} length={} reproduce=--seed {} --first-case {} --cases 1",
            case.index,
            case.seed,
            case.mutation.strategy,
            case.mutation.layer,
            case.mutation.field,
            outcome_name(case.outcome),
            case.frame.as_ref().map(|frame| frame.length).unwrap_or(0),
            case.reproduction.operation_seed,
            case.reproduction.case_index,
        ))?;
        let original = serde_json::to_string(&case.mutation.original).map_err(|source| {
            CliError::new(70, format!("serialize fuzz mutation failed: {source}"))
        })?;
        let value = serde_json::to_string(&case.mutation.value).map_err(|source| {
            CliError::new(70, format!("serialize fuzz mutation failed: {source}"))
        })?;
        write_stdout_line(format_args!("  original={original} value={value}"))?;
        if let Some(frame) = &case.frame {
            write_stdout_line(format_args!("  frame {}", spaced_hex(frame.bytes())))?;
        }
        if let Some(error) = &case.error {
            write_stdout_line(format_args!(
                "  error kind={} code={} message={}",
                error.kind.as_str(),
                error.code,
                error.message,
            ))?;
        }
        if let Some(sent) = &case.sent {
            write_stdout_line(format_args!("  sent {}", captured_frame_text(sent)))?;
        }
        for (kind, frames) in [
            ("response", &case.responses),
            ("unmatched", &case.unmatched),
            ("undecoded", &case.undecoded),
        ] {
            for frame in frames {
                write_stdout_line(format_args!("  {kind} {}", captured_frame_text(frame)))?;
            }
        }
        render_output_diagnostics_text(&case.diagnostics)?;
    }
    write_stdout_line(format_args!(
        "fuzz completed {} case(s), {} packet operation(s), {} byte(s)",
        result.cases_generated, stats.packets_completed, stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

pub(super) fn render_offline_complete(
    summary: core::fuzz::Summary,
    stream: &NdjsonStream,
) -> Result<(), CliError> {
    let (event, diagnostics, stats) = output::fuzz::Event::complete_from_offline(summary);
    stream.complete_with_stats(event, diagnostics, stats)
}

pub(super) fn render_live_complete(
    summary: packetcraftr::fuzz::Summary,
    stream: &NdjsonStream,
) -> Result<(), CliError> {
    let (event, diagnostics, stats) = output::fuzz::Event::complete_from_live(summary);
    stream.complete_with_stats(event, diagnostics, stats)
}

fn mode_name(value: output::fuzz::Mode) -> &'static str {
    match value {
        output::fuzz::Mode::Offline => "offline",
        output::fuzz::Mode::Live => "live",
    }
}

fn outcome_name(value: output::fuzz::Outcome) -> &'static str {
    match value {
        output::fuzz::Outcome::Built => "built",
        output::fuzz::Outcome::Rejected => "rejected",
        output::fuzz::Outcome::Response => "response",
        output::fuzz::Outcome::Timeout => "timeout",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_labels_cover_every_fuzz_mode_and_outcome() {
        assert_eq!(mode_name(output::fuzz::Mode::Offline), "offline");
        assert_eq!(mode_name(output::fuzz::Mode::Live), "live");
        assert_eq!(outcome_name(output::fuzz::Outcome::Built), "built");
        assert_eq!(outcome_name(output::fuzz::Outcome::Rejected), "rejected");
        assert_eq!(outcome_name(output::fuzz::Outcome::Response), "response");
        assert_eq!(outcome_name(output::fuzz::Outcome::Timeout), "timeout");
    }
}
