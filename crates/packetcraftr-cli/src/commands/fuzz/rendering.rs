// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{core, output};

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, emit_stream_record, emit_stream_with_stats, render_diagnostics_text,
    render_output_diagnostics_text, spaced_hex, write_stdout_line,
};

pub(super) fn render_fuzz_text(
    result: output::fuzz::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "mode={} seed={} first_case={} generated={} built={} rejected={}",
        fuzz_mode_name(result.mode),
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
            fuzz_outcome_name(case.outcome),
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

pub(super) fn render_fuzz_stream(
    result: output::fuzz::Result,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    let output::fuzz::Result {
        seed,
        first_case,
        mode,
        cases_generated,
        cases_built,
        cases_rejected,
        cases,
    } = result;
    let mut sequence = 0_u64;
    for case in cases {
        emit_stream_record(
            output::contract::Command::Fuzz,
            &mut sequence,
            output::fuzz::Event::Case {
                operation_seed: seed,
                case: Box::new(case),
            },
        )?;
    }
    emit_stream_with_stats(
        output::contract::Command::Fuzz,
        sequence,
        output::fuzz::Event::Complete {
            operation_seed: seed,
            first_case,
            mode,
            cases_generated,
            cases_built,
            cases_rejected,
        },
        diagnostics,
        stats,
    )
}

fn fuzz_mode_name(value: output::fuzz::Mode) -> &'static str {
    match value {
        output::fuzz::Mode::Offline => "offline",
        output::fuzz::Mode::Live => "live",
    }
}

fn fuzz_outcome_name(value: output::fuzz::Outcome) -> &'static str {
    match value {
        output::fuzz::Outcome::Built => "built",
        output::fuzz::Outcome::Rejected => "rejected",
        output::fuzz::Outcome::Sent => "sent",
        output::fuzz::Outcome::Response => "response",
        output::fuzz::Outcome::Timeout => "timeout",
        output::fuzz::Outcome::Error => "error",
    }
}
