// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_cli::output;
use packetcraftr_core::error::Kind;

use crate::errors::CliError;
use crate::rendering::{
    captured_frame_text, render_diagnostics_text, spaced_hex, write_stdout_line,
};

pub(super) fn render_text(
    output::workflow::Converted {
        result,
        diagnostics,
        stats,
    }: output::workflow::Converted<output::fuzz::Report>,
) -> Result<(), CliError> {
    let stats = stats.expect("fuzz conversion includes packet statistics");
    write_stdout_line(format_args!(
        "mode={} seed={} first_case={} generated={} built={} rejected={}",
        result.mode.as_str(),
        result.seed,
        result.first_case,
        result.cases_generated,
        result.cases_built,
        result.cases_rejected,
    ))?;
    for case in &result.cases {
        crate::cancellation::check()?;
        write_stdout_line(format_args!(
            "case={} seed={} strategy={} target={}.{} outcome={} length={} reproduce=--seed {} --first-case {} --cases 1",
            case.index,
            case.seed,
            case.mutation.strategy,
            case.mutation.layer,
            case.mutation.field,
            case.outcome.as_str(),
            case.frame.as_ref().map(|frame| frame.length).unwrap_or(0),
            case.reproduction.operation_seed,
            case.reproduction.case_index,
        ))?;
        let original = mutation_json(&case.mutation.original)?;
        let value = mutation_json(&case.mutation.value)?;
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
        render_diagnostics_text(&case.diagnostics)?;
    }
    crate::cancellation::check()?;
    write_stdout_line(format_args!(
        "fuzz completed {} case(s), {} packet operation(s), {} byte(s)",
        result.cases_generated, stats.packets_completed, stats.bytes
    ))?;
    render_diagnostics_text(&diagnostics)
}

fn mutation_json<T: serde::Serialize>(value: &T) -> Result<String, CliError> {
    serde_json::to_string(value).map_err(|source| {
        CliError::new(
            Kind::Internal,
            format!("serialize fuzz mutation failed: {source}"),
        )
    })
}
