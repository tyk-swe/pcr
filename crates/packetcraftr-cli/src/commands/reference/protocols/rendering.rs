// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::output;
use crate::rendering::write_stdout_line;

pub(super) fn protocol_line(protocol: &output::protocols::Summary) -> String {
    format!(
        "{} aliases=[{}] build={} dissect={} exact_round_trip={} matcher={} decode_only={} stream_decode={} transports=[{}]",
        protocol.protocol,
        protocol.aliases.join(", "),
        protocol.build,
        protocol.dissect,
        protocol.exact_round_trip,
        protocol.matcher,
        protocol.decode_only,
        protocol.stream_decode,
        protocol.transports.join(", ")
    )
}

pub(super) fn render_detail(
    invocation: &crate::invocation::Invocation,
    protocol: &output::protocols::Detail,
) -> Result<(), CliError> {
    let summary = &protocol.summary;
    write_stdout_line(invocation, format_args!("protocol: {}", summary.protocol))?;
    write_stdout_line(
        invocation,
        format_args!("aliases: [{}]", summary.aliases.join(", ")),
    )?;
    write_stdout_line(invocation, format_args!("build: {}", summary.build))?;
    write_stdout_line(invocation, format_args!("dissect: {}", summary.dissect))?;
    write_stdout_line(
        invocation,
        format_args!("exact_round_trip: {}", summary.exact_round_trip),
    )?;
    write_stdout_line(invocation, format_args!("matcher: {}", summary.matcher))?;
    write_stdout_line(
        invocation,
        format_args!("decode_only: {}", summary.decode_only),
    )?;
    write_stdout_line(
        invocation,
        format_args!("stream_decode: {}", summary.stream_decode),
    )?;
    write_stdout_line(
        invocation,
        format_args!("transports: [{}]", summary.transports.join(", ")),
    )?;
    if let Some(coverage) = &summary.coverage {
        write_stdout_line(invocation, format_args!("coverage: {coverage}"))?;
    }
    write_stdout_line(invocation, format_args!("bindings:"))?;
    for binding in &protocol.bindings {
        write_stdout_line(
            invocation,
            format_args!(
                "  {} discriminator={}",
                binding.parent, binding.discriminator
            ),
        )?;
    }
    write_stdout_line(invocation, format_args!("fields:"))?;
    for field in &protocol.fields {
        write_stdout_line(
            invocation,
            format_args!(
                "  {} kind={} required={} derived={} description={}",
                field.name,
                field.kind.as_str(),
                field.required,
                field.derived,
                field.description
            ),
        )?;
    }
    if !protocol.filter_fields.is_empty() {
        let fields = &protocol.filter_fields;
        write_stdout_line(invocation, format_args!("filter_fields:"))?;
        for field in fields {
            write_stdout_line(
                invocation,
                format_args!("  {}: {}", field.path, field.description),
            )?;
        }
    }
    Ok(())
}
