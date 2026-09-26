// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `protocols`' text output.

use crate::errors::CliError;
use crate::output;
use crate::rendering::write_stdout_line;

/// One text row per protocol.
pub(super) fn protocol_line(protocol: &output::protocols::Summary) -> String {
    format!(
        "{} aliases=[{}] build={} dissect={} exact_round_trip={} matcher={} decode_only={}",
        protocol.protocol,
        protocol.aliases.join(", "),
        protocol.build,
        protocol.dissect,
        protocol.exact_round_trip,
        protocol.matcher,
        protocol.decode_only
    )
}

pub(super) fn render_detail(protocol: &output::protocols::Detail) -> Result<(), CliError> {
    write_stdout_line(format_args!("protocol: {}", protocol.protocol))?;
    write_stdout_line(format_args!("aliases: [{}]", protocol.aliases.join(", ")))?;
    write_stdout_line(format_args!("build: {}", protocol.build))?;
    write_stdout_line(format_args!("dissect: {}", protocol.dissect))?;
    write_stdout_line(format_args!(
        "exact_round_trip: {}",
        protocol.exact_round_trip
    ))?;
    write_stdout_line(format_args!("matcher: {}", protocol.matcher))?;
    write_stdout_line(format_args!("decode_only: {}", protocol.decode_only))?;
    write_stdout_line(format_args!("bindings:"))?;
    for binding in &protocol.bindings {
        write_stdout_line(format_args!(
            "  {} discriminator={}",
            binding.parent, binding.discriminator
        ))?;
    }
    write_stdout_line(format_args!("fields:"))?;
    for field in &protocol.fields {
        write_stdout_line(format_args!(
            "  {} kind={} required={} derived={} description={}",
            field.name,
            field.kind.as_str(),
            field.required,
            field.derived,
            field.description
        ))?;
    }
    if !protocol.filter_fields.is_empty() {
        let fields = &protocol.filter_fields;
        write_stdout_line(format_args!("filter_fields:"))?;
        for field in fields {
            write_stdout_line(format_args!("  {}: {}", field.path, field.description))?;
        }
    }
    Ok(())
}
