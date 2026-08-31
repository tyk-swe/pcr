// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use packetcraftr::{core, output};

use self::arguments::Args;
use super::format::BuildFormat;
use super::registry;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::{
    emit_aggregate, render_diagnostics_text, spaced_hex, write_plain_line, write_raw,
    write_stdout_line, write_summary_line,
};

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), CliError> {
    let format = BuildFormat::narrow(output::contract::Command::Build, format)?;
    let registry = registry()?;
    let packet = read_recipe(arguments.recipe, &registry)?;
    let built = core::build::Builder::new(registry)
        .build(
            packet,
            core::build::Context::default(),
            core::build::Options {
                mode: arguments.mode.into(),
                ..core::build::Options::default()
            },
        )
        .map_err(CliError::classified)?;
    let (result, diagnostics) = output::build::Report::from_built(built);
    match format {
        BuildFormat::Text => {
            write_summary_line(format_args!("built {} bytes", result.frame.length))?;
            write_stdout_line(format_args!("{}", spaced_hex(result.frame.bytes())))?;
            render_diagnostics_text(&diagnostics)
        }
        BuildFormat::Hex => write_plain_line(format_args!("{}", result.frame.bytes_hex())),
        BuildFormat::Raw => write_raw(result.frame.bytes()),
        BuildFormat::Json => emit_aggregate(output::contract::Command::Build, result, diagnostics),
    }
}
