// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use packetcraftr::{core, output};

use self::arguments::BuildArgs;
use super::super::errors::CliError;
use super::super::input::read_recipe;
use super::super::rendering::{
    emit_aggregate, render_diagnostics_text, spaced_hex, write_plain_line, write_raw,
    write_stdout_line,
};
use super::super::system::default_registry_arc;

pub(super) fn run(arguments: BuildArgs, output: output::contract::Format) -> Result<(), CliError> {
    let registry = default_registry_arc()?;
    let packet = read_recipe(arguments.recipe, &registry)?;
    let built = core::build::Builder::new(registry)
        .build(
            packet,
            core::build::BuildContext::default(),
            core::build::BuildOptions {
                mode: arguments.mode.into(),
                ..core::build::BuildOptions::default()
            },
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    let (result, diagnostics) = output::build::Result::from_built(built);
    match output {
        output::contract::Format::Text => {
            write_stdout_line(format_args!("built {} bytes", result.length))?;
            write_stdout_line(format_args!("{}", spaced_hex(result.bytes())))?;
            render_diagnostics_text(&diagnostics)
        }
        output::contract::Format::Hex => write_plain_line(format_args!("{}", result.bytes_hex)),
        output::contract::Format::Raw => write_raw(result.bytes()),
        output::contract::Format::Json => {
            emit_aggregate(output::contract::Command::Build, result, diagnostics)
        }
        _ => unreachable!("build format is checked before command dispatch"),
    }
}
