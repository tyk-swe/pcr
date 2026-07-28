// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Offline packet build command.

use packetcraftr::{output, packet};

use super::super::arguments::BuildArgs;
use super::super::errors::CliError;
use super::super::input::read_recipe;
use super::super::rendering::{
    emit_json, spaced_hex, write_plain_line, write_raw, write_stdout_line,
};
use super::super::runtime::default_registry_arc;

pub(crate) fn run_build(
    arguments: BuildArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let registry = default_registry_arc()?;
    let packet = read_recipe(arguments.recipe, &registry)?;
    let built = packet::build::Builder::new(registry)
        .build(
            packet,
            packet::build::Context::default(),
            packet::build::Options {
                mode: arguments.mode.into(),
                ..packet::build::Options::default()
            },
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    let (result, diagnostics) = output::build::Result::from_built(built);
    match output {
        output::contract::Format::Text => {
            write_stdout_line(format_args!("built {} bytes", result.length))?;
            write_stdout_line(format_args!("{}", spaced_hex(result.bytes())))?;
            for diagnostic in &diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        output::contract::Format::Hex => write_plain_line(format_args!("{}", result.bytes_hex)),
        output::contract::Format::Raw => write_raw(result.bytes()),
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Build,
            result,
            diagnostics,
        )),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Build,
                format: output,
            },
        )),
    }
}
