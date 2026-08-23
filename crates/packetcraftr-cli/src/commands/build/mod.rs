// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use packetcraftr::{core, output};

use self::arguments::Args;
use super::super::input::read_recipe;
use super::super::rendering::{
    emit_aggregate, render_diagnostics_text, spaced_hex, write_plain_line, write_raw,
    write_stdout_line,
};
use super::registry;
use packetcraftr::BoundaryError;

pub(super) fn run(arguments: Args, format: output::contract::Format) -> Result<(), BoundaryError> {
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
        .map_err(BoundaryError::from_error)?;
    let (result, diagnostics) = output::build::Result::from_built(built);
    match format {
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
