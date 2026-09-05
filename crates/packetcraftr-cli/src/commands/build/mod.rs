// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;

use packetcraftr::output::contract::Format;

use packetcraftr::core::error::{Classification, Classified as _, Kind};
use packetcraftr::{core, output};

use self::arguments::Args;
use super::registry;
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::rendering::{
    emit_aggregate, render_diagnostics_text, spaced_hex, write_plain_line, write_raw,
    write_stdout_line, write_summary_line,
};

pub(super) fn run(arguments: Args, format: Format) -> Result<(), CliError> {
    let registry = registry()?;
    // Recipe byte limits bound parsing; the builder owns the requested layer budget.
    let packet = read_recipe(arguments.recipe, &registry, usize::MAX)?;
    let built = core::build::Builder::new(registry)
        .build(
            packet,
            core::build::Context::default(),
            arguments.budget.build_options(arguments.mode.into()),
        )
        .map_err(build_error)?;
    let (result, diagnostics) = output::build::Report::from_built(built);
    match format {
        Format::Text => {
            write_summary_line(format_args!("built {} bytes", result.frame.length))?;
            write_stdout_line(format_args!("{}", spaced_hex(result.frame.bytes())))?;
            render_diagnostics_text(&diagnostics)
        }
        Format::Hex => write_plain_line(format_args!("{}", result.frame.bytes_hex())),
        Format::Raw => write_raw(result.frame.bytes()),
        Format::Json => emit_aggregate(output::contract::Command::Build, result, diagnostics),
        _ => unreachable!("command dispatch validated the output format"),
    }
}

fn build_error(error: core::build::Error) -> CliError {
    match error {
        error @ (core::build::Error::LayerLimit { .. }
        | core::build::Error::PacketSizeLimit { .. }) => {
            let classification = error.classification();
            CliError::from_classification(
                Classification::new(
                    "packet.build_resource_limit",
                    Kind::Packet,
                    classification.remediation,
                ),
                error.to_string(),
                error.causes(),
            )
        }
        error => CliError::classified(error),
    }
}
