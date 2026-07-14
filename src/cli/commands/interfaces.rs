// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Interface enumeration command.

use packetcraftr::{net, output};

use super::super::errors::CliError;
use super::super::rendering::{emit_json, write_stdout_line};

pub(in crate::cli) fn run_interfaces(output: output::contract::Format) -> Result<(), CliError> {
    let interfaces = net::interface::Provider::interfaces(&net::interface::SystemProvider)
        .map_err(CliError::classified)?;
    let result = output::network::interfaces::Result::new(interfaces);
    match output {
        output::contract::Format::Text => {
            for interface in result.interfaces {
                write_stdout_line(format_args!(
                    "{} (index {}): {}",
                    interface.name,
                    interface.index,
                    interface.addresses.join(", ")
                ))?;
            }
            Ok(())
        }
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Interfaces,
            result,
            Vec::new(),
        )),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Interfaces,
                format: output,
            },
        )),
    }
}
