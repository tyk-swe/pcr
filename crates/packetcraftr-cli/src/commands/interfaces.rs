// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{netio as net, output};

use super::super::errors::CliError;
use super::super::rendering::{emit_aggregate, write_stdout_line};
use super::format::AggregateFormat;

pub(super) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr interfaces
  packetcraftr --output json interfaces"#;

pub(super) fn run(format: output::contract::Format) -> Result<(), CliError> {
    let format = AggregateFormat::narrow(output::contract::Command::Interfaces, format)?;
    let interfaces = net::interface::Provider::interfaces(&net::interface::SystemProvider)
        .map_err(CliError::classified)?;
    let result = output::interfaces::Result::new(interfaces);
    match format {
        AggregateFormat::Text => {
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
        AggregateFormat::Json => {
            emit_aggregate(output::contract::Command::Interfaces, result, Vec::new())
        }
    }
}
