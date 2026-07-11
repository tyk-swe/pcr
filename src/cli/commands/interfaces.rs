// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Interface enumeration command.

fn run_interfaces(output: OutputFormat) -> Result<(), CliError> {
    let interfaces =
        crate::net::InterfaceProvider::interfaces(&crate::net::SystemInterfaceProvider)
            .map_err(CliError::classified)?;
    let result = InterfacesCommandResult::new(interfaces);
    match output {
        OutputFormat::Text => {
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
        OutputFormat::Json => emit_json(&AggregateOutput::success(
            CommandName::Interfaces,
            result,
            Vec::new(),
        )),
        _ => Err(CliError::classified(
            OutputContractError::UnsupportedFormat {
                command: CommandName::Interfaces,
                format: output,
            },
        )),
    }
}
