// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::process::ExitCode;

use clap::Parser;
use packetcraftr::output;

use super::super::arguments::Cli;
use super::super::errors::{
    CliError, color_choice_from_env, command_from_env, machine_format_from_env,
};
use super::super::rendering::{
    emit_json, emit_json_compact, emit_stderr_document, emit_stderr_error, emit_stdout_document,
    terminal_document,
};
use super::dispatch::run;

pub(crate) fn run_entrypoint() -> ExitCode {
    color_choice_from_env().write_global();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = u8::try_from(error.exit_code()).unwrap_or(70);
            let raw_message = error.to_string();
            let message = terminal_document(&raw_message);
            if error.use_stderr()
                && let Some(output) = machine_format_from_env()
            {
                let error = CliError::new(code, message);
                let emitted = match output {
                    output::contract::Format::Json => {
                        emit_json(&output::envelope::AggregateError::error(
                            command_from_env(),
                            error.output_error(),
                        ))
                    }
                    output::contract::Format::Ndjson => {
                        emit_json_compact(&output::envelope::StreamError::error(
                            command_from_env(),
                            0,
                            error.output_error(),
                        ))
                    }
                    _ => unreachable!("machine_format_from_env returns structured formats"),
                };
                return match emitted {
                    Ok(()) => ExitCode::from(code),
                    Err(write_error) => {
                        let _ = emit_stderr_error(&write_error.message);
                        ExitCode::from(write_error.exit_code)
                    }
                };
            }
            let emitted = if error.use_stderr() {
                emit_stderr_document(&raw_message)
            } else {
                emit_stdout_document(&raw_message)
            };
            return match emitted {
                Ok(()) => ExitCode::from(code),
                Err(_) => ExitCode::from(5),
            };
        }
    };
    cli.color.write_global();
    let output = output::contract::Format::from(cli.output);
    let command = cli.command.name();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let emitted = match output {
                output::contract::Format::Json => emit_json(
                    &output::envelope::AggregateError::error(Some(command), error.output_error()),
                ),
                output::contract::Format::Ndjson => {
                    emit_json_compact(&output::envelope::StreamError::error(
                        Some(command),
                        error.sequence.unwrap_or(0),
                        error.output_error(),
                    ))
                }
                _ => emit_stderr_error(&error.message),
            };
            if let Err(write_error) = emitted {
                if matches!(
                    output,
                    output::contract::Format::Json | output::contract::Format::Ndjson
                ) {
                    let _ = emit_stderr_error(&write_error.message);
                }
                return ExitCode::from(write_error.exit_code);
            }
            ExitCode::from(error.exit_code)
        }
    }
}
