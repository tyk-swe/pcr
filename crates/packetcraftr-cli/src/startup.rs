// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod context;

use std::process::ExitCode;

use clap::Parser;
use packetcraftr::output;

use self::context::from_env;
use super::cli::Cli;
use super::errors::CliError;
use super::rendering::{
    emit_json, emit_json_compact, emit_stderr_document, emit_stderr_error, emit_stdout_document,
    terminal_document,
};

pub(crate) fn run() -> ExitCode {
    let context = from_env();
    context.color.write_global();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = u8::try_from(error.exit_code()).unwrap_or(70);
            let raw_message = error.to_string();
            let message = terminal_document(&raw_message);
            if error.use_stderr()
                && let Some(format) = context.format
            {
                let error = CliError::new(code, message);
                let emitted = match format {
                    output::contract::Format::Json => {
                        emit_json(&output::envelope::AggregateError::error(
                            context.command,
                            error.output_error(),
                        ))
                    }
                    output::contract::Format::Ndjson => {
                        emit_json_compact(&output::envelope::StreamError::error(
                            context.command,
                            0,
                            error.output_error(),
                        ))
                    }
                    _ => unreachable!("startup context returns only structured formats"),
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
    let format = output::contract::Format::from(cli.format);
    let command = cli.command.kind();
    match cli.command.run(format) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let emitted = match format {
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
                    format,
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
