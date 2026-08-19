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
    NdjsonStream, emit_json, emit_stderr_document, emit_stderr_error, emit_stdout_document,
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
                        let stream = NdjsonStream::stdout(context.command);
                        stream.emit_error(error.output_error())
                    }
                    _ => unreachable!("startup context returns only structured formats"),
                };
                return match emitted {
                    Ok(()) => ExitCode::from(code),
                    Err(write_error) => {
                        let _ = emit_stderr_error(&write_error);
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
    let mut stream = NdjsonStream::stdout(Some(command));
    match cli.command.run(format, &mut stream) {
        Ok(()) => match require_success_terminal(format, &stream) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => command_failure(format, command, error, &mut stream),
        },
        Err(error) => command_failure(format, command, error, &mut stream),
    }
}

fn require_success_terminal(
    format: output::contract::Format,
    stream: &NdjsonStream,
) -> Result<(), CliError> {
    if format == output::contract::Format::Ndjson && !stream.is_terminal() {
        return Err(CliError::new(
            70,
            "NDJSON command returned without a terminal completion record",
        ));
    }
    Ok(())
}

fn command_failure(
    format: output::contract::Format,
    command: output::contract::Command,
    error: CliError,
    stream: &mut NdjsonStream,
) -> ExitCode {
    let exit_code = error.exit_code;
    let (emitted, report_write_error) = match format {
        output::contract::Format::Json => (
            emit_json(&output::envelope::AggregateError::error(
                Some(command),
                error.output_error(),
            )),
            true,
        ),
        output::contract::Format::Ndjson if stream.is_open() => {
            (stream.emit_error(error.output_error()), true)
        }
        output::contract::Format::Ndjson => (emit_stderr_error(&error), false),
        _ => (emit_stderr_error(&error), false),
    };
    if let Err(write_error) = emitted {
        if report_write_error {
            let _ = emit_stderr_error(&write_error);
        }
        return ExitCode::from(write_error.exit_code);
    }
    ExitCode::from(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_ndjson_requires_a_terminal_record() {
        let stream = NdjsonStream::new(
            Some(output::contract::Command::Read),
            std::io::Cursor::new(Vec::new()),
        );
        assert!(require_success_terminal(output::contract::Format::Ndjson, &stream).is_err());
        stream
            .complete(serde_json::json!({"event": "complete"}), Vec::new())
            .unwrap();
        assert!(require_success_terminal(output::contract::Format::Ndjson, &stream).is_ok());
        assert!(require_success_terminal(output::contract::Format::Json, &stream).is_ok());
    }
}
