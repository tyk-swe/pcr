// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core::error::Kind;

mod context;

use clap::Parser;
use packetcraftr::output;

use self::context::{MachineFormat, from_env};
use super::cli::Cli;
use super::errors::CliError;
use super::rendering::{
    StreamEncoder, emit_json, emit_stderr_document, emit_stderr_error, emit_stdout_document,
    stdout_stream, terminal_document, write_unattributed_error,
};

pub(crate) fn run() -> u8 {
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
                // clap exits 2 for usage errors; anything else is unexpected.
                // The process exit code stays clap's either way.
                let kind = if code == 2 { Kind::Cli } else { Kind::Internal };
                let error = CliError::new(kind, message);
                let emitted = match format {
                    MachineFormat::Json => emit_json(&output::envelope::Envelope::<()>::error(
                        context.command,
                        error.output_error(),
                    )),
                    MachineFormat::Ndjson => {
                        write_unattributed_error(context.command, error.output_error())
                    }
                };
                return match emitted {
                    Ok(()) => code,
                    Err(write_error) => {
                        let _ = emit_stderr_error(&write_error);
                        write_error.exit_code()
                    }
                };
            }
            let emitted = if error.use_stderr() {
                emit_stderr_document(&raw_message)
            } else {
                emit_stdout_document(&raw_message)
            };
            return match emitted {
                Ok(()) => code,
                Err(_) => 5,
            };
        }
    };
    cli.color.write_global();
    let format = output::contract::Format::from(cli.format);
    let command = cli.command.kind();
    let stream = match if format == output::contract::Format::Ndjson {
        stdout_stream(command)
    } else {
        Ok(StreamEncoder::new(command, std::io::stdout()))
    } {
        Ok(stream) => stream,
        Err(error) => {
            let _ = emit_stderr_error(&error);
            return error.exit_code();
        }
    };
    match cli.command.run(format, &stream) {
        Ok(()) => match require_success_terminal(format, &stream) {
            Ok(()) => 0,
            Err(error) => command_failure(format, command, error, &stream),
        },
        Err(error) => command_failure(format, command, error, &stream),
    }
}

fn require_success_terminal(
    format: output::contract::Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    if format == output::contract::Format::Ndjson && !stream.is_terminal() {
        return Err(CliError::new(
            Kind::Internal,
            "NDJSON command returned without a terminal completion record",
        ));
    }
    Ok(())
}

fn command_failure(
    format: output::contract::Format,
    command: output::contract::Command,
    error: CliError,
    stream: &StreamEncoder,
) -> u8 {
    let open = stream.is_open();
    let error = if format == output::contract::Format::Ndjson && !open && !stream.is_terminal() {
        CliError::from_classification(
            packetcraftr::core::error::Classification::new(
                "io.stdout",
                Kind::Io,
                Some("treat the structured stream as incomplete"),
            ),
            "NDJSON stream is incomplete; output is unavailable for a terminal record",
            vec![error.message],
        )
    } else {
        error
    };
    let exit_code = error.exit_code();
    let (emitted, report_write_error) = match format {
        output::contract::Format::Json => (
            emit_json(&output::envelope::Envelope::<()>::error(
                Some(command),
                error.output_error(),
            )),
            true,
        ),
        output::contract::Format::Ndjson if open => (
            stream
                .emit_error(error.output_error())
                .map_err(CliError::from),
            true,
        ),
        output::contract::Format::Ndjson => (emit_stderr_error(&error), false),
        _ => (emit_stderr_error(&error), false),
    };
    if let Err(write_error) = emitted {
        if report_write_error {
            let _ = emit_stderr_error(&write_error);
        }
        return write_error.exit_code();
    }
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_ndjson_requires_a_terminal_record() {
        let stream = StreamEncoder::new(
            output::contract::Command::Read,
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
