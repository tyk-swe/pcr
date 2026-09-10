// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(test)]
use crate::test_support::TestRecord;

use packetcraftr_core::error::Kind;

mod context;

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::{CommandFactory, FromArgMatches};
use packetcraftr_cli::output;

use self::context::{MachineFormat, from_env};
use super::cli::Cli;
use super::errors::{CANCELLED_EXIT_CODE, CliError, exit_code_for};
use super::rendering::{
    StreamEncoder, emit_json, emit_stderr_document, emit_stderr_error, emit_stdout_document,
    stdout_stream, terminal_document, write_unattributed_error,
};

pub(crate) fn run() -> ExitCode {
    let context = from_env();
    context.color.write_global();
    let (cli, matches) = match Cli::command()
        .try_get_matches()
        .and_then(|matches| Cli::from_arg_matches(&matches).map(|cli| (cli, matches)))
    {
        Ok(parsed) => parsed,
        Err(error) => {
            let code = u8::try_from(error.exit_code()).unwrap_or(exit_code_for(Kind::Internal));
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
                    Ok(()) => ExitCode::from(code),
                    Err(write_error) => {
                        let _ = emit_stderr_error(&write_error);
                        ExitCode::from(write_error.exit_code())
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
                Err(_) => ExitCode::from(exit_code_for(Kind::Io)),
            };
        }
    };
    cli.color.write_global();
    let format = cli.format;
    if matches!(
        format,
        output::contract::Format::Raw
            | output::contract::Format::Pcap
            | output::contract::Format::PcapNg
    ) && cli.command.kind().formats().contains(&format)
        && std::io::stdout().is_terminal()
        && !cli.force_binary_stdout
    {
        let error = CliError::new(
            Kind::Cli,
            "refusing binary output to a terminal; redirect stdout to a file or pipe, or pass --force-binary-stdout",
        );
        let _ = emit_stderr_error(&error);
        return ExitCode::from(error.exit_code());
    }
    let command = cli.command.kind();
    if cli.resource_diagnostics
        && matches!(
            format,
            output::contract::Format::Json | output::contract::Format::Ndjson
        )
    {
        crate::resources::configure(&matches, command, format);
    }
    let stream = match if format == output::contract::Format::Ndjson {
        stdout_stream(
            command,
            std::time::Duration::from_millis(cli.output_timeout_ms.unwrap_or(1000)),
        )
    } else {
        Ok(StreamEncoder::new(command, std::io::stdout()))
    } {
        Ok(stream) => stream,
        Err(error) => {
            let _ = emit_stderr_error(&error);
            return ExitCode::from(error.exit_code());
        }
    };
    if cli.resource_diagnostics
        && !matches!(
            format,
            output::contract::Format::Json | output::contract::Format::Ndjson
        )
    {
        return command_failure(
            format,
            command,
            CliError::new(
                Kind::Cli,
                "--resource-diagnostics requires --output json or ndjson",
            ),
            &stream,
        );
    }
    if cli.output_timeout_ms.is_some() && format != output::contract::Format::Ndjson {
        return command_failure(
            format,
            command,
            CliError::new(Kind::Cli, "--output-timeout-ms requires --output ndjson"),
            &stream,
        );
    }
    let stream = if cli.resource_diagnostics {
        stream.with_resource_diagnostics(|| {
            crate::resources::snapshot().expect("diagnostics configured")
        })
    } else {
        stream
    };
    if cli.command.supports_cancellation()
        && let Err(error) = crate::cancellation::install()
    {
        return command_failure(format, command, error, &stream);
    }
    match cli.command.run(format, &stream) {
        Ok(()) => {
            if let Err(error) = crate::cancellation::check() {
                if format == output::contract::Format::Json {
                    // The aggregate document has already been published. A
                    // late interrupt changes the exit status, but a second
                    // stdout document would invalidate the completed JSON.
                    let _ = emit_stderr_error(&error);
                    return ExitCode::from(CANCELLED_EXIT_CODE);
                }
                return command_failure(format, command, error, &stream);
            }
            match require_success_terminal(format, &stream) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => command_failure(format, command, error, &stream),
            }
        }
        Err(error) => command_failure(format, command, error, &stream),
    }
}

fn require_success_terminal(
    format: output::contract::Format,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    if format == output::contract::Format::Ndjson && !stream.is_complete() {
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
) -> ExitCode {
    let open = stream.is_open();
    let error = if format == output::contract::Format::Ndjson && !open && !stream.is_terminal() {
        let causes = std::iter::once(error.message).chain(error.causes).collect();
        CliError::from_classification(
            packetcraftr_core::error::Classification::new(
                "io.stdout",
                Kind::Io,
                Some("treat the structured stream as incomplete"),
            ),
            "NDJSON stream is incomplete; output is unavailable for a terminal record",
            causes,
        )
    } else {
        error
    };
    let exit_code = if crate::cancellation::signal().is_cancelled() {
        CANCELLED_EXIT_CODE
    } else {
        error.exit_code()
    };
    let (emitted, report_write_error) = match format {
        output::contract::Format::Json => (
            emit_json(&crate::resources::decorate(
                output::envelope::Envelope::<()>::error(Some(command), error.output_error()),
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
        return ExitCode::from(write_error.exit_code());
    }
    ExitCode::from(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_encoder_fails_cleanup_without_another_output_attempt() {
        use std::io::{self, Write};
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        struct BlockedWriter(mpsc::Sender<()>, mpsc::Receiver<()>);
        impl Write for BlockedWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.send(()).unwrap();
                self.1
                    .recv_timeout(Duration::from_secs(3))
                    .map_err(io::Error::other)?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (entered, writer_entered) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let stream = StreamEncoder::new(
            output::contract::Command::Scan,
            BlockedWriter(entered, wait),
        );
        let callback = stream.clone();
        let worker = std::thread::spawn(move || callback.emit_data(TestRecord(()), Vec::new()));
        writer_entered.recv_timeout(Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        let status = command_failure(
            output::contract::Format::Ndjson,
            output::contract::Command::Scan,
            CliError::new(Kind::Policy, "workflow publication deadline expired"),
            &stream,
        );
        assert_eq!(status, ExitCode::from(5));
        assert!(started.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
        worker.join().unwrap().unwrap();
        assert!(writer_entered.try_recv().is_err());
    }

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
    #[test]
    fn a_terminal_error_cannot_satisfy_successful_completion() {
        let stream = StreamEncoder::new(output::contract::Command::Read, Vec::new());
        stream
            .emit_error(CliError::new(Kind::Io, "fixture failure").output_error())
            .unwrap();
        assert!(stream.is_terminal());
        assert!(require_success_terminal(output::contract::Format::Ndjson, &stream).is_err());
    }
}
