// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The publication deadline ends before error cleanup.

use std::io::IsTerminal;
use std::process::ExitCode;

use clap::ArgMatches;
use packetcraftr_core::error::Kind;

use super::{CommandExit, Generate, Spec};
use crate::cli::Parsed;
use crate::errors::{CANCELLED_EXIT_CODE, CliError};
use crate::output;
use crate::output::contract::{Command, Format};
use crate::rendering::{
    OUTPUT_TIMEOUT_MS, StreamEncoder, emit_json, emit_stderr_error, stdout_stream,
};
use crate::resources::Preset;

pub(crate) fn run(parsed: Parsed) -> ExitCode {
    let Parsed {
        cli,
        matches,
        definition,
    } = parsed;
    cli.command.start(Launch {
        format: output::contract::Format::from(cli.format),
        presentation: crate::rendering::Presentation {
            verbose: cli.verbose,
        },
        resource_diagnostics: cli.resource_diagnostics,
        resource_preset: cli.resource_preset,
        output_timeout_ms: cli.output_timeout_ms,
        force_binary_stdout: cli.force_binary_stdout,
        matches: &matches,
        definition: &definition,
    })
}

pub(super) struct Launch<'a> {
    format: output::contract::Format,
    presentation: crate::rendering::Presentation,
    resource_diagnostics: bool,
    resource_preset: Option<Preset>,
    output_timeout_ms: Option<u64>,
    force_binary_stdout: bool,
    matches: &'a ArgMatches,
    definition: &'a clap::Command,
}

impl Launch<'_> {
    pub(super) fn generate(self, arguments: impl Generate) -> ExitCode {
        let invocation = crate::invocation::Invocation::new(
            self.format,
            StreamEncoder::new(Command::Protocols, std::io::stdout()),
            None,
            crate::cancellation::signal().clone(),
            None,
        );
        match arguments.generate(&invocation, self.format) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                if let Err(write_error) = emit_stderr_error(&error) {
                    return ExitCode::from(write_error.exit_code());
                }
                ExitCode::from(error.exit_code())
            }
        }
    }

    pub(super) fn publish<T: Spec>(
        self,
        command: output::contract::Command,
        arguments: T,
    ) -> ExitCode {
        let format = self.format;
        if matches!(
            format,
            output::contract::Format::Raw
                | output::contract::Format::Pcap
                | output::contract::Format::PcapNg
        ) && command.formats().contains(&format)
            && std::io::stdout().is_terminal()
            && !self.force_binary_stdout
        {
            let error = CliError::new(
                Kind::Usage,
                "refusing binary output to a terminal; redirect stdout to a file or pipe, or pass --force-binary-stdout",
            );
            if let Err(write_error) = emit_stderr_error(&error) {
                return ExitCode::from(write_error.exit_code());
            }
            return ExitCode::from(error.exit_code());
        }
        let diagnostics = (self.resource_diagnostics
            && matches!(format, Format::Json | Format::Ndjson))
        .then(|| {
            std::sync::Arc::new(crate::resources::Diagnostics::new(
                crate::resources::collect_settings(
                    self.definition,
                    self.matches,
                    T::OFFLINE,
                    self.resource_preset,
                    self.output_timeout_ms,
                    format,
                    |settings| arguments.resources(settings),
                ),
            ))
        });
        let mut invocation = crate::invocation::Invocation::new(
            format,
            StreamEncoder::new(command, std::io::stdout()),
            arguments.publication_duration(),
            crate::cancellation::signal().clone(),
            diagnostics,
        );
        if format == Format::Ndjson {
            let stream = match stdout_stream(
                &invocation,
                command,
                std::time::Duration::from_millis(
                    self.output_timeout_ms.unwrap_or(OUTPUT_TIMEOUT_MS),
                ),
            ) {
                Ok(stream) => stream,
                Err(error) => {
                    let _ = emit_stderr_error(&error);
                    return ExitCode::from(error.exit_code());
                }
            };
            invocation = invocation.with_output(stream);
        }
        invocation.output = invocation.output.with_presentation(self.presentation);
        let stream = &invocation.output;
        if self.resource_diagnostics
            && !matches!(
                format,
                output::contract::Format::Json | output::contract::Format::Ndjson
            )
        {
            return command_failure(
                &invocation,
                command,
                CliError::new(
                    Kind::Usage,
                    "--resource-diagnostics requires --output json or ndjson",
                ),
            );
        }
        if self.output_timeout_ms.is_some() && format != output::contract::Format::Ndjson {
            return command_failure(
                &invocation,
                command,
                CliError::new(Kind::Usage, "--output-timeout-ms requires --output ndjson"),
            );
        }
        if T::CANCELLATION
            && let Err(error) = crate::cancellation::install()
        {
            return command_failure(&invocation, command, error);
        }
        match execute(&invocation, command, arguments) {
            Ok(exit) => {
                if let Err(error) = invocation
                    .cancellation
                    .check()
                    .map_err(CliError::classified)
                {
                    if format == output::contract::Format::Json {
                        // A second stdout document would invalidate the completed JSON.
                        let _ = emit_stderr_error(&error);
                        return ExitCode::from(CANCELLED_EXIT_CODE);
                    }
                    return command_failure(&invocation, command, error);
                }
                match require_success_terminal(format, stream) {
                    Ok(()) => ExitCode::from(exit.get()),
                    Err(error) => command_failure(&invocation, command, error),
                }
            }
            Err(error) => command_failure(&invocation, command, error),
        }
    }
}

fn execute<T: Spec>(
    invocation: &crate::invocation::Invocation,
    kind: Command,
    arguments: T,
) -> Result<CommandExit, CliError> {
    kind.require_format(invocation.format)?;
    arguments.run(invocation)
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
    invocation: &crate::invocation::Invocation,
    command: output::contract::Command,
    error: CliError,
) -> ExitCode {
    let format = invocation.format;
    let cancelled = invocation.cancellation.is_cancelled();
    let invocation = &invocation.terminal();
    let stream = &invocation.output;
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
    let exit_code = if cancelled {
        CANCELLED_EXIT_CODE
    } else {
        error.exit_code()
    };
    let (emitted, report_write_error) = match format {
        output::contract::Format::Json => (
            emit_json(
                invocation,
                &invocation.decorate(output::envelope::Envelope::<()>::error(
                    Some(command),
                    error.output_error(),
                )),
            ),
            true,
        ),
        output::contract::Format::Ndjson if open => (
            stream
                .emit_error(error.output_error())
                .map_err(CliError::from),
            true,
        ),
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
