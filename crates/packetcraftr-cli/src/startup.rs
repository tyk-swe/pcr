// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::process::ExitCode;

use packetcraftr_core::error::Kind;

use crate::cli::{self, Context, MachineFormat};
use crate::errors::{CliError, exit_code_for};
use crate::output;
use crate::rendering::{
    emit_json, emit_stderr_document, emit_stderr_error, emit_stdout_document, terminal_document,
    write_unattributed_error,
};

pub(crate) fn run() -> ExitCode {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let context = cli::error_context(&arguments);
    context.color.write_global();
    let parsed = match cli::parse_from(arguments) {
        Ok(parsed) => parsed,
        Err(error) => return parse_error_exit(&context, &error),
    };
    parsed.cli.color.write_global();
    crate::commands::run(parsed)
}

fn parse_error_exit(context: &Context, error: &clap::Error) -> ExitCode {
    let code = u8::try_from(error.exit_code()).unwrap_or(exit_code_for(Kind::Internal));
    let raw_message = error.to_string();
    let message = terminal_document(&raw_message);
    if error.use_stderr()
        && let Some(format) = context.format
    {
        // clap exits 2 for usage errors; anything else is unexpected.
        // The process exit code stays clap's either way.
        let kind = if code == 2 {
            Kind::Usage
        } else {
            Kind::Internal
        };
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
    match emitted {
        Ok(()) => ExitCode::from(code),
        Err(_) => ExitCode::from(exit_code_for(Kind::Io)),
    }
}
