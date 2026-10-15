// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::Kind;

use std::io::{self, Write};

use packetcraftr_core as core;

use super::stdout::stdout_error;
use crate::output;
use serde::Serialize;

use crate::errors::CliError;

#[derive(Debug)]
pub(crate) enum BoundedJsonError {
    Limit,
    Serialize(serde_json::Error),
}

impl BoundedJsonError {
    pub(crate) fn into_cli_error(self, limit: impl FnOnce() -> CliError) -> CliError {
        match self {
            Self::Limit => limit(),
            Self::Serialize(source) => {
                CliError::new(Kind::Internal, format!("serialize output failed: {source}"))
            }
        }
    }
}

pub(crate) fn bounded_json_len(
    value: &impl Serialize,
    limit: usize,
) -> Result<usize, BoundedJsonError> {
    bounded_json_len_with_formatter(value, limit, serde_json::ser::CompactFormatter)
}

pub(crate) fn bounded_pretty_json_len(
    value: &impl Serialize,
    limit: usize,
) -> Result<usize, BoundedJsonError> {
    bounded_json_len_with_formatter(value, limit, serde_json::ser::PrettyFormatter::new())
}

fn bounded_json_len_with_formatter(
    value: &impl Serialize,
    limit: usize,
    formatter: impl serde_json::ser::Formatter,
) -> Result<usize, BoundedJsonError> {
    struct Counter {
        remaining: usize,
        exceeded: bool,
    }

    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.remaining {
                self.exceeded = true;
                return Err(io::Error::other("JSON output limit"));
            }
            self.remaining -= bytes.len();
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter {
        remaining: limit,
        exceeded: false,
    };
    match value.serialize(&mut serde_json::Serializer::with_formatter(
        &mut counter,
        formatter,
    )) {
        Ok(()) => Ok(limit - counter.remaining),
        Err(_) if counter.exceeded => Err(BoundedJsonError::Limit),
        Err(source) => Err(BoundedJsonError::Serialize(source)),
    }
}

pub(crate) fn emit_json(
    invocation: &crate::invocation::Invocation,
    value: &impl Serialize,
) -> Result<(), CliError> {
    invocation.check()?;
    let stdout = io::stdout().lock();
    let mut writer = io::BufWriter::with_capacity(64 * 1024, stdout);
    serde_json::to_writer_pretty(&mut writer, value).map_err(json_error)?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|source| stdout_error("write stdout failed", source))
}

fn json_error(source: serde_json::Error) -> CliError {
    if source.is_io() {
        stdout_error("write stdout failed", io::Error::from(source))
    } else {
        CliError::new(Kind::Internal, format!("serialize output failed: {source}"))
    }
}

pub(crate) fn emit_aggregate<T: Serialize>(
    invocation: &crate::invocation::Invocation,
    command: output::contract::Command,
    result: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
) -> Result<(), CliError> {
    invocation.check()?;
    emit_json(
        invocation,
        &invocation.decorate(output::envelope::Envelope::success(
            command,
            result,
            diagnostics,
        )),
    )
}

pub(crate) fn emit_aggregate_with_stats<T: Serialize>(
    invocation: &crate::invocation::Invocation,
    command: output::contract::Command,
    result: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    invocation.check()?;
    emit_json(
        invocation,
        &invocation.decorate(
            output::envelope::Envelope::success(command, result, diagnostics).with_stats(stats),
        ),
    )
}

pub(crate) fn emit_published<T: Serialize>(
    invocation: &crate::invocation::Invocation,
    command: output::contract::Command,
    published: output::envelope::Published<T>,
) -> Result<(), CliError> {
    invocation.check()?;
    emit_json(
        invocation,
        &invocation.decorate(output::envelope::Envelope::published(command, published)),
    )
}
