// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::time::Duration;

use packetcraftr::runtime::{self, Worker};
use packetcraftr_core::budget::Deadline;

use crate::errors::CliError;

use crate::output;

pub(crate) use crate::output::stream::StreamEncoder;

/// Per-write ceiling when `--output-timeout-ms` is absent.
pub(crate) const OUTPUT_TIMEOUT_MS: u64 = 1000;
const OUTPUT_TIMEOUT: Duration = Duration::from_millis(OUTPUT_TIMEOUT_MS);

pub(crate) fn stdout_stream(
    command: output::contract::Command,
    timeout: Duration,
) -> Result<StreamEncoder, CliError> {
    let runtime = crate::system::runtime(crate::system::Runtime::OutputWriter);
    StreamEncoder::new_bounded(command, io::stdout(), &runtime, timeout)
        .map(|stream| stream.with_terminal_error_timeout(OUTPUT_TIMEOUT))
        .map_err(CliError::classified)
}

pub(crate) fn write_unattributed_error(
    command: Option<output::contract::Command>,
    error: output::envelope::Error,
) -> Result<(), CliError> {
    let runtime = crate::system::runtime(crate::system::Runtime::OutputWriter);
    let sink = Worker::new_in(&runtime, move |error| {
        output::stream::write_unattributed_error(io::stdout(), command, error)
            .map_err(|error| CliError::from(error).into_boundary_error())
    })
    .map_err(CliError::classified)?;
    sink.emit(error, &Deadline::new(OUTPUT_TIMEOUT))
        .map_err(|source| match source {
            // The callback already reported the classified write failure.
            runtime::Error::Output(source) => CliError::classified(source),
            source => CliError::from(output::stream::EncodeError::Write {
                sequence: 0,
                source: io::Error::other(source),
            }),
        })
}
