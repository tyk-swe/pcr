// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The NDJSON stream every structured command writes through.

#[cfg(test)]
use crate::test_support::TestRecord;

use std::io;
use std::time::Duration;

use packetcraftr::progress::{Runtime, Sink};
use packetcraftr_core::budget::Deadline;

use crate::errors::CliError;

use packetcraftr_cli::output;

pub(crate) use packetcraftr_cli::output::stream::StreamEncoder;

/// Per-write ceiling; max-duration publishers clip it to their remaining budget.
/// A terminal error may use this separate cleanup allowance.
const OUTPUT_TIMEOUT: Duration = Duration::from_secs(1);

/// Opens the process-wide NDJSON stream on stdout.
pub(crate) fn stdout_stream(
    command: output::contract::Command,
    timeout: Duration,
) -> Result<StreamEncoder, CliError> {
    let runtime = crate::resources::runtime("output_writer", 1);
    StreamEncoder::new_bounded(command, io::stdout(), &runtime, timeout)
        .map(|stream| stream.with_terminal_error_timeout(OUTPUT_TIMEOUT))
        .map_err(CliError::classified)
}

/// Writes the one NDJSON error record a failure before command selection can
/// publish, which has no stream to join.
pub(crate) fn write_unattributed_error(
    command: Option<output::contract::Command>,
    error: output::envelope::Error,
) -> Result<(), CliError> {
    let sink = Sink::new_in(&Runtime::new(1), move |error| {
        output::stream::write_unattributed_error(io::stdout(), command, error)
            .map_err(|error| CliError::from(error).into_boundary_error())
    })
    .map_err(CliError::classified)?;
    sink.emit(error, &Deadline::new(OUTPUT_TIMEOUT))
        .map_err(|source| {
            CliError::from(output::stream::EncodeError::Write {
                sequence: 0,
                source: io::Error::other(format!("NDJSON stream is incomplete: {source}")),
            })
        })
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) use crate::test_support::{SharedBuffer, assert_contiguous};

    pub(crate) fn stream(command: output::contract::Command) -> (StreamEncoder, SharedBuffer) {
        let output = SharedBuffer::default();
        (StreamEncoder::new(command, output.clone()), output)
    }
}

#[cfg(test)]
mod tests {
    use packetcraftr_core::error::Kind;

    use serde::Serialize;
    use serde::ser::Error as _;
    use serde_json::json;

    use crate::errors::CliError;

    use super::test_support::{assert_contiguous, stream};
    use super::*;

    struct FailingSerialization;

    impl Serialize for FailingSerialization {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(S::Error::custom("fixture serialization failure"))
        }
    }

    #[test]
    fn serialization_failure_keeps_the_unwritten_position_open_for_terminal_error() {
        let (stream, output) = stream(output::contract::Command::Expert);
        stream
            .emit_data(TestRecord(json!({"ok": true})), Vec::new())
            .unwrap();
        let error = stream
            .emit_data(TestRecord(FailingSerialization), Vec::new())
            .expect_err("serialization must fail");

        assert!(error.to_string().contains("sequence 1"));
        assert!(stream.is_open());
        assert_eq!(output.records().len(), 1);
        stream
            .emit_error(CliError::new(Kind::Internal, "serialization failed").output_error())
            .unwrap();
        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records[1]["sequence"], 1);
        assert_eq!(records[1]["status"], "error");
    }
}
