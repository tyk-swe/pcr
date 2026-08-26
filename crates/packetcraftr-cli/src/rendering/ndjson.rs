// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The NDJSON stream every structured command writes through.

use std::io;

use packetcraftr::output;

pub(crate) use packetcraftr::output::envelope::StreamEncoder;

/// Opens the process-wide NDJSON stream on stdout.
pub(crate) fn stdout_stream(command: Option<output::contract::Command>) -> StreamEncoder {
    StreamEncoder::new(command, io::stdout())
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) use crate::test_support::{SharedBuffer, assert_contiguous};

    pub(crate) fn stream(command: output::contract::Command) -> (StreamEncoder, SharedBuffer) {
        let output = SharedBuffer::default();
        (StreamEncoder::new(Some(command), output.clone()), output)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use std::io::Write;

    use serde::Serialize;
    use serde::ser::Error as _;
    use serde_json::json;

    use crate::errors::CliError;

    use super::test_support::{SharedBuffer, assert_contiguous, stream};
    use super::*;

    #[test]
    fn data_and_completion_are_contiguous_from_zero() {
        let (stream, output) = stream(output::contract::Command::Read);
        stream.emit_data(json!({"frame": 1}), Vec::new()).unwrap();
        stream.emit_data(json!({"frame": 2}), Vec::new()).unwrap();
        stream
            .complete(json!({"event": "complete"}), Vec::new())
            .unwrap();

        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 3);
        assert_eq!(records[2]["result"]["event"], "complete");
        assert!(!stream.is_open());
    }

    #[test]
    fn empty_success_completes_at_zero() {
        let (stream, output) = stream(output::contract::Command::Read);
        stream
            .complete(json!({"event": "complete"}), Vec::new())
            .unwrap();

        let records = output.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["status"], "success");
    }

    #[test]
    fn errors_use_the_next_unwritten_position() {
        let fixture_error = || CliError::new(5, "fixture failed").output_error();

        let (empty, empty_output) = stream(output::contract::Command::Capture);
        empty.emit_error(fixture_error()).unwrap();
        assert_eq!(empty_output.records()[0]["sequence"], 0);

        let (partial, partial_output) = stream(output::contract::Command::Capture);
        for value in 0..3 {
            partial
                .emit_data(json!({"value": value}), Vec::new())
                .unwrap();
        }
        partial.emit_error(fixture_error()).unwrap();
        let records = partial_output.records();
        assert_contiguous(&records);
        assert_eq!(records[3]["status"], "error");
    }

    #[test]
    fn domain_identifiers_do_not_select_envelope_positions() {
        let (stream, output) = stream(output::contract::Command::Replay);
        stream
            .emit_data(json!({"source_sequence": 42}), Vec::new())
            .unwrap();
        stream
            .complete(json!({"event": "complete"}), Vec::new())
            .unwrap();

        let records = output.records();
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["result"]["source_sequence"], 42);
        assert_eq!(records[1]["sequence"], 1);
    }

    #[test]
    fn terminal_state_rejects_every_later_record() {
        let (success_stream, output) = stream(output::contract::Command::Follow);
        success_stream
            .complete(json!({"done": true}), Vec::new())
            .unwrap();
        let terminal = output.bytes();

        assert!(
            success_stream
                .emit_data(json!({"late": true}), Vec::new())
                .is_err()
        );
        assert!(
            success_stream
                .emit_error(CliError::new(5, "late").output_error())
                .is_err()
        );
        assert_eq!(output.bytes(), terminal);

        let (error_stream, output) = stream(output::contract::Command::Follow);
        error_stream
            .emit_error(CliError::new(5, "terminal").output_error())
            .unwrap();
        let terminal = output.bytes();
        assert!(
            error_stream
                .emit_data(json!({"late": true}), Vec::new())
                .is_err()
        );
        assert_eq!(output.bytes(), terminal);
    }

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
        stream.emit_data(json!({"ok": true}), Vec::new()).unwrap();
        let error = stream
            .emit_data(FailingSerialization, Vec::new())
            .expect_err("serialization must fail");

        assert!(error.to_string().contains("sequence 1"));
        assert!(stream.is_open());
        assert_eq!(output.records().len(), 1);
        stream
            .emit_error(CliError::new(70, "serialization failed").output_error())
            .unwrap();
        let records = output.records();
        assert_contiguous(&records);
        assert_eq!(records[1]["sequence"], 1);
        assert_eq!(records[1]["status"], "error");
    }

    struct SecondFlushFails {
        output: SharedBuffer,
        flushes: usize,
    }

    impl Write for SecondFlushFails {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.output.write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.flushes == 2 {
                Err(io::Error::other("fixture flush failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn write_failure_names_the_attempted_position_without_appending_an_error() {
        let buffer = SharedBuffer::default();
        let writer = SecondFlushFails {
            output: buffer.clone(),
            flushes: 0,
        };
        let stream = StreamEncoder::new(Some(output::contract::Command::Capture), writer);
        stream.emit_data(json!({"value": 0}), Vec::new()).unwrap();
        let error = stream
            .emit_data(json!({"value": 1}), Vec::new())
            .expect_err("second flush must fail");

        assert!(error.to_string().contains("sequence 1"));
        assert!(!stream.is_open());
        assert!(!stream.is_terminal());
        let records = buffer.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 2);
        assert!(
            stream
                .emit_error(CliError::new(5, "late").output_error())
                .is_err()
        );
        assert_eq!(buffer.records(), records);
    }
}
