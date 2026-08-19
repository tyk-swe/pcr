// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};

use packetcraftr::{core, output};
use serde::Serialize;

use super::super::errors::CliError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Open,
    Terminal,
    Failed,
}

pub(crate) struct NdjsonStream {
    command: Option<output::contract::Command>,
    position: output::envelope::StreamPosition,
    state: State,
    writer: Box<dyn Write>,
}

impl NdjsonStream {
    pub(crate) fn stdout(command: Option<output::contract::Command>) -> Self {
        Self::new(command, io::stdout())
    }

    pub(crate) fn new(
        command: Option<output::contract::Command>,
        writer: impl Write + 'static,
    ) -> Self {
        Self {
            command,
            position: output::envelope::StreamPosition::initial(),
            state: State::Open,
            writer: Box::new(writer),
        }
    }

    pub(crate) fn emit_data<T: Serialize>(
        &mut self,
        result: T,
        diagnostics: Vec<core::diagnostic::Diagnostic>,
    ) -> Result<(), CliError> {
        self.require_open()?;
        let next = self.position.checked_next().map_err(CliError::classified)?;
        let command = self.success_command()?;
        let record =
            output::envelope::Stream::success(command, &self.position, result, diagnostics);
        self.write_record(&record)?;
        self.position = next;
        Ok(())
    }

    pub(crate) fn complete<T: Serialize>(
        &mut self,
        result: T,
        diagnostics: Vec<core::diagnostic::Diagnostic>,
    ) -> Result<(), CliError> {
        self.complete_record(result, diagnostics, None)
    }

    pub(crate) fn complete_with_stats<T: Serialize>(
        &mut self,
        result: T,
        diagnostics: Vec<core::diagnostic::Diagnostic>,
        stats: output::envelope::Stats,
    ) -> Result<(), CliError> {
        self.complete_record(result, diagnostics, Some(stats))
    }

    pub(crate) fn emit_error(&mut self, error: output::envelope::Error) -> Result<(), CliError> {
        self.require_open()?;
        let record = output::envelope::StreamError::error(self.command, &self.position, error);
        self.write_record(&record)?;
        self.state = State::Terminal;
        Ok(())
    }

    pub(crate) fn is_open(&self) -> bool {
        self.state == State::Open
    }

    #[cfg(test)]
    pub(crate) fn next_position(&self) -> u64 {
        self.position.ordinal()
    }

    #[cfg(test)]
    pub(crate) fn is_failed(&self) -> bool {
        self.state == State::Failed
    }

    fn complete_record<T: Serialize>(
        &mut self,
        result: T,
        diagnostics: Vec<core::diagnostic::Diagnostic>,
        stats: Option<output::envelope::Stats>,
    ) -> Result<(), CliError> {
        self.require_open()?;
        let command = self.success_command()?;
        let mut record =
            output::envelope::Stream::success(command, &self.position, result, diagnostics);
        if let Some(stats) = stats {
            record = record.with_stats(stats);
        }
        self.write_record(&record)?;
        self.state = State::Terminal;
        Ok(())
    }

    fn success_command(&self) -> Result<output::contract::Command, CliError> {
        self.command
            .ok_or_else(|| CliError::new(70, "NDJSON success record has no command"))
    }

    fn require_open(&self) -> Result<(), CliError> {
        match self.state {
            State::Open => Ok(()),
            State::Terminal => Err(CliError::new(70, "NDJSON stream is already terminated")),
            State::Failed => Err(CliError::new(70, "NDJSON stream output has already failed")),
        }
    }

    fn write_record(&mut self, record: &impl Serialize) -> Result<(), CliError> {
        let attempted_position = self.position.ordinal();
        let mut line = match serde_json::to_vec(record) {
            Ok(line) => line,
            Err(source) => {
                self.state = State::Failed;
                return Err(attempted_record_error(
                    CliError::new(70, format!("serialize output failed: {source}")),
                    attempted_position,
                ));
            }
        };
        line.push(b'\n');
        if let Err(source) = self
            .writer
            .write_all(&line)
            .and_then(|()| self.writer.flush())
        {
            self.state = State::Failed;
            return Err(attempted_record_error(
                CliError::new(5, format!("write stdout failed: {source}")),
                attempted_position,
            ));
        }
        Ok(())
    }
}

fn attempted_record_error(mut error: CliError, position: u64) -> CliError {
    error.message = format!(
        "NDJSON record at sequence {position} failed: {}",
        error.message
    );
    error
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::RefCell;
    use std::io;
    use std::rc::Rc;

    use serde_json::Value;

    use super::*;

    #[derive(Clone, Default)]
    pub(crate) struct SharedBuffer(Rc<RefCell<Vec<u8>>>);

    impl SharedBuffer {
        pub(crate) fn bytes(&self) -> Vec<u8> {
            self.0.borrow().clone()
        }

        pub(crate) fn records(&self) -> Vec<Value> {
            std::str::from_utf8(&self.0.borrow())
                .expect("NDJSON output is UTF-8")
                .lines()
                .map(|line| serde_json::from_str(line).expect("each line is valid JSON"))
                .collect()
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn stream(command: output::contract::Command) -> (NdjsonStream, SharedBuffer) {
        let output = SharedBuffer::default();
        (NdjsonStream::new(Some(command), output.clone()), output)
    }

    pub(crate) fn assert_contiguous(records: &[Value]) {
        for (expected, record) in records.iter().enumerate() {
            assert_eq!(
                record["sequence"].as_u64(),
                u64::try_from(expected).ok(),
                "record {expected} has the wrong stream position"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use serde::ser::Error as _;
    use serde_json::json;

    use super::test_support::{SharedBuffer, assert_contiguous, stream};
    use super::*;

    #[test]
    fn data_and_completion_are_contiguous_from_zero() {
        let (mut stream, output) = stream(output::contract::Command::Read);
        assert_eq!(stream.next_position(), 0);

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
    fn errors_use_the_next_unwritten_position() {
        let fixture_error = || CliError::new(5, "fixture failed").output_error();

        let (mut empty, empty_output) = stream(output::contract::Command::Capture);
        empty.emit_error(fixture_error()).unwrap();
        assert_eq!(empty_output.records()[0]["sequence"], 0);

        let (mut partial, partial_output) = stream(output::contract::Command::Capture);
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
        let (mut stream, output) = stream(output::contract::Command::Replay);
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
        let (mut success_stream, output) = stream(output::contract::Command::Follow);
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

        let (mut error_stream, output) = stream(output::contract::Command::Follow);
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
    fn serialization_failure_names_the_attempted_position_and_closes_output() {
        let (mut stream, output) = stream(output::contract::Command::Expert);
        stream.emit_data(json!({"ok": true}), Vec::new()).unwrap();
        let error = stream
            .emit_data(FailingSerialization, Vec::new())
            .expect_err("serialization must fail");

        assert!(error.message.contains("sequence 1"));
        assert!(stream.is_failed());
        assert_eq!(output.records().len(), 1);
        assert!(
            stream
                .emit_error(CliError::new(5, "late").output_error())
                .is_err()
        );
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
        let mut stream = NdjsonStream::new(Some(output::contract::Command::Capture), writer);
        stream.emit_data(json!({"value": 0}), Vec::new()).unwrap();
        let error = stream
            .emit_data(json!({"value": 1}), Vec::new())
            .expect_err("second flush must fail");

        assert!(error.message.contains("sequence 1"));
        assert!(stream.is_failed());
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
