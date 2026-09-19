// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    errors::CliError,
    rendering::{StreamEncoder, bounded_json_len},
};
use packetcraftr_cli::output::{contract::ToolFormat, stream::StreamRecord};
use packetcraftr_core::error::Kind;

pub(super) struct EventOutput<'a> {
    format: ToolFormat,
    stream: &'a StreamEncoder,
    remaining: usize,
}

impl<'a> EventOutput<'a> {
    pub(super) fn new(format: ToolFormat, stream: &'a StreamEncoder, maximum: usize) -> Self {
        Self {
            format,
            stream,
            remaining: maximum,
        }
    }

    pub(super) fn emit<T: StreamRecord>(
        &mut self,
        value: T,
        retained: &mut Vec<T>,
        render_text: impl FnOnce(&T) -> Result<(), CliError>,
    ) -> Result<(), CliError> {
        let bytes = bounded_json_len(&value, self.remaining).map_err(|error| {
            error.into_cli_error(|| {
                CliError::new(
                    Kind::Policy,
                    "application output exceeds --max-application-output-bytes",
                )
            })
        })?;
        self.remaining -= bytes;
        match self.format {
            ToolFormat::Json => retained.push(value),
            ToolFormat::Ndjson => self
                .stream
                .emit_data(value, Vec::new())
                .map_err(CliError::from)?,
            ToolFormat::Text => render_text(&value)?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{self, Write};

    use serde::Serialize;
    use serde::ser::{Error as _, SerializeSeq};

    use packetcraftr_cli::output::contract::Command;

    use crate::test_support::{SharedBuffer, TestRecord, assert_contiguous};

    use super::*;

    struct FailingSerialization;

    impl Serialize for FailingSerialization {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(2))?;
            sequence.serialize_element(&0u8)?;
            Err(S::Error::custom("fixture serialization failure"))
        }
    }

    impl StreamRecord for FailingSerialization {
        fn event_name(&self) -> &'static str {
            "frame"
        }
    }

    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fixture closed sink",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn exact_budget_routes_each_format_to_its_own_sink() {
        for format in [ToolFormat::Json, ToolFormat::Ndjson, ToolFormat::Text] {
            let buffer = SharedBuffer::default();
            let stream = StreamEncoder::new(Command::Http, buffer.clone());
            let mut output = EventOutput::new(format, &stream, 4);
            let mut retained = Vec::new();
            let rendered = Cell::new(false);
            output
                .emit(TestRecord("ab"), &mut retained, |_| {
                    rendered.set(true);
                    Ok(())
                })
                .unwrap();
            assert_eq!(retained.len(), usize::from(format == ToolFormat::Json));
            assert_eq!(rendered.get(), format == ToolFormat::Text);
            assert_eq!(
                buffer.records().len(),
                usize::from(format == ToolFormat::Ndjson)
            );
            let mut retained = Vec::new();
            let rendered = Cell::new(false);
            let error = output
                .emit(TestRecord("oversized"), &mut retained, |_| {
                    rendered.set(true);
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.classification.kind, Kind::Policy);
            assert_eq!(
                error.message,
                "application output exceeds --max-application-output-bytes"
            );
            assert!(retained.is_empty());
            assert!(!rendered.get());
            assert_eq!(
                buffer.records().len(),
                usize::from(format == ToolFormat::Ndjson)
            );
        }
    }

    #[test]
    fn the_budget_is_shared_across_record_types_and_retention_vectors() {
        let buffer = SharedBuffer::default();
        let stream = StreamEncoder::new(Command::Http, buffer);
        let mut output = EventOutput::new(ToolFormat::Json, &stream, 5);
        let mut strings: Vec<TestRecord<&str>> = Vec::new();
        let mut numbers: Vec<TestRecord<u64>> = Vec::new();
        let rendered = Cell::new(false);
        output
            .emit(TestRecord("ab"), &mut strings, |_| {
                rendered.set(true);
                Ok(())
            })
            .unwrap();
        output
            .emit(TestRecord(1), &mut numbers, |_| {
                rendered.set(true);
                Ok(())
            })
            .unwrap();
        assert_eq!(strings.len(), 1);
        assert_eq!(numbers.len(), 1);
        assert!(!rendered.get());
        let error = output
            .emit(TestRecord(2), &mut numbers, |_| {
                rendered.set(true);
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.classification.kind, Kind::Policy);
        assert_eq!(numbers.len(), 1);
    }

    #[test]
    fn failed_sizing_and_serialization_preserve_the_remaining_budget() {
        let buffer = SharedBuffer::default();
        let stream = StreamEncoder::new(Command::Http, buffer.clone());
        let mut output = EventOutput::new(ToolFormat::Ndjson, &stream, 4);
        let mut failures = Vec::new();
        let rendered = Cell::new(false);
        let mut rejected = Vec::new();
        let quota = output
            .emit(TestRecord("oversized"), &mut rejected, |_| {
                rendered.set(true);
                Ok(())
            })
            .unwrap_err();
        assert_eq!(quota.classification.code, "policy.denied");
        assert_eq!(quota.exit_code(), 6);
        assert!(rejected.is_empty());
        assert!(buffer.records().is_empty());
        assert!(!rendered.get());
        let error = output
            .emit(FailingSerialization, &mut failures, |_| {
                rendered.set(true);
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.classification.kind, Kind::Internal);
        assert_eq!(error.exit_code(), 70);
        assert_eq!(
            error.message,
            "serialize output failed: fixture serialization failure"
        );
        assert!(failures.is_empty());
        assert!(buffer.records().is_empty());
        assert!(!rendered.get());
        let mut retained = Vec::new();
        output
            .emit(TestRecord("ab"), &mut retained, |_| {
                rendered.set(true);
                Ok(())
            })
            .unwrap();
        assert!(retained.is_empty());
        let records = buffer.records();
        assert_contiguous(&records);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["result"], "ab");
        assert!(!rendered.get());
    }

    #[test]
    fn text_render_failures_propagate_unchanged_after_sizing() {
        let buffer = SharedBuffer::default();
        let stream = StreamEncoder::new(Command::Http, buffer.clone());
        let mut output = EventOutput::new(ToolFormat::Text, &stream, 4);
        let mut retained = Vec::new();
        let error = output
            .emit(TestRecord("ab"), &mut retained, |_| {
                Err(CliError::new(Kind::Io, "fixture render failure"))
            })
            .unwrap_err();
        assert_eq!(error.message, "fixture render failure");
        assert_eq!(error.classification.kind, Kind::Io);
        assert!(retained.is_empty());
        assert!(buffer.bytes().is_empty());
        let next = output
            .emit(TestRecord("ab"), &mut retained, |_| Ok(()))
            .unwrap_err();
        assert_eq!(next.classification.kind, Kind::Policy);
    }

    #[test]
    fn stream_write_failures_keep_their_io_classification() {
        let stream = StreamEncoder::new(Command::Http, BrokenPipe);
        let mut output = EventOutput::new(ToolFormat::Ndjson, &stream, usize::MAX);
        let mut retained = Vec::new();
        let rendered = Cell::new(false);
        let error = output
            .emit(TestRecord("ab"), &mut retained, |_| {
                rendered.set(true);
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.classification.kind, Kind::Io);
        assert_eq!(error.exit_code(), 5);
        assert!(retained.is_empty());
        assert!(!rendered.get());
    }
}
