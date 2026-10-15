// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::{contract::Format, stream::StreamRecord};
use crate::{errors::CliError, rendering::bounded_json_len};
use packetcraftr_core::error::Kind;

pub(crate) struct EventOutput<'a> {
    format: Format,
    invocation: &'a crate::invocation::Invocation,
    remaining: usize,
}

impl<'a> EventOutput<'a> {
    pub(crate) fn new(invocation: &'a crate::invocation::Invocation, maximum: usize) -> Self {
        Self {
            format: invocation.format,
            invocation,
            remaining: maximum,
        }
    }

    pub(crate) fn emit<T: StreamRecord>(
        &mut self,
        value: T,
        retained: &mut Vec<T>,
        render_text: impl FnOnce(&crate::invocation::Invocation, &T) -> Result<(), CliError>,
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
            Format::Json => retained.push(value),
            Format::Ndjson => self
                .invocation
                .output
                .emit_data(value, Vec::new())
                .map_err(CliError::from)?,
            Format::Text => render_text(self.invocation, &value)?,
            other => other.unreachable(),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(dead_code)]

    use std::cell::Cell;
    use std::io::{self, Write};

    use serde::Serialize;
    use serde::ser::{Error as _, SerializeSeq};

    use crate::output::contract::Command;

    use crate::test_support::{SharedBuffer, TestRecord};

    use super::*;
    use crate::rendering::StreamEncoder;

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
    fn the_budget_is_shared_across_record_types_and_retention_vectors() {
        let _invocation = &crate::test_support::invocation();

        let buffer = SharedBuffer::default();
        let stream = StreamEncoder::new(Command::Http, buffer);
        let invocation = crate::invocation::Invocation::new(
            Format::Json,
            stream,
            None,
            Default::default(),
            None,
        );
        let mut output = EventOutput::new(&invocation, 5);
        let mut strings: Vec<TestRecord<&str>> = Vec::new();
        let mut numbers: Vec<TestRecord<u64>> = Vec::new();
        let rendered = Cell::new(false);
        output
            .emit(TestRecord("ab"), &mut strings, |_, _| {
                rendered.set(true);
                Ok(())
            })
            .unwrap();
        output
            .emit(TestRecord(1), &mut numbers, |_, _| {
                rendered.set(true);
                Ok(())
            })
            .unwrap();
        assert_eq!(strings.len(), 1);
        assert_eq!(numbers.len(), 1);
        assert!(!rendered.get());
        let error = output
            .emit(TestRecord(2), &mut numbers, |_, _| {
                rendered.set(true);
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.classification.kind, Kind::Policy);
        assert_eq!(numbers.len(), 1);
    }

    #[test]
    fn stream_write_failures_keep_their_io_classification() {
        let _invocation = &crate::test_support::invocation();

        let stream = StreamEncoder::new(Command::Http, BrokenPipe);
        let invocation = crate::invocation::Invocation::new(
            Format::Ndjson,
            stream,
            None,
            Default::default(),
            None,
        );
        let mut output = EventOutput::new(&invocation, usize::MAX);
        let mut retained = Vec::new();
        let rendered = Cell::new(false);
        let error = output
            .emit(TestRecord("ab"), &mut retained, |_, _| {
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
