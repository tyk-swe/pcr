// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::Kind;

use std::io::{self, Write};

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
            Self::Serialize(source) => serialization_error(source),
        }
    }
}

pub(crate) fn serialization_error(source: serde_json::Error) -> CliError {
    CliError::wrapping(Kind::Internal, "serialize output failed", &source)
}

pub(crate) fn bounded_json_len(
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
    let stdout = io::stdout().lock();
    emit_json_to(invocation, value, stdout)
}

fn emit_json_to(
    invocation: &crate::invocation::Invocation,
    value: &impl Serialize,
    writer: impl Write,
) -> Result<(), CliError> {
    invocation.check()?;
    invocation.begin_json()?;
    let mut writer = io::BufWriter::with_capacity(64 * 1024, writer);
    let result = write_json(&mut writer, value);
    // BufWriter's Drop would retry buffered output after a failed write or flush.
    let _ = writer.into_parts();
    result
}

fn write_json(writer: &mut impl Write, value: &impl Serialize) -> Result<(), CliError> {
    serde_json::to_writer_pretty(&mut *writer, value).map_err(json_error)?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|source| stdout_error("write stdout failed", source))
}

fn json_error(source: serde_json::Error) -> CliError {
    if source.is_io() {
        stdout_error("write stdout failed", io::Error::from(source))
    } else {
        serialization_error(source)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        invocation::{Invocation, StreamEncoder},
        output::contract::{Command, Format},
    };
    use serde::{Serializer, ser::SerializeStruct};

    fn invocation() -> Invocation {
        Invocation::new(
            Format::Json,
            StreamEncoder::new(Command::Build, io::sink()),
            None,
            Default::default(),
            None,
        )
    }

    struct InvalidValue(usize);

    impl Serialize for InvalidValue {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut value = serializer.serialize_struct("InvalidValue", 1)?;
            value.serialize_field("prefix", &"a".repeat(self.0))?;
            Err(serde::ser::Error::custom("injected serialization failure"))
        }
    }

    #[derive(Default)]
    struct FailingWriter {
        bytes: Vec<u8>,
        writes: usize,
        flushes: usize,
        fail_flush: bool,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if !self.fail_flush && self.writes > 1 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected write failure",
                ));
            }
            let count = if self.fail_flush {
                bytes.len()
            } else {
                bytes.len().min(3)
            };
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Err(io::Error::other("injected flush failure"))
        }
    }

    #[test]
    fn error_handling_json_serialization_failure_never_publishes_a_second_document() {
        for length in [0, 70_000] {
            let invocation = invocation();
            let mut bytes = Vec::new();
            let error = emit_json_to(&invocation, &InvalidValue(length), &mut bytes).unwrap_err();
            assert_eq!(error.classification.kind, Kind::Internal);
            assert_eq!(error.causes, ["injected serialization failure"]);
            let written = bytes.len();
            assert_eq!(written > 0, length > 0);
            assert!(invocation.clone().terminal().json_attempted());
            assert!(
                emit_json_to(
                    &invocation.terminal(),
                    &serde_json::json!({"error": "second"}),
                    &mut bytes
                )
                .is_err()
            );
            assert_eq!(bytes.len(), written);
        }
    }

    #[test]
    fn error_handling_json_write_and_flush_failures_do_not_retry_buffered_bytes() {
        for fail_flush in [false, true] {
            let invocation = invocation();
            let mut writer = FailingWriter {
                fail_flush,
                ..Default::default()
            };
            let error = emit_json_to(&invocation, &serde_json::json!({"value": 1}), &mut writer)
                .unwrap_err();
            assert_eq!(error.classification.code, "io.stdout");
            assert!(!error.causes.is_empty());
            assert_eq!(writer.writes, if fail_flush { 1 } else { 2 });
            assert_eq!(writer.flushes, usize::from(fail_flush));
            let writes = writer.writes;
            assert!(emit_json_to(&invocation.terminal(), &(), &mut writer).is_err());
            assert_eq!(writer.writes, writes);
        }
    }

    #[test]
    fn error_handling_json_prepublication_cancellation_still_allows_terminal_report() {
        let invocation = invocation();
        invocation.cancellation.cancel();
        let mut bytes = Vec::new();
        assert!(emit_json_to(&invocation, &(), &mut bytes).is_err());
        assert!(!invocation.json_attempted());
        assert!(bytes.is_empty());
        let envelope = output::envelope::Envelope::<()>::error(
            Some(Command::Build),
            CliError::new(Kind::Io, "cancelled").output_error(),
        );
        emit_json_to(&invocation.terminal(), &envelope, &mut bytes).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["schema"], "packetcraftr.output/v1");
        assert_eq!(document["status"], "error");
        assert_eq!(bytes.last(), Some(&b'\n'));
    }
}
