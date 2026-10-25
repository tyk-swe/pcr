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

    enum WritePhase {
        Prefix(usize),
        Refuse,
        Accept,
    }

    struct FailingWriter {
        bytes: Vec<u8>,
        delivered: Vec<u8>,
        phase: WritePhase,
        refuse_flush: bool,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = match self.phase {
                WritePhase::Prefix(remaining) => {
                    let count = bytes.len().min(remaining);
                    self.phase = if count == remaining {
                        WritePhase::Refuse
                    } else {
                        WritePhase::Prefix(remaining - count)
                    };
                    count
                }
                WritePhase::Refuse => {
                    self.phase = WritePhase::Accept;
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "injected write failure",
                    ));
                }
                WritePhase::Accept => bytes.len(),
            };
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.refuse_flush {
                self.refuse_flush = false;
                return Err(io::Error::other("injected flush failure"));
            }
            self.delivered.clone_from(&self.bytes);
            Ok(())
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
            let expected =
                serde_json::to_vec_pretty(&serde_json::json!({"prefix": "a".repeat(length)}))
                    .unwrap();
            assert!(expected.starts_with(&bytes));
            let written = bytes.clone();
            assert!(
                emit_json_to(
                    &invocation.terminal(),
                    &serde_json::json!({"error": "second"}),
                    &mut bytes
                )
                .is_err()
            );
            assert_eq!(bytes, written);
        }
    }

    #[test]
    fn error_handling_json_write_and_flush_failures_do_not_retry_buffered_bytes() {
        for fail_write in [true, false] {
            let invocation = invocation();
            let mut writer = FailingWriter {
                bytes: Vec::new(),
                delivered: Vec::new(),
                phase: if fail_write {
                    WritePhase::Prefix(3)
                } else {
                    WritePhase::Accept
                },
                refuse_flush: true,
            };
            let error = emit_json_to(&invocation, &"fixture", &mut writer).unwrap_err();
            assert_eq!(error.classification.code, "io.stdout");
            let cause = if fail_write {
                "injected write failure"
            } else {
                "injected flush failure"
            };
            assert!(
                error.causes.iter().any(|value| value.contains(cause)),
                "{:?}",
                error.causes
            );
            let expected = if fail_write {
                b"\"fi".as_slice()
            } else {
                b"\"fixture\"\n"
            };
            assert_eq!(writer.bytes, expected);
            assert!(writer.delivered.is_empty());
            assert!(emit_json_to(&invocation.terminal(), &(), &mut writer).is_err());
            assert_eq!(writer.bytes, expected);
            assert!(writer.delivered.is_empty());
        }
    }

    #[test]
    fn error_handling_json_prepublication_cancellation_still_allows_terminal_report() {
        let invocation = invocation();
        invocation.cancellation.cancel();
        let mut bytes = Vec::new();
        assert!(emit_json_to(&invocation, &(), &mut bytes).is_err());
        assert!(bytes.is_empty());
        let envelope = output::envelope::Envelope::<()>::error(
            Some(Command::Build),
            CliError::new(Kind::Io, "cancelled").output_error(),
        );
        emit_json_to(&invocation.terminal(), &envelope, &mut bytes).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["schema"], "packetcraftr.output/v1");
        assert_eq!(document["status"], "error");
        assert_eq!(document["command"], "build");
        assert_eq!(document["error"]["message"], "cancelled");
        assert_eq!(document["error"]["kind"], "io");
        assert_eq!(bytes.last(), Some(&b'\n'));
    }

    #[test]
    fn json_budget_accepts_complete_output_and_distinguishes_serialization_failures() {
        let value = serde_json::json!({"text": "é\n", "values": [1, true, null]});
        let compact = serde_json::to_vec(&value).unwrap();
        let mut pretty = Vec::new();
        emit_json_to(&invocation(), &value, &mut pretty).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&pretty).unwrap(),
            value
        );
        for (measured, length) in [
            (bounded_json_len(&value, compact.len()), compact.len()),
            (
                bounded_pretty_json_len(&value, pretty.len() - 1),
                pretty.len() - 1,
            ),
        ] {
            assert_eq!(measured.unwrap(), length);
        }
        assert!(matches!(
            bounded_json_len(&value, compact.len() - 1),
            Err(BoundedJsonError::Limit)
        ));
        assert!(matches!(
            bounded_pretty_json_len(&value, pretty.len() - 2),
            Err(BoundedJsonError::Limit)
        ));
        assert!(matches!(
            bounded_json_len(&InvalidValue(0), 1024),
            Err(BoundedJsonError::Serialize(_))
        ));
        assert!(matches!(
            bounded_pretty_json_len(&InvalidValue(1024), 0),
            Err(BoundedJsonError::Limit)
        ));
    }
}
