// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::Kind;

use std::io::{self, Write};

use packetcraftr_core as core;

use packetcraftr_cli::output;
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
    match serde_json::to_writer(&mut counter, value) {
        Ok(()) => Ok(limit - counter.remaining),
        Err(_) if counter.exceeded => Err(BoundedJsonError::Limit),
        Err(source) => Err(BoundedJsonError::Serialize(source)),
    }
}

pub(crate) fn emit_json(value: &impl Serialize) -> Result<(), CliError> {
    crate::invocation::check()?;
    let stdout = io::stdout().lock();
    let mut writer = io::BufWriter::with_capacity(64 * 1024, stdout);
    serde_json::to_writer_pretty(&mut writer, value).map_err(json_error)?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|source| CliError::new(Kind::Io, format!("write stdout failed: {source}")))
}

fn json_error(source: serde_json::Error) -> CliError {
    if source.is_io() {
        CliError::new(Kind::Io, format!("write stdout failed: {source}"))
    } else {
        CliError::new(Kind::Internal, format!("serialize output failed: {source}"))
    }
}

pub(crate) fn emit_aggregate<T: Serialize>(
    command: output::contract::Command,
    result: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
) -> Result<(), CliError> {
    crate::cancellation::check()?;
    emit_json(&crate::resources::decorate(
        output::envelope::Envelope::success(command, result, diagnostics),
    ))
}

pub(crate) fn emit_aggregate_with_stats<T: Serialize>(
    command: output::contract::Command,
    result: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: packetcraftr::Stats,
) -> Result<(), CliError> {
    crate::cancellation::check()?;
    emit_json(&crate::resources::decorate(
        output::envelope::Envelope::success(command, result, diagnostics).with_stats(stats),
    ))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use serde::Serialize;
    use serde::ser::{Error as _, SerializeSeq};

    use super::{BoundedJsonError, bounded_json_len};

    struct Instrumented<'a> {
        second: &'a Cell<bool>,
    }

    impl Serialize for Instrumented<'_> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(2))?;
            sequence.serialize_element(&0u8)?;
            self.second.set(true);
            sequence.serialize_element(&1u8)?;
            sequence.end()
        }
    }

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

    #[test]
    fn bounded_json_len_counts_exact_compact_bytes() {
        let cases = [
            serde_json::json!(null),
            serde_json::json!(""),
            serde_json::json!("multibyte é\n\"quoted\"\\\u{0007}"),
            serde_json::json!({"nested": [1, "two", {"three": [null, true]}], "empty": []}),
        ];
        for value in cases {
            let n = serde_json::to_vec(&value).unwrap().len();
            assert_eq!(bounded_json_len(&value, n).unwrap(), n, "{value}");
            assert!(
                matches!(
                    bounded_json_len(&value, n - 1),
                    Err(BoundedJsonError::Limit)
                ),
                "{value}"
            );
            assert!(
                matches!(bounded_json_len(&value, 0), Err(BoundedJsonError::Limit)),
                "{value}"
            );
            assert_eq!(bounded_json_len(&value, usize::MAX).unwrap(), n, "{value}");
        }
    }

    #[test]
    fn bounded_json_len_stops_serializing_at_the_limit() {
        let second = Cell::new(false);
        let value = Instrumented { second: &second };
        assert!(matches!(
            bounded_json_len(&value, 1),
            Err(BoundedJsonError::Limit)
        ));
        assert!(!second.get());
    }

    #[test]
    fn bounded_json_len_preserves_serialization_failures() {
        let error = bounded_json_len(&FailingSerialization, usize::MAX).unwrap_err();
        let BoundedJsonError::Serialize(source) = error else {
            panic!("expected serialization failure, got {error:?}");
        };
        assert_eq!(source.to_string(), "fixture serialization failure");
    }
}
