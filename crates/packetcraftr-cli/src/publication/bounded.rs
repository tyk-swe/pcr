// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};

use serde::Serialize;

use super::json::serialization_error;
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

impl From<serde_json::Error> for BoundedJsonError {
    fn from(source: serde_json::Error) -> Self {
        if source.is_io() {
            Self::Limit
        } else {
            Self::Serialize(source)
        }
    }
}

/// Passes at most `remaining` bytes to a sink that cannot fail, so the only
/// I/O error it ever reports is the limit.
pub(crate) struct Limited<W> {
    sink: W,
    remaining: usize,
}

impl Limited<io::Sink> {
    fn counter(limit: usize) -> Self {
        Self {
            sink: io::sink(),
            remaining: limit,
        }
    }
}

impl Limited<Vec<u8>> {
    pub(crate) fn buffer(limit: usize) -> Self {
        Self {
            sink: Vec::new(),
            remaining: limit,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), BoundedJsonError> {
        self.write_all(bytes).map_err(|_| BoundedJsonError::Limit)
    }

    pub(crate) fn push_json(&mut self, value: &impl Serialize) -> Result<(), BoundedJsonError> {
        Ok(serde_json::to_writer(self, value)?)
    }

    /// The buffered bytes and what is left of the limit.
    pub(crate) fn finish(self) -> (Vec<u8>, usize) {
        (self.sink, self.remaining)
    }
}

impl<W: Write> Write for Limited<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("output limit"))?;
        self.sink.write_all(bytes)?;
        self.remaining = remaining;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn bounded_json_len(
    value: &impl Serialize,
    limit: usize,
    formatter: impl serde_json::ser::Formatter,
) -> Result<usize, BoundedJsonError> {
    let mut counter = Limited::counter(limit);
    value.serialize(&mut serde_json::Serializer::with_formatter(
        &mut counter,
        formatter,
    ))?;
    Ok(limit - counter.remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Unserializable;

    impl Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("no spelling"))
        }
    }

    #[test]
    fn a_buffer_accepts_exactly_its_limit_and_keeps_what_fit() {
        let mut line = Limited::buffer(6);
        line.push(b"ab").unwrap();
        line.push_json(&"cd").unwrap();
        assert!(matches!(line.push(b"e"), Err(BoundedJsonError::Limit)));
        assert!(matches!(line.push_json(&1), Err(BoundedJsonError::Limit)));
        assert_eq!(line.finish(), (b"ab\"cd\"".to_vec(), 0));
    }

    #[test]
    fn a_serializer_failure_is_not_reported_as_the_limit() {
        let mut line = Limited::buffer(0);
        assert!(matches!(
            line.push_json(&Unserializable),
            Err(BoundedJsonError::Serialize(_))
        ));
        assert!(matches!(
            bounded_json_len(&Unserializable, 0, serde_json::ser::CompactFormatter),
            Err(BoundedJsonError::Serialize(_))
        ));
    }

    #[test]
    fn measured_length_matches_the_encoding_and_stops_at_the_limit() {
        let value = serde_json::json!({"key": [1, 2, 3]});
        let length = serde_json::to_vec(&value).unwrap().len();
        let measure = |limit| bounded_json_len(&value, limit, serde_json::ser::CompactFormatter);
        assert_eq!(measure(length).unwrap(), length);
        assert!(matches!(measure(length - 1), Err(BoundedJsonError::Limit)));
    }
}
