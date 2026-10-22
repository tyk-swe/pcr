// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Serializing one NDJSON record under its byte ceiling, optionally metering
//! the bytes its application result occupies.

use std::cell::Cell;
use std::io::{self, Write};

use serde::Serialize;

use super::EncodeError;

#[derive(Debug)]
pub(crate) enum MeteredError {
    Limit,
    Encode(EncodeError),
    Serialize(serde_json::Error),
}

pub(super) struct ResultMeter {
    pub(super) limit: usize,
    pub(super) active: Cell<bool>,
    pub(super) bytes: Cell<usize>,
    pub(super) exceeded: Cell<bool>,
    pub(super) value_failed: Cell<bool>,
}

impl ResultMeter {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            active: Cell::new(false),
            bytes: Cell::new(0),
            exceeded: Cell::new(false),
            value_failed: Cell::new(false),
        }
    }
}

pub(super) struct Counted<'a, T> {
    pub(super) value: T,
    pub(super) meter: Option<&'a ResultMeter>,
}
impl<T: Serialize> Serialize for Counted<'_, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some(meter) = self.meter {
            meter.active.set(true);
        }
        let result = self.value.serialize(serializer);
        if let Some(meter) = self.meter {
            meter.active.set(false);
            meter.value_failed.set(result.is_err());
        }
        result
    }
}

/// Maximum encoded NDJSON record bytes, including its newline.
pub const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn serialize_line(
    record: &impl Serialize,
    sequence: u64,
) -> Result<Vec<u8>, EncodeError> {
    serialize_line_with_limit(record, sequence, MAX_RECORD_BYTES)
}

pub(super) fn serialize_line_with_limit(
    record: &impl Serialize,
    sequence: u64,
    limit: usize,
) -> Result<Vec<u8>, EncodeError> {
    serialize_line_metered(record, sequence, limit, None)
}

pub(super) fn serialize_line_metered(
    record: &impl Serialize,
    sequence: u64,
    limit: usize,
    meter: Option<&ResultMeter>,
) -> Result<Vec<u8>, EncodeError> {
    struct BoundedLine<'a> {
        meter: Option<&'a ResultMeter>,
        bytes: Vec<u8>,
        limit: usize,
        exceeded: bool,
    }
    impl Write for BoundedLine<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(meter) = self.meter.filter(|meter| meter.active.get()) {
                if bytes.len() > meter.limit.saturating_sub(meter.bytes.get()) {
                    meter.exceeded.set(true);
                    return Err(io::Error::other(
                        "application JSON value byte ceiling exceeded",
                    ));
                }
                meter.bytes.set(meter.bytes.get() + bytes.len());
            }
            if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
                self.exceeded = true;
                return Err(io::Error::other("NDJSON record byte ceiling exceeded"));
            }
            let required = self.bytes.len() + bytes.len();
            if required > self.bytes.capacity() {
                let capacity = required
                    .max(self.bytes.capacity().saturating_mul(2))
                    .min(self.limit);
                self.bytes
                    .try_reserve_exact(capacity - self.bytes.len())
                    .map_err(io::Error::other)?;
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut line = BoundedLine {
        meter,
        bytes: Vec::new(),
        limit,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut line, record);
    if line.exceeded || limit == 0 {
        return Err(EncodeError::RecordLimit { sequence, limit });
    }
    result.map_err(|source| EncodeError::Serialize { sequence, source })?;
    if let Err(source) = line.write_all(b"\n") {
        if line.exceeded {
            return Err(EncodeError::RecordLimit { sequence, limit });
        }
        return Err(EncodeError::Serialize {
            sequence,
            source: serde_json::Error::io(source),
        });
    }
    Ok(line.bytes)
}
