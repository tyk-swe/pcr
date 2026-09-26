// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Test helpers shared by the crate's unit tests and, through the
//! `test-support` feature, its integration tests. Not a supported API.

use std::io::{self, Write};
use std::sync::{Arc, Mutex, OnceLock};

use crate::output::{contract::Command, stream::StreamEncoder};
use serde_json::Value;

/// A writer the test can still read after handing it to an encoder.
#[derive(Clone, Default)]
pub struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    pub fn bytes(&self) -> Vec<u8> {
        self.0.lock().expect("shared buffer lock").clone()
    }

    pub fn records(&self) -> Vec<Value> {
        parse_ndjson(&self.bytes())
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("shared buffer lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An NDJSON encoder writing into a buffer the caller can read back.
pub fn stream(command: Command) -> (StreamEncoder, SharedBuffer) {
    let buffer = SharedBuffer::default();
    (StreamEncoder::new(command, buffer.clone()), buffer)
}

pub fn parse_ndjson(bytes: &[u8]) -> Vec<Value> {
    let text = std::str::from_utf8(bytes).expect("NDJSON output must be UTF-8");
    assert!(
        text.is_empty() || text.ends_with('\n'),
        "nonempty NDJSON output ends every record with a newline"
    );
    text.lines()
        .map(|line| {
            serde_json::from_str(line)
                .expect("each NDJSON line holds exactly one complete JSON value")
        })
        .collect()
}

pub fn assert_contiguous(records: &[Value]) {
    for (expected, record) in records.iter().enumerate() {
        assert_eq!(
            record["sequence"].as_u64(),
            u64::try_from(expected).ok(),
            "record {expected} has the wrong stream sequence"
        );
    }
}

pub fn output_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../schemas/packetcraftr.output.v6.schema.json"
        ))
        .expect("published output schema must be JSON")
    })
}

/// Integration tests build their own validator over [`output_schema`], because
/// `jsonschema` is only a dev-dependency.
#[cfg(test)]
pub(crate) fn schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        jsonschema::validator_for(output_schema()).expect("published output schema must compile")
    })
}

/// Arbitrary data for stream state and I/O failure tests.
#[derive(serde::Serialize)]
#[serde(transparent)]
pub struct TestRecord<T>(pub T);

impl<T: serde::Serialize> crate::output::stream::StreamRecord for TestRecord<T> {
    fn event_name(&self) -> &'static str {
        "frame"
    }
}
