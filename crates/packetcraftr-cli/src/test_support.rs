// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::Value;

/// A writer the test can still read after handing it to an encoder.
#[derive(Clone, Default)]
pub(crate) struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.0.lock().expect("shared buffer lock").clone()
    }

    pub(crate) fn records(&self) -> Vec<Value> {
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

pub(crate) fn parse_ndjson(bytes: &[u8]) -> Vec<Value> {
    std::str::from_utf8(bytes)
        .expect("NDJSON output must be UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("each NDJSON line must be valid JSON"))
        .collect()
}

pub(crate) fn assert_contiguous(records: &[Value]) {
    for (expected, record) in records.iter().enumerate() {
        assert_eq!(
            record["sequence"].as_u64(),
            u64::try_from(expected).ok(),
            "record {expected} has the wrong stream sequence"
        );
    }
}

pub(crate) fn assert_single_complete(records: &[Value]) {
    assert_eq!(
        records
            .iter()
            .filter(|record| record["event"] == "complete")
            .count(),
        1,
        "stream must contain exactly one complete event"
    );
}

pub(crate) fn output_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../schemas/packetcraftr.output.v2.schema.json"
        ))
        .expect("published output schema must be JSON")
    })
}

pub(crate) fn schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        jsonschema::validator_for(output_schema()).expect("published output schema must compile")
    })
}

/// Arbitrary data for stream state and I/O failure tests.
#[derive(serde::Serialize)]
#[serde(transparent)]
pub(crate) struct TestRecord<T>(pub(crate) T);

impl<T: serde::Serialize> packetcraftr_cli::output::stream::StreamRecord for TestRecord<T> {
    fn event_name(&self) -> &'static str {
        "frame"
    }
}
