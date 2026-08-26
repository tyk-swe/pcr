// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

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

pub(crate) fn schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../schemas/packetcraftr.output.v1.schema.json"
        ))
        .expect("published output schema must be JSON");
        jsonschema::validator_for(&schema).expect("published output schema must compile")
    })
}
