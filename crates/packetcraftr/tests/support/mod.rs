// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Shared by several test binaries; each one uses a different subset.
#![allow(dead_code)]
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io::{self, Write};
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::Value;

/// A writer the test can still read after handing it to an encoder.
#[derive(Clone, Default)]
pub(crate) struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl SharedWriter {
    pub(crate) fn records(&self) -> Vec<Value> {
        std::str::from_utf8(&self.0.lock().expect("shared writer lock"))
            .expect("encoded output must be UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("each record must be JSON"))
            .collect()
    }
}

impl Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("shared writer lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The published output schema, parsed once per test binary.
pub(crate) fn output_schema() -> &'static Value {
    static SCHEMA: OnceLock<Value> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../../../schemas/packetcraftr.output.v2.schema.json"
        ))
        .expect("published output schema must be JSON")
    })
}

/// A compiled validator for the published output schema.
pub(crate) fn output_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        jsonschema::validator_for(output_schema()).expect("published output schema must compile")
    })
}

/// A compiled validator for the published packet-document schema.
pub(crate) fn packet_schema_validator() -> &'static jsonschema::Validator {
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    VALIDATOR.get_or_init(|| {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../schemas/packetcraftr.packet.v2.schema.json"
        ))
        .expect("published packet schema must be JSON");
        jsonschema::validator_for(&schema).expect("published packet schema must compile")
    })
}
