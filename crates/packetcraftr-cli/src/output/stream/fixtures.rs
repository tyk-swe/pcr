// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use super::StreamRecord;

/// Shared in-memory sink for encoder tests.
#[derive(Clone, Default)]
pub(super) struct Buffer(pub(super) Arc<Mutex<Vec<u8>>>);
impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Minimal nonterminal record.
#[derive(Serialize)]
pub(super) struct Data;
impl StreamRecord for Data {
    fn event_name(&self) -> &'static str {
        "frame"
    }
}
