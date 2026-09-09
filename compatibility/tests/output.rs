// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![forbid(unsafe_code)]

use packetcraftr_cli::output::{
    contract::Command,
    stream::{StreamEncoder, StreamRecord},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

// Independent consumer shape; no use of the producer's envelope types/schema.
#[derive(Deserialize)]
struct Record {
    schema: String,
    command: String,
    sequence: u64,
    event: String,
    status: String,
    result: serde_json::Value,
}
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);
impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Serialize)]
struct Frame {
    number: u64,
}
impl StreamRecord for Frame {
    fn event_name(&self) -> &'static str {
        "frame"
    }
}

#[test]
fn independent_consumer_requires_contiguous_sequence_and_acknowledged_completion() {
    let buffer = Buffer::default();
    let stream = StreamEncoder::new(Command::Read, buffer.clone());
    stream.emit_data(Frame { number: 99 }, Vec::new()).unwrap();
    stream
        .complete(serde_json::json!({"frames":1}), Vec::new())
        .unwrap();
    let bytes = buffer.0.lock().unwrap();
    let records = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Record>()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(records.len(), 2);
    for (sequence, record) in records.iter().enumerate() {
        assert_eq!(record.schema, "packetcraftr.output/v3");
        assert_eq!(record.command, "read");
        assert_eq!(record.status, "success");
        assert_eq!(record.sequence, sequence as u64);
    }
    assert_eq!(records[0].event, "frame");
    assert_eq!(records[0].result["number"], 99);
    assert_eq!(records[1].event, "complete");
    assert_eq!(records[1].result["frames"], 1);
    assert!(stream.emit_data(Frame { number: 100 }, Vec::new()).is_err());
}
