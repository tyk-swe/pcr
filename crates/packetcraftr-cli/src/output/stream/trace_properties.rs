// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::fixtures::Buffer;
use super::*;
use proptest::prelude::*;

#[derive(Serialize)]
struct Data {
    value: u8,
}
impl StreamRecord for Data {
    fn event_name(&self) -> &'static str {
        "frame"
    }
}

fn fixture_error() -> Error {
    Error::new(
        Classification::new("io.fixture", Kind::Io, None),
        "fixture".to_owned(),
        Vec::new(),
    )
}

proptest! {
    #[test]
    fn complete_invocation_traces_have_one_terminal_and_no_post_terminal_data(
        actions in proptest::collection::vec(0u8..4, 0..128),
        command in 0..Command::ALL.len(),
    ) {
        let command = Command::ALL[command];
        let buffer = Buffer::default();
        let stream = StreamEncoder::new(command, buffer.clone());
        let mut terminal = false;
        let mut count = 0;
        for action in actions {
            let result = match action {
                0 | 1 => stream.emit_data(Data { value: action }, Vec::new()),
                2 => stream.complete((), Vec::new()),
                _ => stream.emit_error(fixture_error()),
            };
            if terminal {
                prop_assert!(matches!(result, Err(EncodeError::Terminal)));
            } else {
                prop_assert!(result.is_ok());
                count += 1;
                terminal = action >= 2;
            }
        }
        if !terminal {
            stream.complete((), Vec::new()).unwrap();
            count += 1;
        }
        let bytes = buffer.0.lock().unwrap();
        prop_assert_eq!(bytes.last(), Some(&b'\n'));
        // Physical NDJSON framing: one complete JSON value per line. A
        // streaming deserializer would also accept concatenated values or a
        // record spread across lines, so parse line-wise instead.
        let text = std::str::from_utf8(&bytes).unwrap();
        let records: Vec<serde_json::Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        prop_assert_eq!(records.len(), count);
        for (sequence, record) in records.iter().enumerate() {
            prop_assert_eq!(record["sequence"].as_u64(), Some(sequence as u64));
            prop_assert_eq!(&record["schema"], "packetcraftr.output/v5");
            prop_assert_eq!(&record["command"], command.as_str());
            let terminal = matches!(record["event"].as_str(), Some("complete" | "error"));
            prop_assert_eq!(terminal, sequence + 1 == records.len());
        }
    }
}
