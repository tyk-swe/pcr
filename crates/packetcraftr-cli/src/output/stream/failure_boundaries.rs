// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::test_support::Data;
use super::*;

#[test]
fn serialized_limit_counts_escaping_and_newline_at_exact_boundaries() {
    let value = "\n\"";
    let expected = serde_json::to_vec(&value).unwrap().len() + 1;
    for limit in [expected - 1, expected, expected + 1] {
        let result = serialize_line_with_limit(&value, 7, limit);
        if limit < expected {
            assert!(matches!(
                result,
                Err(EncodeError::RecordLimit { sequence: 7, .. })
            ));
        } else {
            assert_eq!(result.unwrap().len(), expected);
        }
    }
}

struct FailAfter {
    remaining: usize,
    fail_flush: bool,
}
impl Write for FailAfter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("injected byte failure"));
        }
        let count = self.remaining.min(bytes.len());
        self.remaining -= count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.fail_flush {
            Err(io::Error::other("injected flush failure"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn every_partial_data_or_terminal_write_and_flush_failure_is_final() {
    for terminal in [false, true] {
        let envelope = Envelope::record(
            Command::Read,
            0,
            if terminal { "complete" } else { "frame" },
            (),
            Vec::new(),
        );
        let length = serialize_line(&envelope, 0).unwrap().len();
        for remaining in 0..=length {
            let stream = StreamEncoder::new(
                Command::Read,
                FailAfter {
                    remaining,
                    fail_flush: remaining == length,
                },
            );
            let result = if terminal {
                stream.complete((), Vec::new())
            } else {
                stream.emit_data(Data, Vec::new())
            };
            assert!(matches!(
                result,
                Err(EncodeError::Write { sequence: 0, .. })
            ));
            assert!(!stream.is_open());
            assert!(!stream.is_complete());
            assert!(!stream.is_terminal());
            assert!(matches!(
                stream.complete((), Vec::new()),
                Err(EncodeError::Failed)
            ));
            assert!(matches!(
                stream.emit_data(Data, Vec::new()),
                Err(EncodeError::Failed)
            ));
        }
    }
}
