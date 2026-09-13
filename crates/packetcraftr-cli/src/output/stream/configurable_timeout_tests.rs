// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::fixtures::Data;
use super::*;
use std::sync::mpsc;

struct WaitingWriter(mpsc::Sender<()>, mpsc::Receiver<()>);
impl Write for WaitingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.send(()).unwrap();
        self.1
            .recv_timeout(Duration::from_secs(3))
            .map_err(io::Error::other)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn extended_wait_accepts_a_slow_writer_and_cleanup_uses_its_own_ceiling() {
    let runtime = Runtime::new(1);
    let (entered, waiting) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let stream = StreamEncoder::new_bounded(
        Command::Read,
        WaitingWriter(entered, released),
        &runtime,
        Duration::from_secs(2),
    )
    .unwrap()
    .with_terminal_error_timeout(Duration::from_millis(10));
    let publisher = stream.clone();
    let worker = std::thread::spawn(move || publisher.emit_data(Data, Vec::new()));
    waiting.recv_timeout(Duration::from_secs(2)).unwrap();
    // Coordinate release rather than asserting wall-time performance.
    release.send(()).unwrap();
    worker.join().unwrap().unwrap();
    let result = stream.emit_error(Error::new(
        Classification::new("io.fixture", Kind::Io, None),
        "stop",
        Vec::new(),
    ));
    assert!(matches!(
        result,
        Err(EncodeError::Write { sequence: 1, .. })
    ));
    assert_eq!(runtime.snapshot().timed_out_retaining_capacity, 1);
    release.send(()).unwrap();
    assert!(!stream.is_complete());
}
