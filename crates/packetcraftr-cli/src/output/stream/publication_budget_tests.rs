// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::test_support::{Buffer, Data};
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::Instant;

struct SpendDuringSerialization(Arc<AtomicBool>);
impl Serialize for SpendDuringSerialization {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.store(true, Ordering::Release);
        serializer.serialize_unit()
    }
}
impl StreamRecord for SpendDuringSerialization {
    fn event_name(&self) -> &'static str {
        "frame"
    }
}

#[test]
fn serialization_that_spends_the_budget_is_not_published_and_can_report_an_error() {
    let spent = Arc::new(AtomicBool::new(false));
    let observed = spent.clone();
    let now = Instant::now();
    let deadline = Deadline::with_time_source(Duration::from_secs(1), move || {
        if observed.load(Ordering::Acquire) {
            now + Duration::from_secs(2)
        } else {
            now
        }
    });
    let buffer = Buffer::default();
    let owner = StreamEncoder::new(Command::Read, buffer.clone());
    let publisher = owner.clone().with_deadline(Arc::new(deadline));
    let error = publisher
        .emit_data(SpendDuringSerialization(spent), Vec::new())
        .unwrap_err();
    assert!(matches!(
        error,
        EncodeError::Deadline {
            phase: "serialization",
            ..
        }
    ));
    assert!(buffer.0.lock().unwrap().is_empty());
    owner
        .emit_error(Error::new(
            error.classification(),
            error.to_string(),
            Vec::new(),
        ))
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(&buffer.0.lock().unwrap()).unwrap();
    assert_eq!(record["sequence"], 0);
    assert_eq!(record["event"], "error");
    assert!(!owner.is_complete());
}

#[test]
fn an_operation_deadline_bounds_waiting_for_the_encoder_lock() {
    let owner = StreamEncoder::new(Command::Read, io::sink());
    let publisher = owner
        .clone()
        .with_deadline(Arc::new(Deadline::new(Duration::from_millis(25))));
    let guard = owner.output.lock().unwrap();
    let (send, receive) = mpsc::channel();
    let worker =
        std::thread::spawn(move || send.send(publisher.emit_data(Data, Vec::new())).unwrap());
    let result = receive.recv_timeout(Duration::from_secs(2));
    drop(guard);
    worker.join().unwrap();
    assert!(matches!(
        result.unwrap(),
        Err(EncodeError::Deadline { phase: "lock", .. })
    ));
    assert!(owner.is_open());
}

/// Generous bound on the fixture's release wait so a broken test fails
/// instead of blocking the writer worker forever; far above the millisecond
/// production deadline under test.
const RELEASE_WATCHDOG: Duration = Duration::from_secs(30);

struct Blocked {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    expired: Arc<AtomicBool>,
}
impl Write for Blocked {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.entered.send(()).unwrap();
        if self.release.recv_timeout(RELEASE_WATCHDOG).is_err() {
            self.expired.store(true, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Blocked fixture release watchdog expired",
            ));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn writer_wait_uses_remaining_operation_budget_and_retains_cleanup_capacity() {
    let runtime = Runtime::new(1);
    let (entered, waiting) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let expired = Arc::new(AtomicBool::new(false));
    let owner = StreamEncoder::new_bounded(
        Command::Read,
        Blocked {
            entered,
            release: released,
            expired: expired.clone(),
        },
        &runtime,
        Duration::from_secs(30),
    )
    .unwrap();
    let now = Instant::now();
    let publisher = owner
        .clone()
        .with_deadline(Arc::new(Deadline::with_time_source(
            Duration::from_millis(25),
            move || now,
        )));
    let (send, receive) = mpsc::channel();
    let worker =
        std::thread::spawn(move || send.send(publisher.emit_data(Data, Vec::new())).unwrap());
    let entered = waiting.recv_timeout(Duration::from_secs(2));
    let result = receive.recv_timeout(Duration::from_secs(2));
    let retained = runtime.snapshot().active;
    release.send(()).unwrap();
    worker.join().unwrap();
    entered.unwrap();
    assert!(matches!(result.unwrap(), Err(EncodeError::Write { .. })));
    assert_eq!(
        retained, 1,
        "a deadline never releases a still-blocked writer"
    );
    assert!(
        !expired.load(Ordering::Acquire),
        "the release watchdog fired; the test never released the writer"
    );
    assert!(!owner.is_open());
    assert!(!owner.is_complete());
}
