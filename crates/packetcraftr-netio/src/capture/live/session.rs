// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned capture-session lifecycle and worker join semantics.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use packetcraftr_core::budget::Deadline;

use crate::deadline::{POLL_INTERVAL, remaining_before};
use packetcraftr_core::error::Source;

use crate::workers::{Permit, Task, Waited};

use crate::{
    Error,
    capture::{Captured, Limits, MAX_TIMEOUT, Metadata, Session, Statistics},
    workers::reaper::{ReaperClient, ReaperStartError, shared_reaper},
};

use super::{
    CaptureInterrupt, NativeCaptureParts,
    queue::CaptureQueue,
    worker::{capture_worker, transfer_capture_worker},
};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// The instant a capture wait ends: `None` once the caller's deadline is
/// spent, so the wait takes only what is already there. A remainder above
/// the public maximum is refused rather than clipped.
fn capture_deadline(deadline: &Deadline) -> Result<Option<Instant>, Error> {
    deadline.check_cancelled()?;
    let Some(timeout) = deadline
        .remaining()
        .ok()
        .filter(|remaining| !remaining.is_zero())
    else {
        return Ok(None);
    };
    if timeout > MAX_TIMEOUT {
        return Err(Error::InvalidCaptureTimeout {
            timeout,
            maximum: MAX_TIMEOUT,
        });
    }
    Instant::now()
        .checked_add(timeout)
        .map(Some)
        .ok_or(Error::InvalidCaptureTimeout {
            timeout,
            maximum: MAX_TIMEOUT,
        })
}

pub(crate) struct NativeCaptureSession {
    metadata: Metadata,
    shared: Arc<CaptureQueue>,
    stop: Arc<AtomicBool>,
    /// Pooled worker, its permit, and interrupt handle share one lifetime.
    /// The permit precedes worker creation; the interrupt outlives the
    /// worker, and the session's clone of the permit outlives the interrupt.
    running: Option<RunningCapture>,
    reaper: ReaperClient,
    shutdown_timeout: Duration,
    shutdown: Shutdown,
}

struct RunningCapture {
    worker: Task<()>,
    interrupt: Arc<dyn CaptureInterrupt>,
    permit: Permit,
}

enum Shutdown {
    NotAttempted,
    /// Shutdown ran but its finite deadline expired, so the worker is still
    /// owned and an explicit retry is still allowed.
    Incomplete,
    Finished(Result<(), Error>),
}

impl NativeCaptureSession {
    pub(crate) fn spawn(parts: NativeCaptureParts, limits: Limits) -> Result<Self, Error> {
        Self::spawn_with_shutdown_timeout(parts, limits, SHUTDOWN_TIMEOUT)
    }

    fn spawn_with_shutdown_timeout(
        parts: NativeCaptureParts,
        limits: Limits,
        shutdown_timeout: Duration,
    ) -> Result<Self, Error> {
        Self::spawn_with_reaper(parts, limits, shutdown_timeout, shared_reaper())
    }

    fn spawn_with_reaper(
        parts: NativeCaptureParts,
        limits: Limits,
        shutdown_timeout: Duration,
        reaper: Result<ReaperClient, ReaperStartError>,
    ) -> Result<Self, Error> {
        // Both fallible cleanup-service steps happen before the source worker
        // is created, so failure cannot leave an unmanaged native worker.
        let reaper = reaper.map_err(|error| Error::Capture {
            message: "native capture cleanup is unavailable".to_owned(),
            source: Some(Source::new(error)),
        })?;
        let permit = reaper.reserve().map_err(|error| Error::Capture {
            message: format!(
                "native capture cleanup capacity {} is exhausted",
                error.capacity
            ),
            source: Some(Source::new(error)),
        })?;
        let NativeCaptureParts {
            source,
            interrupt,
            metadata,
        } = parts;
        let shared = Arc::new(CaptureQueue::new(limits));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_shared = Arc::clone(&shared);
        let worker_stop = Arc::clone(&stop);
        let interface_index = metadata.interface.index;
        let link_type = metadata.link_type;
        let mut source = source;
        // The source closes on the pooled thread, before the pool releases
        // the worker's clone of the permit.
        let worker = permit
            .spawn(move || {
                let terminal_shared = Arc::clone(&worker_shared);
                let result = catch_unwind(AssertUnwindSafe(|| {
                    capture_worker(
                        source.as_mut(),
                        worker_shared,
                        worker_stop,
                        interface_index,
                        link_type,
                    )
                }))
                .unwrap_or_else(|_| {
                    Err(Error::Capture {
                        message: "native capture worker panicked".to_owned(),
                        source: None,
                    })
                });
                if let Err(error) = result {
                    terminal_shared.set_error(error);
                }
            })
            .map_err(|error| Error::Capture {
                message: "could not start the owned capture worker".to_owned(),
                source: Some(Source::new(error)),
            })?;
        Ok(Self {
            metadata,
            shared,
            stop,
            running: Some(RunningCapture {
                worker,
                interrupt,
                permit,
            }),
            reaper,
            shutdown_timeout,
            shutdown: Shutdown::NotAttempted,
        })
    }
}

impl Session for NativeCaptureSession {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, caller: &Deadline) -> Result<(), Error> {
        let deadline = capture_deadline(caller)?;
        let expired = || Error::CaptureReadiness {
            message: "capture readiness deadline expired".to_owned(),
        };
        let mut state = self.shared.lock();
        while !state.ready && !state.closed && state.error.is_none() {
            let Some(remaining) = deadline.and_then(remaining_before) else {
                return Err(expired());
            };
            // Wait in slices: the queue signals readiness, not cancellation.
            let (next, _) = self
                .shared
                .wait_timeout(state, remaining.min(POLL_INTERVAL));
            state = next;
            if !state.ready && !state.closed && state.error.is_none() {
                caller.check_cancelled()?;
            }
        }
        if let Some(error) = state
            .error
            .clone()
            .filter(|_| !state.ready || state.queue.is_empty())
        {
            state.error_observed = true;
            Err(error)
        } else if state.ready {
            Ok(())
        } else {
            Err(Error::CaptureReadiness {
                message: "native capture worker closed before reporting readiness".to_owned(),
            })
        }
    }

    fn next_captured_frame(&mut self, caller: &Deadline) -> Result<Option<Captured>, Error> {
        let deadline = capture_deadline(caller)?;
        let mut state = self.shared.lock();
        loop {
            if let Some(captured) = state.queue.front() {
                let queued_bytes = state
                    .queued_bytes
                    .checked_sub(captured.frame.bytes().len())
                    .ok_or_else(|| Error::InvalidCaptureStatistics {
                        message: "native capture queue byte accounting underflowed".to_owned(),
                    })?;
                state.queued_bytes = queued_bytes;
                return Ok(state.queue.pop_front());
            }
            if let Some(error) = state.error.clone() {
                state.error_observed = true;
                return Err(error);
            }
            if state.closed {
                return Ok(None);
            }
            let Some(remaining) = deadline.and_then(remaining_before) else {
                return Ok(None);
            };
            // Wait in slices: the queue signals records, not cancellation.
            let (next_state, _) = self
                .shared
                .wait_timeout(state, remaining.min(POLL_INTERVAL));
            state = next_state;
            if state.queue.is_empty() && state.error.is_none() {
                caller.check_cancelled()?;
            }
        }
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        self.shutdown_with_timeout(self.shutdown_timeout)
    }

    fn statistics(&self) -> Statistics {
        self.shared.lock().statistics
    }
}

impl NativeCaptureSession {
    fn shutdown_with_timeout(&mut self, timeout: Duration) -> Result<(), Error> {
        if let Shutdown::Finished(result) = &self.shutdown {
            return result.clone();
        }
        self.shutdown = Shutdown::Incomplete;
        self.stop.store(true, Ordering::Release);

        let stopped = match self.running.take() {
            None => Ok(()),
            Some(RunningCapture {
                worker,
                interrupt,
                permit,
            }) => {
                let interrupt_result = catch_unwind(AssertUnwindSafe(|| interrupt.interrupt()))
                    .map_err(|_| Error::Capture {
                        message: "native capture interrupt panicked during shutdown".to_owned(),
                        source: None,
                    });
                match worker.wait(&Deadline::new(timeout)) {
                    Waited::Pending(worker) => {
                        permit.retention_marker().mark_retained();
                        // The deadline expired with the worker still running,
                        // so this session keeps the complete bundle and an
                        // explicit retry stays possible.
                        self.running = Some(RunningCapture {
                            worker,
                            interrupt,
                            permit,
                        });
                        return Err(Error::DeadlineExceeded {
                            operation: "shutting down native capture",
                        });
                    }
                    // The worker is finished, so the native interrupt and the
                    // cleanup permit are released here and only here.
                    Waited::Finished(join_result) => {
                        // A user-supplied interrupt may own resources with a
                        // destructor. Release it before returning admission.
                        drop(interrupt);
                        drop(permit);
                        join_result
                            .map_err(|_| Error::Capture {
                                message: "native capture worker panicked during shutdown"
                                    .to_owned(),
                                source: None,
                            })
                            .and(interrupt_result)
                    }
                }
            }
        };

        let result = stopped.and_then(|()| {
            let mut state = self.shared.lock();
            state.closed = true;
            if state.error_observed {
                Ok(())
            } else if let Some(error) = state.error.clone() {
                state.error_observed = true;
                Err(error)
            } else {
                Ok(())
            }
        });
        self.shutdown = Shutdown::Finished(result.clone());
        result
    }
}

impl Drop for NativeCaptureSession {
    fn drop(&mut self) {
        if matches!(self.shutdown, Shutdown::NotAttempted) {
            let _ = catch_unwind(AssertUnwindSafe(|| self.shutdown()));
        }
        if let Some(RunningCapture {
            worker,
            interrupt,
            permit,
        }) = self.running.take()
        {
            // Explicit shutdown has already used its finite deadline. A
            // running worker is transferred, together with its interrupt and
            // its cleanup permit, to an owner that can wait without blocking
            // this Drop path.
            transfer_capture_worker(
                worker,
                Arc::clone(&self.stop),
                interrupt,
                permit,
                &self.reaper,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
    };
    use std::thread;
    use std::time::SystemTime;

    use bytes::Bytes;
    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::capture::live::{
        NativeCaptureEvent, NativeCaptureSource, NativeCaptureStatistics, NativeCapturedPacket,
    };
    use crate::error::test_support::assert_same_failure;
    use crate::{
        capture::{Limits, Metadata},
        interface::Id as InterfaceId,
        workers::reaper::test_support::{client_with_receiver, retained_tasks, start_with},
    };

    fn metadata(name: &str, index: u32) -> Metadata {
        Metadata {
            interface: InterfaceId {
                name: name.to_owned(),
                index,
            },
            link_type: LinkType::ETHERNET,
            snap_length: 64,
            native: Default::default(),
        }
    }

    #[derive(Default)]
    struct FakeInterrupt {
        calls: AtomicUsize,
    }

    impl CaptureInterrupt for FakeInterrupt {
        fn interrupt(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct LifetimeInterrupt {
        dropped: Sender<()>,
    }

    impl CaptureInterrupt for LifetimeInterrupt {
        fn interrupt(&self) {}
    }

    impl Drop for LifetimeInterrupt {
        fn drop(&mut self) {
            let _ = self.dropped.send(());
        }
    }

    struct PanickingInterrupt;

    impl CaptureInterrupt for PanickingInterrupt {
        fn interrupt(&self) {
            panic!("injected capture interrupt panic");
        }
    }

    struct CountingSource {
        calls: Arc<AtomicUsize>,
    }

    impl NativeCaptureSource for CountingSource {
        fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(NativeCaptureEvent::Closed)
        }

        fn statistics(&mut self) -> Result<NativeCaptureStatistics, Error> {
            Ok(NativeCaptureStatistics::default())
        }
    }

    struct BlockingSource {
        started: Option<Sender<()>>,
        release: Receiver<()>,
        finished: Option<Sender<()>>,
    }

    impl NativeCaptureSource for BlockingSource {
        fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            self.release.recv().map_err(|_| Error::Capture {
                message: "fake capture release channel closed".to_owned(),
                source: None,
            })?;
            if let Some(finished) = self.finished.take() {
                let _ = finished.send(());
            }
            Ok(NativeCaptureEvent::Closed)
        }

        fn statistics(&mut self) -> Result<NativeCaptureStatistics, Error> {
            Ok(NativeCaptureStatistics::default())
        }
    }

    struct PanickingSource {
        started: Option<Sender<()>>,
    }

    impl NativeCaptureSource for PanickingSource {
        fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            panic!("fake capture worker panic");
        }

        fn statistics(&mut self) -> Result<NativeCaptureStatistics, Error> {
            Ok(NativeCaptureStatistics::default())
        }
    }

    struct ScriptedSource {
        events: VecDeque<Result<NativeCaptureEvent, Error>>,
        finished: Option<Sender<()>>,
    }

    impl NativeCaptureSource for ScriptedSource {
        fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
            self.events.pop_front().unwrap_or_else(|| {
                Err(Error::Capture {
                    message: "scripted source exhausted".to_owned(),
                    source: None,
                })
            })
        }

        fn statistics(&mut self) -> Result<NativeCaptureStatistics, Error> {
            Ok(NativeCaptureStatistics::default())
        }
    }

    impl Drop for ScriptedSource {
        fn drop(&mut self) {
            if let Some(finished) = self.finished.take() {
                let _ = finished.send(());
            }
        }
    }

    fn scripted_session(
        events: impl IntoIterator<Item = Result<NativeCaptureEvent, Error>>,
        interrupt: Arc<FakeInterrupt>,
    ) -> (NativeCaptureSession, Receiver<()>) {
        let (finished_sender, finished_receiver) = mpsc::channel();
        let interrupt: Arc<dyn CaptureInterrupt> = interrupt;
        let session = NativeCaptureSession::spawn(
            NativeCaptureParts {
                source: Box::new(ScriptedSource {
                    events: events.into_iter().collect(),
                    finished: Some(finished_sender),
                }),
                interrupt,
                metadata: metadata("scripted-capture", 9),
            },
            Limits::default(),
        )
        .expect("scripted capture worker should spawn");
        (session, finished_receiver)
    }

    fn wait_for_scripted_terminal_state(
        session: &NativeCaptureSession,
        finished: Receiver<()>,
        queued_frames: usize,
    ) {
        finished
            .recv_timeout(Duration::from_secs(1))
            .expect("scripted capture worker should reach its terminal state");
        let state = session.shared.lock();
        assert!(state.error.is_some());
        assert_eq!(state.queue.len(), queued_frames);
    }

    fn blocked_session(
        release: Receiver<()>,
        finished: Option<Sender<()>>,
        interrupt: Arc<FakeInterrupt>,
        shutdown_timeout: Duration,
    ) -> (NativeCaptureSession, Receiver<()>) {
        let (started_sender, started_receiver) = mpsc::channel();
        let interrupt_for_parts: Arc<dyn CaptureInterrupt> = interrupt;
        let session = NativeCaptureSession::spawn_with_shutdown_timeout(
            NativeCaptureParts {
                source: Box::new(BlockingSource {
                    started: Some(started_sender),
                    release,
                    finished,
                }),
                interrupt: interrupt_for_parts,
                metadata: metadata("fake-capture", 1),
            },
            Limits::default(),
            shutdown_timeout,
        )
        .expect("fake capture worker should spawn");
        (session, started_receiver)
    }

    fn wait_until_blocked(started: Receiver<()>) {
        started
            .recv_timeout(Duration::from_millis(100))
            .expect("fake capture worker should enter its blocking read");
    }

    #[test]
    fn shutdown_timeout_preserves_capture_ownership_for_retry() {
        let (release_sender, release_receiver) = mpsc::channel();
        let interrupt = Arc::new(FakeInterrupt::default());
        let (mut session, started_receiver) = blocked_session(
            release_receiver,
            None,
            Arc::clone(&interrupt),
            Duration::from_millis(5),
        );
        session
            .wait_ready(&Deadline::new(Duration::from_millis(100)))
            .expect("fake capture should become ready");
        wait_until_blocked(started_receiver);

        assert!(matches!(
            session.shutdown(),
            Err(Error::DeadlineExceeded {
                operation: "shutting down native capture"
            })
        ));
        assert!(session.running.is_some());
        assert_eq!(interrupt.calls.load(Ordering::SeqCst), 1);

        release_sender
            .send(())
            .expect("release fake capture worker");
        session.shutdown().expect("released worker shuts down");
        assert!(session.running.is_none());
        session
            .shutdown()
            .expect("shutdown after the worker is gone is idempotent");
        assert_eq!(interrupt.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn capture_worker_panic_is_terminal_and_cached() {
        let interrupt = Arc::new(FakeInterrupt::default());
        let interrupt_for_parts: Arc<dyn CaptureInterrupt> = interrupt.clone();
        let (started_sender, started_receiver) = mpsc::channel();
        let mut session = NativeCaptureSession::spawn_with_shutdown_timeout(
            NativeCaptureParts {
                source: Box::new(PanickingSource {
                    started: Some(started_sender),
                }),
                interrupt: interrupt_for_parts,
                metadata: metadata("fake-panic", 2),
            },
            Limits::default(),
            // The panic hook may symbolize a backtrace (RUST_BACKTRACE=1)
            // before the worker finishes, so the deadline only bounds a hang.
            Duration::from_secs(10),
        )
        .expect("fake capture worker should spawn");
        started_receiver
            .recv_timeout(Duration::from_millis(100))
            .expect("fake capture worker should reach the panic point");

        let first = session
            .shutdown()
            .expect_err("worker panic must be reported");
        let second = session
            .shutdown()
            .expect_err("cached worker panic must remain terminal");
        assert_same_failure(&first, &second);
        assert!(matches!(
            first,
            Error::Capture { ref message, .. }
                if message == "native capture worker panicked"
        ));
        assert!(session.running.is_none());
        assert_eq!(interrupt.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn queued_frame_is_delivered_before_a_later_terminal_source_error() {
        let ingress = Instant::now();
        let terminal = Error::Capture {
            message: "source failed after one frame".to_owned(),
            source: None,
        };
        let interrupt = Arc::new(FakeInterrupt::default());
        let (mut session, finished) = scripted_session(
            [
                Ok(NativeCaptureEvent::Packet(NativeCapturedPacket {
                    timestamp: SystemTime::UNIX_EPOCH,
                    received_at: Some(ingress),
                    captured_length: 3,
                    original_length: 5,
                    bytes: Bytes::from_static(&[1, 2, 3]),
                })),
                Err(terminal.clone()),
            ],
            Arc::clone(&interrupt),
        );
        wait_for_scripted_terminal_state(&session, finished, 1);

        session
            .wait_ready(&Deadline::new(Duration::from_millis(100)))
            .expect("queued evidence keeps a ready session readable");
        let captured = session
            .next_captured_frame(&Deadline::new(Duration::ZERO))
            .expect("queued frame")
            .expect("one queued frame");
        assert_eq!(captured.frame.bytes().as_ref(), &[1, 2, 3]);
        assert_eq!(captured.frame.captured_length(), 3);
        assert_eq!(captured.frame.original_length(), 5);
        assert_eq!(captured.frame.interface, Some(9));
        assert_eq!(captured.received_at, Some(ingress));
        assert_same_failure(
            &session
                .next_captured_frame(&Deadline::new(Duration::ZERO))
                .expect_err("terminal error follows queued evidence"),
            &terminal,
        );
        assert_eq!(
            session.statistics(),
            Statistics {
                received_frames: 1,
                received_bytes: 3,
                ..Statistics::default()
            }
        );
        session
            .shutdown()
            .expect("an already-observed worker error does not become a cleanup error");
        assert_eq!(interrupt.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn invalid_native_frame_fails_readiness_without_delivering_partial_evidence() {
        let interrupt = Arc::new(FakeInterrupt::default());
        let (mut session, finished) = scripted_session(
            [Ok(NativeCaptureEvent::Packet(NativeCapturedPacket {
                timestamp: SystemTime::UNIX_EPOCH,
                received_at: None,
                captured_length: 2,
                original_length: 2,
                bytes: Bytes::from_static(&[1]),
            }))],
            interrupt,
        );
        wait_for_scripted_terminal_state(&session, finished, 0);

        let error = session
            .wait_ready(&Deadline::new(Duration::from_millis(100)))
            .expect_err("invalid frame must fail closed");
        assert!(matches!(
            error,
            Error::Capture { ref message, .. }
                if message.contains("native capture returned an invalid frame")
        ));
        assert!(matches!(
            session.next_captured_frame(&Deadline::new(Duration::ZERO)),
            Err(Error::Capture { .. })
        ));
        assert_eq!(session.statistics(), Statistics::default());
        session
            .shutdown()
            .expect("observed capture error leaves no cleanup error");
    }

    #[test]
    fn capture_waits_reject_timeouts_above_the_public_maximum() {
        let frozen = Instant::now();
        let fixed = |limit| Deadline::with_time_source(limit, move || frozen);
        assert!(capture_deadline(&fixed(MAX_TIMEOUT)).unwrap().is_some());
        assert!(matches!(
            capture_deadline(&fixed(MAX_TIMEOUT + Duration::from_nanos(1))),
            Err(Error::InvalidCaptureTimeout {
                maximum: MAX_TIMEOUT,
                ..
            })
        ));
        assert!(capture_deadline(&fixed(Duration::ZERO)).unwrap().is_none());
    }

    #[test]
    fn cancellation_ends_a_capture_wait_and_still_allows_explicit_shutdown() {
        let (release_sender, release_receiver) = mpsc::channel();
        let interrupt = Arc::new(FakeInterrupt::default());
        let (mut session, started_receiver) = blocked_session(
            release_receiver,
            None,
            Arc::clone(&interrupt),
            Duration::from_secs(1),
        );
        session
            .wait_ready(&Deadline::new(Duration::from_millis(100)))
            .expect("fake capture should become ready");
        wait_until_blocked(started_receiver);

        let signal = packetcraftr_core::budget::Cancellation::default();
        let caller = Deadline::new(Duration::from_secs(30)).with_cancellation(Some(signal.clone()));
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            signal.cancel();
        });
        let started = Instant::now();
        assert!(matches!(
            session.next_captured_frame(&caller),
            Err(Error::Cancelled(_))
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
        canceller.join().unwrap();

        // Shutdown sets the stop flag before it interrupts the source, so a
        // worker released after the interrupt sees a requested stop rather
        // than an unexpected close.
        let releaser = {
            let interrupt = Arc::clone(&interrupt);
            thread::spawn(move || {
                let waited = Instant::now();
                while interrupt.calls.load(Ordering::SeqCst) == 0
                    && waited.elapsed() < Duration::from_secs(1)
                {
                    thread::sleep(Duration::from_millis(1));
                }
                release_sender
                    .send(())
                    .expect("release fake capture worker");
            })
        };
        session
            .shutdown()
            .expect("cancellation leaves cleanup available");
        releaser.join().unwrap();
    }

    #[test]
    fn drop_transfers_capture_worker_to_reaper() {
        let (release_sender, release_receiver) = mpsc::channel();
        let (finished_sender, finished_receiver) = mpsc::channel();
        let interrupt = Arc::new(FakeInterrupt::default());
        let (mut session, started_receiver) = blocked_session(
            release_receiver,
            Some(finished_sender),
            interrupt,
            Duration::from_millis(5),
        );
        session
            .wait_ready(&Deadline::new(Duration::from_millis(100)))
            .expect("fake capture should become ready");
        wait_until_blocked(started_receiver);
        drop(session);

        release_sender
            .send(())
            .expect("release reaped capture worker");
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("capture reaper should eventually join the worker");
    }

    #[test]
    fn successful_shutdown_keeps_admission_through_interrupt_destruction() {
        struct BlockingDrop {
            entered: Sender<()>,
            release: std::sync::Mutex<Receiver<()>>,
        }
        impl CaptureInterrupt for BlockingDrop {
            fn interrupt(&self) {}
        }
        impl Drop for BlockingDrop {
            fn drop(&mut self) {
                self.entered.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(3))
                    .unwrap();
            }
        }
        let (reaper, _receiver) = client_with_receiver(1, 1);
        let (entered, waiting) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let mut session = NativeCaptureSession::spawn_with_reaper(
            NativeCaptureParts {
                source: Box::new(CountingSource {
                    calls: Arc::new(AtomicUsize::new(0)),
                }),
                interrupt: Arc::new(BlockingDrop {
                    entered,
                    release: std::sync::Mutex::new(released),
                }),
                metadata: metadata("destructor", 1),
            },
            Limits::default(),
            Duration::from_secs(1),
            Ok(reaper.clone()),
        )
        .unwrap();
        let worker = std::thread::spawn(move || {
            let _ = session.shutdown();
        });
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            reaper.reserve().is_err(),
            "interrupt destructor still owns admission"
        );
        release.send(()).unwrap();
        worker.join().unwrap();
        assert!(reaper.reserve().is_ok());
    }

    #[test]
    fn reaper_spawn_failure_does_not_start_an_unmanaged_capture_worker() {
        let calls = Arc::new(AtomicUsize::new(0));
        let reaper_error = match start_with(1, |_| {
            Err(std::io::Error::other("injected capture reaper failure"))
        }) {
            Ok(_) => panic!("injected reaper creation must fail"),
            Err(error) => error,
        };
        let (interrupt_dropped, interrupt_drop_receiver) = mpsc::channel();
        let result = NativeCaptureSession::spawn_with_reaper(
            NativeCaptureParts {
                source: Box::new(CountingSource {
                    calls: Arc::clone(&calls),
                }),
                interrupt: Arc::new(LifetimeInterrupt {
                    dropped: interrupt_dropped,
                }),
                metadata: metadata("unstarted-capture", 11),
            },
            Limits::default(),
            Duration::ZERO,
            Err(reaper_error),
        );
        assert!(matches!(result, Err(Error::Capture { .. })));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        interrupt_drop_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("unstarted capture parts are released normally");
    }

    #[test]
    fn session_drop_is_no_panic_when_reaper_queue_is_saturated() {
        let (reaper, _receiver) = client_with_receiver(1, 1);
        reaper.transfer(Box::new(|| {}));
        let (release_sender, release_receiver) = mpsc::channel();
        let (started_sender, started_receiver) = mpsc::channel();
        let session = NativeCaptureSession::spawn_with_reaper(
            NativeCaptureParts {
                source: Box::new(BlockingSource {
                    started: Some(started_sender),
                    release: release_receiver,
                    finished: None,
                }),
                interrupt: Arc::new(FakeInterrupt::default()),
                metadata: metadata("saturated-reaper", 12),
            },
            Limits::default(),
            Duration::ZERO,
            Ok(reaper.clone()),
        )
        .expect("capture reserves cleanup before starting");
        wait_until_blocked(started_receiver);

        assert!(catch_unwind(AssertUnwindSafe(|| drop(session))).is_ok());
        assert_eq!(retained_tasks(&reaper), 1);
        release_sender
            .send(())
            .expect("retained test worker can still finish safely");
    }

    #[test]
    fn session_drop_contains_capture_interrupt_panics() {
        let (release_sender, release_receiver) = mpsc::channel();
        let (started_sender, started_receiver) = mpsc::channel();
        let (finished_sender, finished_receiver) = mpsc::channel();
        let session = NativeCaptureSession::spawn_with_shutdown_timeout(
            NativeCaptureParts {
                source: Box::new(BlockingSource {
                    started: Some(started_sender),
                    release: release_receiver,
                    finished: Some(finished_sender),
                }),
                interrupt: Arc::new(PanickingInterrupt),
                metadata: metadata("panicking-interrupt", 14),
            },
            Limits::default(),
            Duration::ZERO,
        )
        .expect("capture starts with a defective interrupt fixture");
        wait_until_blocked(started_receiver);

        assert!(catch_unwind(AssertUnwindSafe(|| drop(session))).is_ok());
        release_sender
            .send(())
            .expect("release capture after contained interrupt panic");
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("shared reaper retains the worker after interrupt panic");
    }

    #[test]
    fn reaper_keeps_native_interrupt_alive_until_capture_worker_stops() {
        let (reaper, receiver) = client_with_receiver(1, 1);
        let (release_sender, release_receiver) = mpsc::channel();
        let (started_sender, started_receiver) = mpsc::channel();
        let (finished_sender, finished_receiver) = mpsc::channel();
        let (interrupt_dropped, interrupt_drop_receiver) = mpsc::channel();
        let session = NativeCaptureSession::spawn_with_reaper(
            NativeCaptureParts {
                source: Box::new(BlockingSource {
                    started: Some(started_sender),
                    release: release_receiver,
                    finished: Some(finished_sender),
                }),
                interrupt: Arc::new(LifetimeInterrupt {
                    dropped: interrupt_dropped,
                }),
                metadata: metadata("lifetime-capture", 13),
            },
            Limits::default(),
            Duration::ZERO,
            Ok(reaper),
        )
        .expect("capture reserves cleanup before starting");
        wait_until_blocked(started_receiver);
        drop(session);

        let task = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("drop transfers the complete capture bundle");
        let reap = thread::spawn(task);
        assert!(matches!(
            interrupt_drop_receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release_sender.send(()).expect("release capture worker");
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("capture source stops");
        reap.join().expect("test reaper completes");
        interrupt_drop_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("interrupt is released only after worker join");
    }

    #[test]
    fn drop_after_shutdown_timeout_transfers_capture_worker_without_second_wait() {
        let (release_sender, release_receiver) = mpsc::channel();
        let (finished_sender, finished_receiver) = mpsc::channel();
        let interrupt = Arc::new(FakeInterrupt::default());
        let (mut session, started_receiver) = blocked_session(
            release_receiver,
            Some(finished_sender),
            Arc::clone(&interrupt),
            Duration::from_millis(5),
        );
        session
            .wait_ready(&Deadline::new(Duration::from_millis(100)))
            .expect("fake capture should become ready");
        wait_until_blocked(started_receiver);
        assert!(matches!(
            session.shutdown(),
            Err(Error::DeadlineExceeded {
                operation: "shutting down native capture"
            })
        ));

        session.shutdown_timeout = Duration::from_secs(1);
        let drop_started = Instant::now();
        drop(session);
        assert!(
            drop_started.elapsed() < Duration::from_millis(250),
            "drop spent a second shutdown timeout before reaping"
        );

        release_sender
            .send(())
            .expect("release reaped capture worker");
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("capture reaper should eventually join the worker");
        assert!(interrupt.calls.load(Ordering::SeqCst) >= 1);
    }
}
