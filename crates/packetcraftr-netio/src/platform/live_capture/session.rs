// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Owned capture-session lifecycle and worker join semantics.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use crate::{
    Error,
    capture::{Captured, Limits, MAX_TIMEOUT, Metadata, Session, Statistics},
};

use super::{
    CaptureInterrupt, NativeCaptureParts,
    queue::SharedCapture,
    worker::{capture_worker, transfer_capture_worker},
};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

fn capture_deadline(timeout: Duration) -> Result<Instant, Error> {
    if timeout > MAX_TIMEOUT {
        return Err(Error::InvalidCaptureTimeout {
            timeout,
            maximum: MAX_TIMEOUT,
        });
    }
    Instant::now()
        .checked_add(timeout)
        .ok_or(Error::InvalidCaptureTimeout {
            timeout,
            maximum: MAX_TIMEOUT,
        })
}

pub(in crate::platform) struct NativeCaptureSession {
    metadata: Metadata,
    shared: Arc<SharedCapture>,
    stop: Arc<AtomicBool>,
    interrupt: Option<Arc<dyn CaptureInterrupt>>,
    worker: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
    shutdown_attempted: bool,
    shutdown_result: Option<Result<(), Error>>,
}

impl NativeCaptureSession {
    pub(in crate::platform) fn spawn(
        parts: NativeCaptureParts,
        limits: Limits,
    ) -> Result<Self, Error> {
        Self::spawn_with_shutdown_timeout(parts, limits, SHUTDOWN_TIMEOUT)
    }

    fn spawn_with_shutdown_timeout(
        parts: NativeCaptureParts,
        limits: Limits,
        shutdown_timeout: Duration,
    ) -> Result<Self, Error> {
        let NativeCaptureParts {
            source,
            interrupt,
            metadata,
        } = parts;
        let shared = Arc::new(SharedCapture::new(limits));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_shared = Arc::clone(&shared);
        let worker_stop = Arc::clone(&stop);
        let interface_index = metadata.interface.index;
        let link_type = metadata.link_type;
        let worker_name = format!("packetcraftr-capture-{}", metadata.interface.name);
        let mut source = source;
        let worker = thread::Builder::new()
            .name(worker_name)
            .spawn(move || {
                let panic_shared = Arc::clone(&worker_shared);
                if catch_unwind(AssertUnwindSafe(|| {
                    capture_worker(
                        source.as_mut(),
                        worker_shared,
                        worker_stop,
                        interface_index,
                        link_type,
                    );
                }))
                .is_err()
                {
                    panic_shared.set_error(Error::Capture {
                        message: "native capture worker panicked".to_owned(),
                    });
                }
            })
            .map_err(|error| Error::Capture {
                message: format!("could not start the owned capture worker: {error}"),
            })?;
        Ok(Self {
            metadata,
            shared,
            stop,
            interrupt: Some(interrupt),
            worker: Some(worker),
            shutdown_timeout,
            shutdown_attempted: false,
            shutdown_result: None,
        })
    }
}

impl Session for NativeCaptureSession {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, timeout: Duration) -> Result<(), Error> {
        let deadline = capture_deadline(timeout)?;
        let mut state = self.shared.lock()?;
        while !state.ready && !state.closed && state.error.is_none() {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(Error::CaptureReadiness {
                    message: "capture readiness deadline expired".to_owned(),
                });
            };
            let (next, timed_out) = self.shared.wait_timeout(state, remaining)?;
            state = next;
            if timed_out && !state.ready && !state.closed && state.error.is_none() {
                return Err(Error::CaptureReadiness {
                    message: "capture readiness deadline expired".to_owned(),
                });
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

    fn next_captured_frame(&mut self, timeout: Duration) -> Result<Option<Captured>, Error> {
        let deadline = capture_deadline(timeout)?;
        let mut state = self.shared.lock()?;
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
            if state.closed || timeout.is_zero() {
                return Ok(None);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(None);
            };
            let (next_state, timed_out) = self.shared.wait_timeout(state, remaining)?;
            state = next_state;
            if timed_out {
                continue;
            }
        }
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        self.shutdown_with_timeout(self.shutdown_timeout)
    }

    fn statistics(&self) -> Statistics {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .statistics
    }
}

impl NativeCaptureSession {
    fn shutdown_with_timeout(&mut self, timeout: Duration) -> Result<(), Error> {
        if let Some(result) = &self.shutdown_result {
            return result.clone();
        }
        self.shutdown_attempted = true;
        self.stop.store(true, Ordering::Release);
        if let Some(interrupt) = &self.interrupt {
            interrupt.interrupt();
        }

        let join_result = match join_worker(&mut self.worker, timeout) {
            JoinAttempt::TimedOut(error) => return Err(error),
            JoinAttempt::Finished(result) => result,
        };
        // The worker is now known to be finished. It is safe to release the
        // native interrupt only after this ownership boundary has completed.
        self.interrupt.take();

        let result = join_result.and_then(|()| {
            let mut state = self.shared.lock()?;
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
        self.shutdown_result = Some(result.clone());
        result
    }
}

enum JoinAttempt {
    Finished(Result<(), Error>),
    TimedOut(Error),
}

fn join_worker(worker: &mut Option<JoinHandle<()>>, timeout: Duration) -> JoinAttempt {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return JoinAttempt::TimedOut(Error::DeadlineExceeded {
            operation: "shutting down native capture",
        });
    };
    loop {
        let Some(handle) = worker.as_ref() else {
            return JoinAttempt::Finished(Ok(()));
        };
        if handle.is_finished() {
            break;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return JoinAttempt::TimedOut(Error::DeadlineExceeded {
                operation: "shutting down native capture",
            });
        };
        thread::park_timeout(remaining.min(Duration::from_millis(10)));
    }

    // `is_finished` is monotonic: once true, taking the handle cannot turn a
    // still-running worker into an unowned detached thread.
    let handle = worker
        .take()
        .expect("finished native capture worker handle disappeared");
    JoinAttempt::Finished(handle.join().map_err(|_| Error::Capture {
        message: "native capture worker panicked during shutdown".to_owned(),
    }))
}

impl Drop for NativeCaptureSession {
    fn drop(&mut self) {
        if !self.shutdown_attempted {
            let _ = self.shutdown();
        }
        if let Some(worker) = self.worker.take() {
            // Explicit shutdown has already used its finite deadline. A
            // running worker is transferred, together with its interrupt, to
            // an owner that can wait without blocking this Drop path.
            transfer_capture_worker(worker, Arc::clone(&self.stop), self.interrupt.take());
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
    use std::time::SystemTime;

    use bytes::Bytes;
    use packetcraftr_core::frame::LinkType;

    use super::super::{
        NativeCaptureEvent, NativeCaptureSource, NativeCaptureStatistics, NativeCapturedPacket,
    };
    use super::*;
    use crate::{
        capture::{Limits, Metadata},
        interface::Id as InterfaceId,
    };

    fn metadata(name: &str, index: u32) -> Metadata {
        Metadata {
            interface: InterfaceId {
                name: name.to_owned(),
                index,
            },
            link_type: LinkType::ETHERNET,
            snap_length: 64,
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
        let state = session.shared.lock().expect("scripted capture state");
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
            .wait_ready(Duration::from_millis(100))
            .expect("fake capture should become ready");
        wait_until_blocked(started_receiver);

        assert!(matches!(
            session.shutdown(),
            Err(Error::DeadlineExceeded {
                operation: "shutting down native capture"
            })
        ));
        assert!(session.worker.is_some());
        assert!(session.interrupt.is_some());
        assert_eq!(interrupt.calls.load(Ordering::SeqCst), 1);

        release_sender
            .send(())
            .expect("release fake capture worker");
        assert_eq!(session.shutdown(), Ok(()));
        assert!(session.worker.is_none());
        assert!(session.interrupt.is_none());
        assert_eq!(session.shutdown(), Ok(()));
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
            Duration::from_millis(100),
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
        assert_eq!(first, second);
        assert!(matches!(
            first,
            Error::Capture { ref message }
                if message == "native capture worker panicked"
        ));
        assert!(session.worker.is_none());
        assert!(session.interrupt.is_none());
        assert_eq!(interrupt.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn queued_frame_is_delivered_before_a_later_terminal_source_error() {
        let ingress = Instant::now();
        let terminal = Error::Capture {
            message: "source failed after one frame".to_owned(),
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
            .wait_ready(Duration::from_millis(100))
            .expect("queued evidence keeps a ready session readable");
        let captured = session
            .next_captured_frame(Duration::ZERO)
            .expect("queued frame")
            .expect("one queued frame");
        assert_eq!(captured.frame.bytes().as_ref(), &[1, 2, 3]);
        assert_eq!(captured.frame.captured_length(), 3);
        assert_eq!(captured.frame.original_length(), 5);
        assert_eq!(captured.frame.interface, Some(9));
        assert_eq!(captured.received_at, Some(ingress));
        assert_eq!(
            session
                .next_captured_frame(Duration::ZERO)
                .expect_err("terminal error follows queued evidence"),
            terminal
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
            .wait_ready(Duration::from_millis(100))
            .expect_err("invalid frame must fail closed");
        assert!(matches!(
            error,
            Error::Capture { ref message }
                if message.contains("native capture returned an invalid frame")
        ));
        assert!(matches!(
            session.next_captured_frame(Duration::ZERO),
            Err(Error::Capture { .. })
        ));
        assert_eq!(session.statistics(), Statistics::default());
        session
            .shutdown()
            .expect("observed capture error leaves no cleanup error");
    }

    #[test]
    fn capture_waits_reject_timeouts_above_the_public_maximum() {
        assert!(capture_deadline(MAX_TIMEOUT).is_ok());
        assert!(matches!(
            capture_deadline(MAX_TIMEOUT + Duration::from_nanos(1)),
            Err(Error::InvalidCaptureTimeout {
                maximum: MAX_TIMEOUT,
                ..
            })
        ));
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
            .wait_ready(Duration::from_millis(100))
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
            .wait_ready(Duration::from_millis(100))
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
