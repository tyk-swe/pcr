// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use packetcraftr_core::budget::Deadline;

use crate::deadline::{POLL_INTERVAL, remaining_before};
use packetcraftr_core::frame::LinkType;

use crate::workers::{Permit, Task, Waited};

use crate::{
    Error,
    capture::{Captured, Limits, Metadata, Session, Stats},
    workers::reaper::ReaperClient,
};

use super::{
    CaptureInterrupt, NativeCaptureParts,
    queue::CaptureQueue,
    worker::{capture_worker, transfer_capture_worker},
};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) struct NativeCaptureSession {
    metadata: Metadata,
    shared: Arc<CaptureQueue>,
    stop: Arc<AtomicBool>,
    /// The interrupt outlives the worker, and the permit outlives the interrupt.
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
    Incomplete,
    Finished(Result<(), Error>),
}

pub(crate) struct Started {
    metadata: Metadata,
    shared: Arc<CaptureQueue>,
    stop: Arc<AtomicBool>,
    interrupt: Arc<dyn CaptureInterrupt>,
}

pub(crate) struct Reader {
    source: Box<dyn super::NativeCaptureSource>,
    shared: Arc<CaptureQueue>,
    stop: Arc<AtomicBool>,
    interface_index: u32,
    link_type: LinkType,
}

impl Reader {
    pub(crate) fn run(mut self) {
        let terminal_shared = Arc::clone(&self.shared);
        let result = catch_unwind(AssertUnwindSafe(|| {
            capture_worker(
                self.source.as_mut(),
                self.shared,
                self.stop,
                self.interface_index,
                self.link_type,
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
    }
}

impl NativeCaptureSession {
    pub(crate) fn prepare(parts: NativeCaptureParts, limits: Limits) -> (Started, Reader) {
        let NativeCaptureParts {
            source,
            interrupt,
            metadata,
        } = parts;
        let shared = Arc::new(CaptureQueue::new(limits));
        let stop = Arc::new(AtomicBool::new(false));
        let reader = Reader {
            source,
            shared: Arc::clone(&shared),
            stop: Arc::clone(&stop),
            interface_index: metadata.interface.index,
            link_type: metadata.link_type,
        };
        (
            Started {
                metadata,
                shared,
                stop,
                interrupt,
            },
            reader,
        )
    }

    pub(crate) fn attach(
        started: Started,
        worker: Task<()>,
        permit: Permit,
        reaper: ReaperClient,
    ) -> Self {
        let Started {
            metadata,
            shared,
            stop,
            interrupt,
        } = started;
        Self {
            metadata,
            shared,
            stop,
            running: Some(RunningCapture {
                worker,
                interrupt,
                permit,
            }),
            reaper,
            shutdown_timeout: SHUTDOWN_TIMEOUT,
            shutdown: Shutdown::NotAttempted,
        }
    }
}

impl Session for NativeCaptureSession {
    fn supports_ingress_time(&self) -> bool {
        true
    }
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, caller: &Deadline) -> Result<(), Error> {
        let deadline = crate::capture::wait_end(caller)?;
        let expired = || Error::CaptureReadiness {
            message: "capture readiness deadline expired".to_owned(),
        };
        let mut state = self.shared.lock();
        while !state.ready && !state.closed && state.error.is_none() {
            let Some(remaining) = deadline.and_then(remaining_before) else {
                return Err(expired());
            };
            // Wait in slices: the queue signals readiness, not cancellation.
            state = self
                .shared
                .wait_timeout(state, remaining.min(POLL_INTERVAL));
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
        let deadline = crate::capture::wait_end(caller)?;
        let mut state = self.shared.lock();
        loop {
            if let Some(captured) = state.pop_front()? {
                return Ok(Some(captured));
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
            state = self
                .shared
                .wait_timeout(state, remaining.min(POLL_INTERVAL));
            if state.queue.is_empty() && state.error.is_none() {
                caller.check_cancelled()?;
            }
        }
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        self.shutdown_with_timeout(self.shutdown_timeout)
    }

    fn stats(&self) -> Stats {
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
                        self.running = Some(RunningCapture {
                            worker,
                            interrupt,
                            permit,
                        });
                        return Err(Error::DeadlineExceeded {
                            operation: "shutting down native capture",
                        });
                    }
                    Waited::Finished(join_result) => {
                        // Release a user-supplied interrupt before returning admission.
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
            // Explicit shutdown has already used its finite deadline.
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
    #![allow(dead_code)]

    use std::collections::VecDeque;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender},
    };
    use std::thread;
    use std::time::Instant;

    use super::*;
    use crate::capture::live::{
        NativeCaptureEvent, NativeCaptureSource, NativeCaptureStats,
        test_support::{BlockingSource, FakeInterrupt},
    };

    use crate::{
        capture::Limits,
        test_support::capture_metadata,
        workers::{Class, Pool, reaper::shared_reaper},
    };

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

        fn stats(&mut self) -> Result<NativeCaptureStats, Error> {
            Ok(NativeCaptureStats::default())
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

        fn stats(&mut self) -> Result<NativeCaptureStats, Error> {
            Ok(NativeCaptureStats::default())
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

        fn stats(&mut self) -> Result<NativeCaptureStats, Error> {
            Ok(NativeCaptureStats::default())
        }
    }

    impl Drop for ScriptedSource {
        fn drop(&mut self) {
            if let Some(finished) = self.finished.take() {
                let _ = finished.send(());
            }
        }
    }

    fn spawn_on(
        parts: NativeCaptureParts,
        pool: &Arc<Pool>,
        reaper: ReaperClient,
        shutdown_timeout: Duration,
    ) -> NativeCaptureSession {
        let permit = pool
            .admit(Class::Native)
            .expect("the test pool admits the reader");
        let (started, reader) = NativeCaptureSession::prepare(parts, Limits::default());
        let worker = permit
            .spawn(move || reader.run())
            .expect("the reader spawns");
        let mut session = NativeCaptureSession::attach(started, worker, permit, reaper);
        session.shutdown_timeout = shutdown_timeout;
        session
    }

    fn spawn(parts: NativeCaptureParts, shutdown_timeout: Duration) -> NativeCaptureSession {
        spawn_on(
            parts,
            crate::workers::shared(),
            shared_reaper().expect("the shared reaper starts"),
            shutdown_timeout,
        )
    }

    fn scripted_session(
        events: impl IntoIterator<Item = Result<NativeCaptureEvent, Error>>,
        interrupt: Arc<FakeInterrupt>,
    ) -> (NativeCaptureSession, Receiver<()>) {
        let (finished_sender, finished_receiver) = mpsc::channel();
        let interrupt: Arc<dyn CaptureInterrupt> = interrupt;
        let session = spawn(
            NativeCaptureParts {
                source: Box::new(ScriptedSource {
                    events: events.into_iter().collect(),
                    finished: Some(finished_sender),
                }),
                interrupt,
                metadata: capture_metadata("scripted-capture", 9),
            },
            SHUTDOWN_TIMEOUT,
        );
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
        let session = spawn(
            NativeCaptureParts {
                source: Box::new(BlockingSource {
                    started: Some(started_sender),
                    release,
                    finished,
                }),
                interrupt: interrupt_for_parts,
                metadata: capture_metadata("fake-capture", 1),
            },
            shutdown_timeout,
        );
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
        // Releasing the source only wakes the worker. Synchronize completion
        // before testing the retry instead of requiring scheduling within 5 ms.
        session
            .running
            .as_ref()
            .expect("timed-out shutdown retains the worker")
            .worker
            .wait_ready(&Deadline::new(Duration::from_secs(5)));
        session.shutdown().expect("released worker shuts down");
        assert!(session.running.is_none());
        session
            .shutdown()
            .expect("shutdown after the worker is gone is idempotent");
        assert_eq!(interrupt.calls.load(Ordering::SeqCst), 2);
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

        // Shutdown sets the stop flag before it interrupts the source.
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
}
