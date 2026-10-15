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
