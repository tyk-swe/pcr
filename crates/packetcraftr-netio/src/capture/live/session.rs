// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use packetcraftr_core::budget::{Deadline, Interrupted};

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

pub(crate) struct NativeCaptureSession {
    metadata: Metadata,
    shared: Arc<CaptureQueue>,
    stop: Arc<AtomicBool>,
    /// The interrupt outlives the worker, and the permit outlives the interrupt.
    running: Option<RunningCapture>,
    reaper: ReaperClient,
    stop_result: Option<Result<(), Error>>,
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
            stop_result: None,
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
        let check_control = || {
            caller
                .live_remaining()
                .map(drop)
                .map_err(|interrupted| match interrupted {
                    Interrupted::Cancelled(cancelled) => cancelled.into(),
                    _ => expired(),
                })
        };
        check_control()?;
        let mut state = self.shared.lock();
        while !state.ready && !state.closed && state.error.is_none() {
            check_control()?;
            let Some(remaining) = deadline.and_then(remaining_before) else {
                return Err(expired());
            };
            // Wait in slices: the queue signals readiness, not cancellation.
            state = self
                .shared
                .wait_timeout(state, remaining.min(POLL_INTERVAL));
            check_control()?;
        }
        check_control()?;
        if deadline.and_then(remaining_before).is_none() {
            return Err(expired());
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
            caller.check_cancelled()?;
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
            // An immediate poll still drains already queued records above.
            // Quiet waits retain inherited elapsed control as well as their
            // original real-wall ceiling.
            if let Err(interrupted) = caller.live_remaining() {
                return match interrupted {
                    Interrupted::Cancelled(cancelled) => Err(cancelled.into()),
                    _ => Ok(None),
                };
            }
            let Some(remaining) = deadline.and_then(remaining_before) else {
                return Ok(None);
            };
            state = self
                .shared
                .wait_timeout(state, remaining.min(POLL_INTERVAL));
        }
    }

    fn request_stop(&mut self) -> Result<(), Error> {
        if let Some(result) = &self.stop_result {
            return result.clone();
        }
        self.shutdown = Shutdown::Incomplete;
        self.stop.store(true, Ordering::Release);
        let result = self.running.as_ref().map_or(Ok(()), |running| {
            catch_unwind(AssertUnwindSafe(|| running.interrupt.interrupt())).map_err(|_| {
                Error::Capture {
                    message: "native capture interrupt panicked during shutdown".to_owned(),
                    source: None,
                }
            })
        });
        self.stop_result = Some(result.clone());
        result
    }

    fn shutdown_until(&mut self, deadline: &Deadline) -> Result<(), Error> {
        self.join_until(deadline)
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        self.join_until(&Deadline::new(crate::capture::CLEANUP_TIMEOUT))
    }

    fn stats(&self) -> Stats {
        self.shared.lock().statistics
    }

    fn observation_quality(&self) -> crate::capture::ObservationQuality {
        let state = self.shared.lock();
        let quality = if state.ready && state.error.is_none() && !state.error_observed {
            crate::capture::ObservationQuality::NoReportedLoss
        } else {
            crate::capture::ObservationQuality::Unknown
        };
        quality.with_statistics(state.statistics)
    }
}

impl NativeCaptureSession {
    fn join_until(&mut self, deadline: &Deadline) -> Result<(), Error> {
        if let Shutdown::Finished(result) = &self.shutdown {
            return result
                .clone()
                .and(self.stop_result.clone().unwrap_or(Ok(())));
        }
        let interrupt_result = self.request_stop();

        let stopped = match self.running.take() {
            None => Ok(()),
            Some(RunningCapture {
                worker,
                interrupt,
                permit,
            }) => {
                match worker.wait(deadline) {
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
                        join_result.map_err(|_| Error::Capture {
                            message: "native capture worker panicked during shutdown".to_owned(),
                            source: None,
                        })
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
        result.and(interrupt_result)
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
mod tests;
