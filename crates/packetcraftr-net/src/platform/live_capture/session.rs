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
    Error as LiveIoError,
    capture::{
        CaptureQueueLimits, CaptureSession, CaptureStatistics, CapturedFrame, validate_timeout,
    },
};

use super::{CaptureInterrupt, NativeCaptureParts, queue::SharedCapture, worker::capture_worker};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

pub(in crate::platform) struct NativeCaptureSession {
    shared: Arc<SharedCapture>,
    stop: Arc<AtomicBool>,
    interrupt: Option<Arc<dyn CaptureInterrupt>>,
    worker: Option<JoinHandle<()>>,
    shutdown_result: Option<Result<(), LiveIoError>>,
}

impl NativeCaptureSession {
    pub(in crate::platform) fn spawn(
        parts: NativeCaptureParts,
        limits: CaptureQueueLimits,
    ) -> Result<Self, LiveIoError> {
        let validated_limits = limits.validate()?;
        let shared = Arc::new(SharedCapture::new(validated_limits));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_shared = Arc::clone(&shared);
        let worker_stop = Arc::clone(&stop);
        let interface_index = parts.interface.index;
        let link_type = parts.link_type;
        let mut source = parts.source;
        let worker = thread::Builder::new()
            .name(format!("packetcraftr-capture-{}", parts.interface.name))
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
                    panic_shared.set_error(LiveIoError::Capture {
                        message: "native capture worker panicked".to_owned(),
                    });
                }
            })
            .map_err(|error| LiveIoError::Capture {
                message: format!("could not start the owned capture worker: {error}"),
            })?;
        Ok(Self {
            shared,
            stop,
            interrupt: Some(parts.interrupt),
            worker: Some(worker),
            shutdown_result: None,
        })
    }
}

impl CaptureSession for NativeCaptureSession {
    fn wait_ready(&mut self, timeout: Duration) -> Result<(), LiveIoError> {
        validate_timeout(timeout)?;
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return Err(LiveIoError::CaptureReadiness {
                message: "capture readiness deadline is not representable".to_owned(),
            });
        };
        let mut state = self.shared.lock()?;
        while !state.ready && !state.closed && state.error.is_none() {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(LiveIoError::CaptureReadiness {
                    message: "capture readiness deadline expired".to_owned(),
                });
            };
            let (next, timed_out) = self.shared.wait_timeout(state, remaining)?;
            state = next;
            if timed_out && !state.ready && !state.closed && state.error.is_none() {
                return Err(LiveIoError::CaptureReadiness {
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
            Err(LiveIoError::CaptureReadiness {
                message: "native capture worker closed before reporting readiness".to_owned(),
            })
        }
    }

    fn next_captured_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<CapturedFrame>, LiveIoError> {
        validate_timeout(timeout)?;
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return Err(LiveIoError::DeadlineExceeded {
                operation: "waiting for captured frame",
            });
        };
        let mut state = self.shared.lock()?;
        loop {
            if let Some(captured) = state.queue.front() {
                let queued_bytes = state
                    .queued_bytes
                    .checked_sub(captured.frame.bytes().len())
                    .ok_or_else(|| LiveIoError::InvalidCaptureStatistics {
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

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        if let Some(result) = &self.shutdown_result {
            return result.clone();
        }
        self.request_stop();
        if let Some(worker) = self.worker.as_ref() {
            wait_for_worker(worker, SHUTDOWN_TIMEOUT)?;
        }
        let join_result = self.worker.take().map_or(Ok(()), join_worker);
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

    fn statistics(&self) -> CaptureStatistics {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .statistics
    }
}

impl NativeCaptureSession {
    fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(interrupt) = &self.interrupt {
            interrupt.interrupt();
        }
    }
}

fn wait_for_worker(worker: &JoinHandle<()>, timeout: Duration) -> Result<(), LiveIoError> {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return Err(LiveIoError::DeadlineExceeded {
            operation: "shutting down native capture",
        });
    };
    while !worker.is_finished() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(LiveIoError::DeadlineExceeded {
                operation: "shutting down native capture",
            });
        };
        thread::park_timeout(remaining.min(Duration::from_millis(10)));
    }
    Ok(())
}

fn join_worker(worker: JoinHandle<()>) -> Result<(), LiveIoError> {
    worker.join().map_err(|_| LiveIoError::Capture {
        message: "native capture worker panicked during shutdown".to_owned(),
    })
}

impl Drop for NativeCaptureSession {
    fn drop(&mut self) {
        self.request_stop();
        if let Some(worker) = self.worker.take() {
            let _ = join_worker(worker);
        }
    }
}
