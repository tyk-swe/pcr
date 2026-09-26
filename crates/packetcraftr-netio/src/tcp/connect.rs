// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ordinary TCP connects on the native worker pool, under their sub-limit.

use crate::{
    tcp::{ConnectOutcome, Connection, Error, MAX_PENDING_CONNECTIONS, Provider},
    workers::{self, Class, RetentionMarker, Task},
};
use packetcraftr_core::budget::{Cancelled, Deadline};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime},
};

#[derive(Default)]
struct CancelState {
    cancelled: bool,
    attempted: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Progress {
    Running,
    Complete,
    /// The worker panicked before reporting an outcome.
    Failed,
}

pub(super) struct Pending<S> {
    task: Task<ConnectOutcome<S>>,
    cancel: Arc<Mutex<CancelState>>,
    retention: RetentionMarker,
    progress: Progress,
}
impl<S> Pending<S> {
    pub(super) fn cancel(&mut self) -> bool {
        let mut state = self
            .cancel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.cancelled = true;
        state.attempted
    }

    pub(super) fn poll(&mut self) -> Result<Option<ConnectOutcome<S>>, Error> {
        match self.progress {
            Progress::Complete => return Err(Error::Completed),
            Progress::Failed => return Err(Error::Worker),
            Progress::Running => {}
        }
        match self.task.try_take() {
            None => Ok(None),
            Some(Ok(outcome)) => {
                self.progress = Progress::Complete;
                Ok(Some(outcome))
            }
            Some(Err(_)) => {
                self.progress = Progress::Failed;
                Err(Error::Worker)
            }
        }
    }
}
impl<S> Drop for Pending<S> {
    fn drop(&mut self) {
        self.cancel();
        if self.progress == Progress::Running {
            self.retention.mark_retained();
        }
        // A running worker keeps its permit through provider cleanup. An
        // unclaimed successful connection holds the same permit until the
        // task's outcome, and with it the socket, is dropped.
    }
}

pub(super) fn start<P>(
    provider: Arc<P>,
    endpoint: SocketAddr,
    caller: &Deadline,
) -> Result<Pending<P::Stream>, Error>
where
    P: Provider + 'static,
    P::Stream: 'static,
{
    let deadline = crate::deadline::detach(caller).map_err(Error::interrupted)?;
    if deadline.limit() > crate::capture::MAX_TIMEOUT {
        return Err(Error::Timeout);
    }
    let started = Instant::now();
    let started_at = SystemTime::now();
    let permit = workers::shared()
        .admit(Class::TcpConnect)
        .map_err(|_| Error::Capacity {
            limit: MAX_PENDING_CONNECTIONS,
        })?;
    let lease = permit.clone();
    let cancel = Arc::new(Mutex::new(CancelState::default()));
    let cancelled = Arc::clone(&cancel);
    // The provider and any failed stream are dropped when this job ends,
    // before the pool releases the permit.
    let task = permit
        .spawn(move || {
            let admitted = {
                let mut state = cancelled
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // A connection stopped before its provider ran reports why
                // it never started: cancelled, or out of time.
                let admitted = if state.cancelled {
                    Err(Error::Cancelled(Cancelled))
                } else {
                    crate::deadline::remaining(&deadline)
                        .map(drop)
                        .map_err(Error::interrupted)
                };
                state.attempted = admitted.is_ok();
                admitted
            };
            let attempted = admitted.is_ok();
            let result = admitted.and_then(|()| {
                provider
                    .connect(endpoint, &deadline)
                    .map(|stream| Connection::new(stream, lease))
            });
            ConnectOutcome {
                attempted,
                started_at,
                completed_at: SystemTime::now(),
                elapsed: started.elapsed(),
                result,
            }
        })
        .map_err(Error::Spawn)?;
    Ok(Pending {
        retention: task.retention_marker(),
        task,
        cancel,
        progress: Progress::Running,
    })
}
