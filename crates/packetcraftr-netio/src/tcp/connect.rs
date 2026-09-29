// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    tcp::{ConnectOutcome, Connection, Error, MAX_PENDING_CONNECTIONS, Provider},
    workers::{self, Class, Task},
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

/// Pollable bounded connect. Dropping it cancels unstarted work.
pub struct PendingConnect<S> {
    task: Task<ConnectOutcome<S>>,
    cancel: Arc<Mutex<CancelState>>,
    progress: Progress,
}
impl<S> PendingConnect<S> {
    pub fn cancel(&mut self) -> bool {
        let mut state = self
            .cancel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.cancelled = true;
        state.attempted
    }

    pub fn poll(&mut self) -> Result<Option<ConnectOutcome<S>>, Error> {
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

    /// Returns `None` if `deadline` expires or is cancelled while work is pending.
    pub fn wait(&mut self, deadline: &Deadline) -> Result<Option<ConnectOutcome<S>>, Error> {
        self.task.wait_ready(deadline);
        self.poll()
    }
}
impl<S> Drop for PendingConnect<S> {
    fn drop(&mut self) {
        self.cancel();
        if self.progress == Progress::Running {
            self.task.retention_marker().mark_retained();
        }
        // A running worker keeps its permit through provider cleanup.
    }
}

pub fn start_connect<P>(
    provider: Arc<P>,
    endpoint: SocketAddr,
    caller: &Deadline,
) -> Result<PendingConnect<P::Stream>, Error>
where
    P: Provider + 'static,
    P::Stream: 'static,
{
    let deadline = crate::deadline::detach(caller).map_err(Error::interrupted)?;
    if deadline.limit() > crate::deadline::MAX_WAIT {
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
    let task = permit
        .spawn(move || {
            let admitted = {
                let mut state = cancelled
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    Ok(PendingConnect {
        task,
        cancel,
        progress: Progress::Running,
    })
}
