// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    tcp::{ConnectOutcome, Connection, Error, MAX_PENDING_CONNECTIONS, Provider},
    workers::{self, Task},
};
use packetcraftr_core::budget::{Cancelled, Deadline};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
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

pub struct ConnectBudget {
    state: Arc<BudgetState>,
}

struct BudgetState {
    capacity: usize,
    active: AtomicUsize,
}

pub(crate) struct Lease {
    state: Arc<BudgetState>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ConnectBudget {
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Arc::new(BudgetState {
                capacity,
                active: AtomicUsize::new(0),
            }),
        }
    }

    pub fn capacity(&self) -> usize {
        self.state.capacity
    }

    pub fn active(&self) -> usize {
        self.state.active.load(Ordering::Relaxed)
    }

    fn lease(&self) -> Result<Lease, Error> {
        let mut active = self.state.active.load(Ordering::Relaxed);
        loop {
            if active >= self.state.capacity {
                return Err(Error::Capacity {
                    limit: self.state.capacity,
                });
            }
            match self.state.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => active = actual,
            }
        }
        Ok(Lease {
            state: Arc::clone(&self.state),
        })
    }

    pub fn start<P>(
        &self,
        provider: Arc<P>,
        endpoint: SocketAddr,
        caller: &Deadline,
    ) -> Result<PendingConnect<P::Stream>, Error>
    where
        P: Provider + 'static,
        P::Stream: 'static,
    {
        self.start_on(workers::shared(), provider, endpoint, caller)
    }

    pub(crate) fn start_on<P>(
        &self,
        pool: &Arc<workers::Pool>,
        provider: Arc<P>,
        endpoint: SocketAddr,
        caller: &Deadline,
    ) -> Result<PendingConnect<P::Stream>, Error>
    where
        P: Provider + 'static,
        P::Stream: 'static,
    {
        let lease = self.lease()?;
        start_on(pool, provider, endpoint, caller, Some(lease))
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
    start(provider, endpoint, caller, None)
}

fn start<P>(
    provider: Arc<P>,
    endpoint: SocketAddr,
    caller: &Deadline,
    lease: Option<Lease>,
) -> Result<PendingConnect<P::Stream>, Error>
where
    P: Provider + 'static,
    P::Stream: 'static,
{
    start_on(workers::shared(), provider, endpoint, caller, lease)
}

pub(crate) fn start_on<P>(
    pool: &Arc<workers::Pool>,
    provider: Arc<P>,
    endpoint: SocketAddr,
    caller: &Deadline,
    lease: Option<Lease>,
) -> Result<PendingConnect<P::Stream>, Error>
where
    P: Provider + 'static,
    P::Stream: 'static,
{
    let deadline = caller.detach().map_err(Error::interrupted)?;
    if deadline.limit() > crate::deadline::MAX_WAIT {
        return Err(Error::Timeout);
    }
    let started = Instant::now();
    let started_at = SystemTime::now();
    let permit = pool.admit_connect().map_err(|_| Error::Capacity {
        limit: MAX_PENDING_CONNECTIONS,
    })?;
    let cancel = Arc::new(Mutex::new(CancelState::default()));
    let cancelled = Arc::clone(&cancel);
    let dispatch_control = deadline.clone();
    let task = permit
        .spawn_with_control(&dispatch_control, move |slot| {
            let lease_guard = lease.map(Arc::new);
            let connection_lease = lease_guard.clone();
            let outcome = workers::unwind_after_cleanup(|| {
                let _lease = connection_lease;
                let admitted = {
                    let mut state = cancelled
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let admitted = if state.cancelled {
                        Err(Error::Cancelled(Cancelled))
                    } else {
                        deadline
                            .live_remaining()
                            .map(drop)
                            .map_err(Error::interrupted)
                    };
                    state.attempted = admitted.is_ok();
                    admitted
                };
                let attempted = admitted.is_ok();
                let result = admitted.and_then(|()| {
                    let stream = provider.connect(endpoint, &deadline)?;
                    // A provider may return after cancellation or expiry. Close its
                    // stream before releasing admission instead of publishing success.
                    let state = cancelled
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if state.cancelled {
                        return Err(Error::Cancelled(Cancelled));
                    }
                    deadline.live_remaining().map_err(Error::interrupted)?;
                    Ok(Connection::new(stream, slot.into_socket(), _lease))
                });
                ConnectOutcome {
                    attempted,
                    started_at,
                    completed_at: SystemTime::now(),
                    elapsed: started.elapsed(),
                    result,
                }
            });
            drop(lease_guard);
            outcome
        })
        .map_err(|error| match dispatch_control.enforce() {
            Err(interrupted) => Error::interrupted(interrupted),
            Ok(()) => Error::Spawn(error),
        })?;
    Ok(PendingConnect {
        task,
        cancel,
        progress: Progress::Running,
    })
}
