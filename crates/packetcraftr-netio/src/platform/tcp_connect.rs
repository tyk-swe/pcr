// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Process-wide admission for portable TCP connection workers and their sockets.

use crate::tcp::{ConnectError, ConnectOutcome, Connection, Provider};
use packetcraftr_core::budget::Cancellation;
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime},
};

#[derive(Default)]
struct State {
    active: usize,
    retained: usize,
    rejected: usize,
}
static STATE: Mutex<State> = Mutex::new(State {
    active: 0,
    retained: 0,
    rejected: 0,
});

pub(crate) struct Lease {
    retained: AtomicBool,
}
impl Lease {
    fn retain(&self) {
        let mut state = STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.retained.swap(true, Ordering::Relaxed) {
            state.retained += 1;
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active -= 1;
        if self.retained.load(Ordering::Relaxed) {
            state.retained -= 1;
        }
    }
}
fn reserve() -> Result<Arc<Lease>, ConnectError> {
    let mut state = STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.active >= crate::tcp::MAX_PENDING_CONNECTIONS {
        state.rejected = state.rejected.saturating_add(1);
        return Err(ConnectError::Capacity {
            limit: crate::tcp::MAX_PENDING_CONNECTIONS,
        });
    }
    state.active += 1;
    Ok(Arc::new(Lease {
        retained: AtomicBool::new(false),
    }))
}
pub(super) fn snapshot() -> crate::resources::NativeSnapshot {
    let state = STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    crate::resources::NativeSnapshot {
        supported: true,
        capacity: crate::tcp::MAX_PENDING_CONNECTIONS,
        active: state.active,
        rejected_admissions: state.rejected,
        cleanup_retaining_capacity: state.retained,
    }
}

#[derive(Default)]
struct CancelState {
    cancelled: bool,
    attempted: bool,
}

pub(crate) struct Pending<S> {
    receiver: mpsc::Receiver<ConnectOutcome<S>>,
    worker: Option<JoinHandle<()>>,
    cancel: Arc<Mutex<CancelState>>,
    lease: Weak<Lease>,
    complete: bool,
}
impl<S> Pending<S> {
    pub(crate) fn cancel(&mut self) -> bool {
        let mut state = self
            .cancel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.cancelled = true;
        state.attempted
    }

    pub(crate) fn poll(&mut self) -> Result<Option<ConnectOutcome<S>>, ConnectError> {
        if self.complete {
            return Err(ConnectError::Completed);
        }
        match self.receiver.try_recv() {
            Ok(result) => {
                self.complete = true;
                Ok(Some(result))
            }
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(ConnectError::Worker),
        }
    }
}
impl<S> Drop for Pending<S> {
    fn drop(&mut self) {
        self.cancel();
        if !self.complete
            && let Some(lease) = self.lease.upgrade()
        {
            lease.retain();
        }
        if let Some(worker) = self.worker.take()
            && worker.is_finished()
        {
            let _ = worker.join();
        }
        // A running worker keeps its lease through provider cleanup. Queued
        // successful connections own the same lease until their socket closes.
    }
}

pub(super) fn start<P>(
    provider: Arc<P>,
    endpoint: SocketAddr,
    timeout: Duration,
    cancellation: Option<Cancellation>,
) -> Result<Pending<P::Stream>, ConnectError>
where
    P: Provider + Send + Sync + 'static,
    P::Stream: Send + 'static,
{
    if timeout.is_zero() || timeout > crate::capture::MAX_TIMEOUT {
        return Err(ConnectError::Timeout);
    }
    if let Some(signal) = &cancellation {
        signal.check()?;
    }
    let started = Instant::now();
    let started_at = SystemTime::now();
    let deadline = started.checked_add(timeout).ok_or(ConnectError::Timeout)?;
    let lease = reserve()?;
    let marker = Arc::downgrade(&lease);
    let cancel = Arc::new(Mutex::new(CancelState::default()));
    let cancelled = Arc::clone(&cancel);
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("packetcraftr-tcp-connect".to_owned())
        .spawn(move || {
            // Provider/stream cleanup must precede releasing native admission,
            // including unwinding and receiver cancellation paths.
            let admission = lease;
            let connection_provider = provider;
            let remaining = deadline.saturating_duration_since(Instant::now());
            let attempted = {
                let mut state = cancelled
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.cancelled
                    || remaining.is_zero()
                    || cancellation
                        .as_ref()
                        .is_some_and(|signal| signal.check().is_err())
                {
                    false
                } else {
                    state.attempted = true;
                    true
                }
            };
            let result = if attempted {
                connection_provider
                    .connect(endpoint, remaining)
                    .map(|stream| Connection::new(stream, Arc::clone(&admission)))
            } else {
                Err(std::io::Error::new(
                    if remaining.is_zero() {
                        std::io::ErrorKind::TimedOut
                    } else {
                        std::io::ErrorKind::Interrupted
                    },
                    "connection stopped before provider execution",
                ))
            };
            let outcome = ConnectOutcome {
                attempted,
                started_at,
                completed_at: SystemTime::now(),
                elapsed: started.elapsed(),
                result,
            };
            let _ = sender.send(outcome);
            drop(connection_provider);
            drop(admission);
        })
        .map_err(ConnectError::Spawn)?;
    Ok(Pending {
        receiver,
        worker: Some(worker),
        cancel,
        lease: marker,
        complete: false,
    })
}
