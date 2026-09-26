// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Process-wide admission for portable TCP connection workers and their sockets.

use crate::tcp::{ConnectError, ConnectOutcome, Connection, Provider};
use packetcraftr_core::budget::{Deadline, Interrupted};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::{Instant, SystemTime},
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

pub(super) struct Lease {
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
pub(crate) fn snapshot() -> crate::resources::NativeSnapshot {
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

pub(super) struct Pending<S> {
    receiver: mpsc::Receiver<ConnectOutcome<S>>,
    worker: Option<JoinHandle<()>>,
    cancel: Arc<Mutex<CancelState>>,
    lease: Weak<Lease>,
    complete: bool,
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

    pub(super) fn poll(&mut self) -> Result<Option<ConnectOutcome<S>>, ConnectError> {
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
    caller: &Deadline,
) -> Result<Pending<P::Stream>, ConnectError>
where
    P: Provider + 'static,
    P::Stream: 'static,
{
    let deadline = crate::deadline::detach(caller).map_err(|interrupted| match interrupted {
        Interrupted::Cancelled(cancelled) => ConnectError::Cancelled(cancelled),
        _ => ConnectError::DeadlineExceeded,
    })?;
    if deadline.limit() > crate::capture::MAX_TIMEOUT {
        return Err(ConnectError::Timeout);
    }
    let started = Instant::now();
    let started_at = SystemTime::now();
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
            let admitted = {
                let mut state = cancelled
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let admitted = if state.cancelled {
                    Err(not_started(std::io::ErrorKind::Interrupted))
                } else {
                    crate::deadline::remaining(&deadline)
                        .map(drop)
                        .map_err(|interrupted| {
                            not_started(match interrupted {
                                Interrupted::Cancelled(_) => std::io::ErrorKind::Interrupted,
                                _ => std::io::ErrorKind::TimedOut,
                            })
                        })
                };
                state.attempted = admitted.is_ok();
                admitted
            };
            let attempted = admitted.is_ok();
            let result = admitted.and_then(|()| {
                connection_provider
                    .connect(endpoint, &deadline)
                    .map(|stream| Connection::new(stream, Arc::clone(&admission)))
            });
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

/// The outcome of a connection the worker never handed to its provider.
fn not_started(kind: std::io::ErrorKind) -> std::io::Error {
    std::io::Error::new(kind, "connection stopped before provider execution")
}
