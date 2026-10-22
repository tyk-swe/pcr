// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Root, TCP data, execution, and socket accounting for admitted native work.

use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use super::{Pool, State, lock};
use crate::resources::NativeSnapshot;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    #[cfg_attr(not(native_route), allow(dead_code))]
    Native,
    TcpConnect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("native worker admission reached its limit of {capacity}")]
pub(crate) struct Exhausted {
    pub(crate) capacity: usize,
}

#[derive(Clone, Copy, Default)]
pub(super) struct Counters {
    active: usize,
    rejected: usize,
    retained: usize,
}

impl State {
    fn counters(&mut self, class: Class) -> impl Iterator<Item = &mut Counters> {
        let tcp = (class == Class::TcpConnect).then_some(&mut self.tcp);
        std::iter::once(&mut self.all).chain(tcp)
    }
}

impl Pool {
    pub(crate) fn snapshot(&self) -> NativeSnapshot {
        Self::sample(self.capacity, lock(&self.state).all)
    }

    pub(crate) fn tcp_snapshot(&self) -> NativeSnapshot {
        Self::sample(self.data_capacity, lock(&self.state).tcp)
    }

    pub(crate) fn execution_snapshot(&self) -> NativeSnapshot {
        Self::sample(self.capacity, lock(&self.state).execution)
    }

    pub(crate) fn socket_snapshot(&self) -> NativeSnapshot {
        Self::sample(self.data_capacity, lock(&self.state).sockets)
    }

    fn sample(capacity: usize, counters: Counters) -> NativeSnapshot {
        NativeSnapshot {
            supported: true,
            capacity,
            active: counters.active,
            rejected_admissions: counters.rejected,
            cleanup_retaining_capacity: counters.retained,
        }
    }

    pub(crate) fn admit(self: &Arc<Self>) -> Result<Permit, Exhausted> {
        self.admit_class(Class::Native)
    }

    pub(crate) fn admit_connect(self: &Arc<Self>) -> Result<ConnectPermit, Exhausted> {
        self.admit_class(Class::TcpConnect).map(ConnectPermit)
    }

    fn admit_class(self: &Arc<Self>, class: Class) -> Result<Permit, Exhausted> {
        let mut state = lock(&self.state);
        let refused = state.all.active >= self.capacity
            || (class == Class::TcpConnect && state.tcp.active >= self.data_capacity);
        for counters in state.counters(class) {
            if refused {
                counters.rejected = counters.rejected.saturating_add(1);
            } else {
                counters.active += 1;
            }
        }
        if refused {
            state.execution.rejected = state.execution.rejected.saturating_add(1);
            return Err(Exhausted {
                capacity: if class == Class::TcpConnect {
                    self.data_capacity
                } else {
                    self.capacity
                },
            });
        }
        state.execution.active += 1;
        Ok(Permit {
            root: RootLease(Arc::new(Grant {
                marker: RetentionMarker {
                    pool: Arc::clone(self),
                    class,
                    phase: Arc::new(AtomicU8::new(EXECUTING)),
                },
            })),
        })
    }

    pub(super) fn finish_admission(&self, permit: RootLease) {
        let mut state = lock(&self.state);
        permit.0.marker.finish_execution(&mut state);
        if let Some(grant) = Arc::into_inner(permit.0) {
            grant.marker.release(&mut state);
        }
    }
}

// Bit flags; every transition occurs under the pool state lock. A connect may
// briefly own both execution and its socket, but holds its root/data charge once.
const EXECUTING: u8 = 1;
const SOCKET: u8 = 2;
const RETAINED: u8 = 4;
const RELEASED: u8 = 8;

/// One admitted execution, consumed when its only job is dispatched.
pub(crate) struct Permit {
    pub(super) root: RootLease,
}

/// One admitted TCP connection attempt, consumed when its only job is dispatched.
pub(crate) struct ConnectPermit(Permit);

/// Keeps a root slot charged without granting execution or socket promotion.
#[derive(Clone)]
pub(crate) struct RootLease(Arc<Grant>);

/// The sole socket promotion right for one admitted TCP connection attempt.
pub(crate) struct SocketReservation(RootLease);

/// An established socket's root/data ownership, without execution admission.
pub(crate) struct SocketPermit {
    _root: RootLease,
}

struct Grant {
    marker: RetentionMarker,
}

#[derive(Clone)]
pub(crate) struct RetentionMarker {
    pool: Arc<Pool>,
    class: Class,
    phase: Arc<AtomicU8>,
}

impl RetentionMarker {
    pub(crate) fn mark_retained(&self) {
        let mut state = lock(&self.pool.state);
        let phase = self.phase.load(Ordering::Relaxed);
        if phase & (RETAINED | RELEASED) == 0 {
            self.phase.store(phase | RETAINED, Ordering::Relaxed);
            for counters in state.counters(self.class) {
                counters.retained += 1;
            }
            if phase & EXECUTING != 0 {
                state.execution.retained += 1;
            }
            if phase & SOCKET != 0 {
                state.sockets.retained += 1;
            }
        }
    }

    fn finish_execution(&self, state: &mut State) {
        let phase = self.phase.load(Ordering::Relaxed);
        if phase & EXECUTING != 0 {
            state.execution.active -= 1;
            if phase & RETAINED != 0 {
                state.execution.retained -= 1;
            }
            self.phase.store(phase & !EXECUTING, Ordering::Relaxed);
        }
    }

    fn release(&self, state: &mut State) {
        self.finish_execution(state);
        let previous = self.phase.swap(RELEASED, Ordering::Relaxed);
        if previous == RELEASED {
            return;
        }
        for counters in state.counters(self.class) {
            counters.active -= 1;
            if previous & RETAINED != 0 {
                counters.retained -= 1;
            }
        }
        if previous & SOCKET != 0 {
            state.sockets.active -= 1;
            if previous & RETAINED != 0 {
                state.sockets.retained -= 1;
            }
        }
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        // `Pool::finish_admission` releases under its own lock; the phase is final then.
        if self.marker.phase.load(Ordering::Relaxed) != RELEASED {
            let mut state = lock(&self.marker.pool.state);
            self.marker.release(&mut state);
        }
    }
}

impl SocketReservation {
    /// Transfer root/data ownership to the socket without acquiring another root
    /// slot. The worker keeps execution admission until its job actually ends.
    pub(crate) fn into_socket(self) -> SocketPermit {
        let marker = &self.0.0.marker;
        let mut state = lock(&marker.pool.state);
        let phase = marker.phase.load(Ordering::Relaxed);
        marker.phase.store(phase | SOCKET, Ordering::Relaxed);
        state.sockets.active += 1;
        if phase & RETAINED != 0 {
            state.sockets.retained += 1;
        }
        drop(state);
        SocketPermit { _root: self.0 }
    }
}

impl RootLease {
    pub(crate) fn retention_marker(&self) -> RetentionMarker {
        self.0.marker.clone()
    }
}

impl Permit {
    pub(crate) fn lease(&self) -> RootLease {
        self.root.clone()
    }

    pub(crate) fn retention_marker(&self) -> RetentionMarker {
        self.root.retention_marker()
    }

    pub(super) fn pool(&self) -> &Arc<Pool> {
        &self.root.0.marker.pool
    }
}

impl ConnectPermit {
    /// Splits the attempt into its execution permit and its single socket promotion right.
    pub(super) fn into_parts(self) -> (Permit, SocketReservation) {
        let reservation = SocketReservation(self.0.lease());
        (self.0, reservation)
    }
}
