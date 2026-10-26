// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    any::Any,
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Condvar, Mutex, PoisonError, mpsc::SyncSender},
    time::{Duration, Instant},
};

use packetcraftr_core::budget::Deadline;
use rtnetlink::Handle;

use crate::{
    deadline::{POLL_INTERVAL, remaining_before},
    route,
};

use super::{lock, wait_remaining};

pub(super) const NETLINK_QUEUE_DEPTH: usize = crate::workers::CAPACITY;
const IDLE_RETIREMENT: Duration = Duration::from_millis(250);

type OperationResult = Result<Box<dyn Any + Send>, route::Error>;
type OperationFuture = Pin<Box<dyn Future<Output = OperationResult> + Send>>;
type Operation = Box<dyn FnOnce(Handle) -> OperationFuture + Send>;

pub(super) struct NetlinkRequest {
    pub(super) operation: Operation,
    pub(super) respond: SyncSender<OperationResult>,
    pub(super) deadline: Instant,
    pub(super) control: Arc<Deadline>,
}

pub(super) struct Inbox {
    state: Mutex<InboxState>,
    changed: Condvar,
}

struct InboxState {
    queue: VecDeque<NetlinkRequest>,
    serving: bool,
    owned: bool,
    active: bool,
}

pub(super) enum Refused {
    Retired(NetlinkRequest),
    Stopped(NetlinkRequest),
    Interrupted(route::Error),
}

impl Inbox {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(InboxState {
                queue: VecDeque::new(),
                serving: true,
                owned: true,
                active: false,
            }),
            changed: Condvar::new(),
        }
    }

    pub(super) fn submit(
        &self,
        request: NetlinkRequest,
        caller: &Deadline,
        deadline: Instant,
    ) -> Result<(), Refused> {
        let mut state = lock(&self.state);
        loop {
            let remaining = wait_remaining(caller, deadline, "submitting the netlink request")
                .map_err(Refused::Interrupted)?;
            if !state.serving {
                return Err(if state.owned {
                    Refused::Stopped(request)
                } else {
                    Refused::Retired(request)
                });
            }
            if state.queue.len() < NETLINK_QUEUE_DEPTH {
                state.queue.push_back(request);
                self.changed.notify_all();
                return Ok(());
            }
            // The caller's cancellation has no waker, so the wait is sliced to notice it.
            state = self
                .changed
                .wait_timeout(state, remaining.min(POLL_INTERVAL))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    pub(super) fn next(&self) -> Option<NetlinkRequest> {
        self.next_with_idle(IDLE_RETIREMENT)
    }

    pub(super) fn next_with_idle(&self, idle: Duration) -> Option<NetlinkRequest> {
        let mut state = lock(&self.state);
        let expires = Instant::now() + idle;
        loop {
            if let Some(request) = state.queue.pop_front() {
                state.active = true;
                self.changed.notify_all();
                return Some(request);
            }
            if !state.owned {
                return None;
            }
            let Some(remaining) = remaining_before(expires) else {
                // Submission and retirement hold this same lock: a request is
                // either queued on a reachable worker or returned undelivered.
                state.serving = false;
                state.owned = false;
                self.changed.notify_all();
                return None;
            };
            state = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    pub(super) fn retire_if_idle(&self) -> bool {
        let mut state = lock(&self.state);
        if state.active || !state.queue.is_empty() {
            return false;
        }
        state.serving = false;
        state.owned = false;
        self.changed.notify_all();
        true
    }

    pub(super) fn complete_request(&self) {
        lock(&self.state).active = false;
        self.changed.notify_all();
    }

    pub(super) fn abandon(&self) {
        lock(&self.state).owned = false;
        self.changed.notify_all();
    }

    #[cfg(test)]
    pub(super) fn serving(&self) -> bool {
        lock(&self.state).serving
    }

    #[cfg(test)]
    pub(super) fn active(&self) -> bool {
        lock(&self.state).active
    }

    #[cfg(test)]
    pub(super) fn queued(&self) -> usize {
        lock(&self.state).queue.len()
    }

    pub(super) fn stop(&self) {
        let queued = {
            let mut state = lock(&self.state);
            state.serving = false;
            std::mem::take(&mut state.queue)
        };
        self.changed.notify_all();
        drop(queued);
    }
}

pub(super) struct RequestInFlight<'a>(pub(super) &'a Inbox);

impl Drop for RequestInFlight<'_> {
    fn drop(&mut self) {
        self.0.complete_request();
    }
}

pub(super) struct StopOnExit<'a>(pub(super) &'a Inbox);

impl Drop for StopOnExit<'_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}
