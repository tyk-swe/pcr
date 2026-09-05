// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared bounded ownership service for native workers that miss shutdown.

use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// The maximum number of native workers that may concurrently hold a cleanup
/// reservation. The channel and cleanup pool have the same capacity, so every
/// reserved worker can be transferred and reaped independently.
const REAPER_CAPACITY: usize = 16;

static SHARED_REAPER: OnceLock<Result<ReaperService, ReaperStartError>> = OnceLock::new();

type SharedReceiver = Arc<Mutex<mpsc::Receiver<ReapTask>>>;

#[derive(Clone)]
pub(super) struct ReaperClient {
    tasks: SyncSender<ReapTask>,
    permits: Arc<PermitPool>,
    retained_tasks: Arc<AtomicUsize>,
}

struct ReaperService {
    client: ReaperClient,
    // The service lives for the process lifetime; retaining the handles keeps
    // the threads owned rather than detached.
    _workers: Vec<JoinHandle<()>>,
}

#[derive(Clone, Debug)]
pub(super) struct ReaperStartError {
    message: Arc<str>,
}

impl fmt::Display for ReaperStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

/// So a live-I/O failure can retain this as its typed source instead of
/// formatting it into a message.
impl std::error::Error for ReaperStartError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReaperExhausted {
    pub capacity: usize,
}

pub(super) struct ReaperPermit {
    pool: Arc<PermitPool>,
}

struct PermitPool {
    capacity: usize,
    available: Mutex<usize>,
}

pub(super) type ReapTask = Box<dyn FnOnce() + Send + 'static>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TransferOutcome {
    Queued,
    RetainedQueueFull,
    RetainedReaperStopped,
}

/// Outcome of waiting for a worker thread within a deadline.
pub(super) enum JoinAttempt {
    Finished(thread::Result<()>),
    /// The deadline expired first, so the still-running worker is handed back
    /// to its owner rather than detached.
    TimedOut(JoinHandle<()>),
}

/// Waits for `worker` to finish, polling every `poll_interval`, and hands the
/// handle back if `timeout` expires first.
pub(super) fn join_with_deadline(
    worker: JoinHandle<()>,
    timeout: Duration,
    poll_interval: Duration,
) -> JoinAttempt {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return JoinAttempt::TimedOut(worker);
    };
    while !worker.is_finished() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return JoinAttempt::TimedOut(worker);
        };
        thread::park_timeout(remaining.min(poll_interval));
    }
    // `is_finished` is monotonic: once true, joining cannot block on a worker
    // that is still running.
    JoinAttempt::Finished(worker.join())
}

/// Blocks until `worker` finishes, calling `on_poll` before every wait so a
/// cleanup task can keep nudging a blocked worker.
pub(super) fn wait_until_finished(
    worker: JoinHandle<()>,
    poll_interval: Duration,
    mut on_poll: impl FnMut(),
) {
    while !worker.is_finished() {
        on_poll();
        thread::park_timeout(poll_interval);
    }
    let _ = worker.join();
}

impl ReaperClient {
    pub(super) fn reserve(&self) -> Result<ReaperPermit, ReaperExhausted> {
        let mut available = self
            .permits
            .available
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(next) = available.checked_sub(1) else {
            return Err(ReaperExhausted {
                capacity: self.permits.capacity,
            });
        };
        *available = next;
        Ok(ReaperPermit {
            pool: Arc::clone(&self.permits),
        })
    }

    /// Transfers `task` without blocking. If the bounded service cannot accept
    /// it, the complete closure and every resource it owns are deliberately
    /// retained. This catastrophic fallback leaks a bounded reservation rather
    /// than partially dropping native state that a worker may still access.
    #[must_use]
    pub(super) fn transfer(&self, task: ReapTask) -> TransferOutcome {
        match self.tasks.try_send(task) {
            Ok(()) => TransferOutcome::Queued,
            Err(TrySendError::Full(task)) => {
                self.retain(task);
                TransferOutcome::RetainedQueueFull
            }
            Err(TrySendError::Disconnected(task)) => {
                self.retain(task);
                TransferOutcome::RetainedReaperStopped
            }
        }
    }

    fn retain(&self, task: ReapTask) {
        let _ = self
            .retained_tasks
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            });
        std::mem::forget(task);
    }
}

impl Drop for ReaperPermit {
    fn drop(&mut self) {
        let mut available = self
            .pool
            .available
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(next) = available.checked_add(1)
            && next <= self.pool.capacity
        {
            *available = next;
        }
    }
}

pub(super) fn shared_reaper() -> Result<ReaperClient, ReaperStartError> {
    SHARED_REAPER
        .get_or_init(|| start_reaper(REAPER_CAPACITY, spawn_reaper_thread))
        .as_ref()
        .map(|service| service.client.clone())
        .map_err(Clone::clone)
}

fn start_reaper(
    capacity: usize,
    mut spawn: impl FnMut(SharedReceiver) -> std::io::Result<JoinHandle<()>>,
) -> Result<ReaperService, ReaperStartError> {
    let (tasks, receiver) = mpsc::sync_channel(capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    let permits = Arc::new(PermitPool {
        capacity,
        available: Mutex::new(capacity),
    });
    let retained_tasks = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::with_capacity(capacity);
    for _ in 0..capacity {
        match spawn(Arc::clone(&receiver)) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                drop(tasks);
                for worker in workers {
                    let _ = worker.join();
                }
                return Err(ReaperStartError {
                    message: Arc::from(format!(
                        "start shared native worker reaper failed: {error}"
                    )),
                });
            }
        }
    }
    Ok(ReaperService {
        client: ReaperClient {
            tasks,
            permits,
            retained_tasks,
        },
        _workers: workers,
    })
}

fn spawn_reaper_thread(receiver: SharedReceiver) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("packetcraftr-native-reaper".to_owned())
        .spawn(move || run_reaper(receiver))
}

fn run_reaper(receiver: SharedReceiver) {
    loop {
        let task = receiver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .recv();
        let Ok(task) = task else {
            return;
        };
        // A defective cleanup task must not kill the shared receiver and strand
        // all later ownership transfers.
        let _ = catch_unwind(AssertUnwindSafe(task));
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;

    pub(in crate::platform) fn client_with_receiver(
        queue_capacity: usize,
        permit_capacity: usize,
    ) -> (ReaperClient, mpsc::Receiver<ReapTask>) {
        let (tasks, receiver) = mpsc::sync_channel(queue_capacity);
        (
            ReaperClient {
                tasks,
                permits: Arc::new(PermitPool {
                    capacity: permit_capacity,
                    available: Mutex::new(permit_capacity),
                }),
                retained_tasks: Arc::new(AtomicUsize::new(0)),
            },
            receiver,
        )
    }

    pub(in crate::platform) fn start_with(
        capacity: usize,
        spawn: impl FnMut(SharedReceiver) -> std::io::Result<JoinHandle<()>>,
    ) -> Result<ReaperClient, ReaperStartError> {
        start_reaper(capacity, spawn).map(|service| service.client)
    }

    pub(in crate::platform) fn retained_tasks(client: &ReaperClient) -> usize {
        client.retained_tasks.load(Ordering::Relaxed)
    }

    pub(super) const fn production_capacity() -> usize {
        REAPER_CAPACITY
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::test_support::*;
    use super::*;

    #[test]
    fn reaper_creation_failure_is_fallible() {
        let result = start_with(1, |_| Err(io::Error::other("injected spawn failure")));
        let error = match result {
            Ok(_) => panic!("injected reaper spawn must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("injected spawn failure"));
    }

    #[test]
    fn queue_saturation_retains_complete_task_without_panicking() {
        let (client, _receiver) = client_with_receiver(1, 1);
        assert_eq!(client.transfer(Box::new(|| {})), TransferOutcome::Queued);
        assert_eq!(
            client.transfer(Box::new(|| {})),
            TransferOutcome::RetainedQueueFull
        );
        assert_eq!(retained_tasks(&client), 1);
    }

    #[test]
    fn dead_receiver_retains_complete_task_without_panicking() {
        let (client, receiver) = client_with_receiver(1, 1);
        drop(receiver);
        assert_eq!(
            client.transfer(Box::new(|| {})),
            TransferOutcome::RetainedReaperStopped
        );
        assert_eq!(retained_tasks(&client), 1);
    }

    #[test]
    fn reservations_bound_all_cleanup_liabilities() {
        assert_eq!(production_capacity(), REAPER_CAPACITY);
        let (client, _receiver) = client_with_receiver(1, 1);
        let permit = client.reserve().expect("one reservation");
        assert_eq!(
            client.reserve().map(|_| ()),
            Err(ReaperExhausted { capacity: 1 })
        );
        drop(permit);
        assert!(client.reserve().is_ok());
    }

    #[test]
    fn stalled_task_does_not_block_later_cleanup() {
        let client = start_with(2, spawn_reaper_thread).expect("start test reaper");
        let first_permit = client.reserve().expect("first cleanup reservation");
        let (first_started, first_started_receiver) = mpsc::channel();
        let (release_first, release_first_receiver) = mpsc::channel();
        let (first_finished, first_finished_receiver) = mpsc::channel();
        assert_eq!(
            client.transfer(Box::new(move || {
                let _permit = first_permit;
                first_started.send(()).expect("report first task start");
                let _ = release_first_receiver.recv();
                first_finished.send(()).expect("report first task finish");
            })),
            TransferOutcome::Queued
        );
        first_started_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("first cleanup task starts");

        let second_permit = client.reserve().expect("second cleanup reservation");
        let (second_finished, second_finished_receiver) = mpsc::channel();
        assert_eq!(
            client.transfer(Box::new(move || {
                let _permit = second_permit;
                second_finished.send(()).expect("report second task finish");
            })),
            TransferOutcome::Queued
        );
        second_finished_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("later cleanup completes while first task is stalled");

        release_first.send(()).expect("release first cleanup task");
        first_finished_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("first cleanup eventually completes");
    }
}
