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
    time::Duration,
};

use super::{Exhausted, PermitPool, WorkerPermit, shared_budget};

static SHARED_REAPER: OnceLock<Result<ReaperService, ReaperStartError>> = OnceLock::new();

type SharedReceiver = Arc<Mutex<mpsc::Receiver<ReapTask>>>;

#[derive(Clone)]
pub(crate) struct ReaperClient {
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

/// Shared rather than boxed so [`shared_reaper`] can clone the startup
/// failure out of its `OnceLock` — a live-I/O failure then retains this as
/// its typed source instead of formatting it into a message.
#[derive(Clone, Debug)]
pub(crate) struct ReaperStartError {
    source: Arc<std::io::Error>,
}

impl fmt::Display for ReaperStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "start shared native worker reaper failed: {}",
            self.source
        )
    }
}

impl std::error::Error for ReaperStartError {
    /// The original `std::io::Error` itself, so `raw_os_error()` and the
    /// error's own chain stay reachable through `source()`.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.source)
    }
}

pub(crate) type ReapTask = Box<dyn FnOnce() + Send + 'static>;

/// Blocks until `worker` finishes, calling `on_poll` before every wait so a
/// cleanup task can keep nudging a blocked worker.
pub(crate) fn wait_until_finished(
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
    pub(crate) fn reserve(&self) -> Result<WorkerPermit, Exhausted> {
        self.permits.reserve()
    }

    /// Transfers `task` without blocking. If admission fails, retains the
    /// entire closure and its resources, leaking a bounded reservation to keep
    /// native state alive for workers that may still access it.
    pub(crate) fn transfer(&self, task: ReapTask) {
        if let Err(TrySendError::Full(task) | TrySendError::Disconnected(task)) =
            self.tasks.try_send(task)
        {
            self.retain(task);
        }
    }

    fn retain(&self, task: ReapTask) {
        let _ = self
            .retained_tasks
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            });
        std::mem::forget(task);
    }
}

pub(crate) fn shared_reaper() -> Result<ReaperClient, ReaperStartError> {
    SHARED_REAPER
        .get_or_init(|| start_reaper(shared_budget(), spawn_reaper_thread))
        .as_ref()
        .map(|service| service.client.clone())
        .map_err(Clone::clone)
}

fn start_reaper(
    permits: Arc<PermitPool>,
    mut spawn: impl FnMut(SharedReceiver) -> std::io::Result<JoinHandle<()>>,
) -> Result<ReaperService, ReaperStartError> {
    // The permit capacity bounds the native workers that may concurrently
    // hold a cleanup reservation. The channel and cleanup pool have the same
    // capacity, so every reserved worker can be transferred and reaped
    // independently.
    let capacity = permits.capacity;
    let (tasks, receiver) = mpsc::sync_channel(capacity);
    let receiver = Arc::new(Mutex::new(receiver));
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
                    source: Arc::new(error),
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
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn client_with_receiver(
        queue_capacity: usize,
        permit_capacity: usize,
    ) -> (ReaperClient, mpsc::Receiver<ReapTask>) {
        let (tasks, receiver) = mpsc::sync_channel(queue_capacity);
        (
            ReaperClient {
                tasks,
                permits: Arc::new(PermitPool::new(permit_capacity)),
                retained_tasks: Arc::new(AtomicUsize::new(0)),
            },
            receiver,
        )
    }

    pub(crate) fn start_with(
        capacity: usize,
        spawn: impl FnMut(SharedReceiver) -> std::io::Result<JoinHandle<()>>,
    ) -> Result<ReaperClient, ReaperStartError> {
        start_reaper(Arc::new(PermitPool::new(capacity)), spawn).map(|service| service.client)
    }

    pub(crate) fn retained_tasks(client: &ReaperClient) -> usize {
        client.retained_tasks.load(Ordering::Relaxed)
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
    fn reaper_start_failure_exposes_the_os_error_source() {
        let result = start_with(1, |_| Err(io::Error::from_raw_os_error(13)));
        let error = match result {
            Ok(_) => panic!("injected reaper spawn must fail"),
            Err(error) => error,
        };
        let source = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<io::Error>())
            .expect("the retained source is the original io error");
        assert_eq!(source.raw_os_error(), Some(13));
    }

    #[test]
    fn queue_saturation_retains_complete_task_without_panicking() {
        let (client, _receiver) = client_with_receiver(1, 1);
        client.transfer(Box::new(|| {}));
        client.transfer(Box::new(|| {}));
        assert_eq!(retained_tasks(&client), 1);
    }

    #[test]
    fn dead_receiver_retains_complete_task_without_panicking() {
        let (client, receiver) = client_with_receiver(1, 1);
        drop(receiver);
        client.transfer(Box::new(|| {}));
        assert_eq!(retained_tasks(&client), 1);
    }

    #[test]
    fn reservations_bound_all_cleanup_liabilities() {
        let (client, _receiver) = client_with_receiver(1, 1);
        let permit = client.reserve().expect("one reservation");
        assert_eq!(client.reserve().map(|_| ()), Err(Exhausted { capacity: 1 }));
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
        client.transfer(Box::new(move || {
            let _permit = first_permit;
            first_started.send(()).expect("report first task start");
            let _ = release_first_receiver.recv();
            first_finished.send(()).expect("report first task finish");
        }));
        first_started_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("first cleanup task starts");

        let second_permit = client.reserve().expect("second cleanup reservation");
        let (second_finished, second_finished_receiver) = mpsc::channel();
        client.transfer(Box::new(move || {
            let _permit = second_permit;
            second_finished.send(()).expect("report second task finish");
        }));
        second_finished_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("later cleanup completes while first task is stalled");

        release_first.send(()).expect("release first cleanup task");
        first_finished_receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("first cleanup eventually completes");
    }
}
