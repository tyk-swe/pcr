// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Source;

use super::{Task, Waited, shared};

static SHARED_REAPER: OnceLock<Result<ReaperService, ReaperStartError>> = OnceLock::new();

type SharedReceiver = Arc<Mutex<mpsc::Receiver<ReapTask>>>;

#[derive(Clone)]
pub(crate) struct ReaperClient {
    tasks: SyncSender<ReapTask>,
    retained_tasks: Arc<AtomicUsize>,
}

struct ReaperService {
    client: ReaperClient,
    _workers: Vec<JoinHandle<()>>,
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("start shared native worker reaper failed")]
pub(crate) struct ReaperStartError {
    #[source]
    source: Source,
}

pub(crate) type ReapTask = Box<dyn FnOnce() + Send + 'static>;

/// A nudge can arrive before the worker blocks, so it is repeated every `poll_interval`.
pub(crate) fn wait_until_finished(
    task: Task<()>,
    poll_interval: Duration,
    mut on_poll: impl FnMut(),
) {
    let mut task = task;
    loop {
        on_poll();
        match task.wait(&Deadline::new(poll_interval)) {
            Waited::Finished(_) => return,
            Waited::Pending(pending) => task = pending,
        }
    }
}

impl ReaperClient {
    /// If admission fails, leaks the task so native state outlives workers that may still use it.
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
        .get_or_init(|| start_reaper(shared().capacity(), spawn_reaper_thread))
        .as_ref()
        .map(|service| service.client.clone())
        .map_err(Clone::clone)
}

fn start_reaper(
    capacity: usize,
    mut spawn: impl FnMut(SharedReceiver) -> std::io::Result<JoinHandle<()>>,
) -> Result<ReaperService, ReaperStartError> {
    // The channel and threads match pool capacity, so every admitted worker can be reaped.
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
                    source: Source::new(error),
                });
            }
        }
    }
    Ok(ReaperService {
        client: ReaperClient {
            tasks,
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
        // A defective cleanup task must not kill the shared receiver.
        let _ = catch_unwind(AssertUnwindSafe(task));
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn client_with_receiver(
        queue_capacity: usize,
    ) -> (ReaperClient, mpsc::Receiver<ReapTask>) {
        let (tasks, receiver) = mpsc::sync_channel(queue_capacity);
        (
            ReaperClient {
                tasks,
                retained_tasks: Arc::new(AtomicUsize::new(0)),
            },
            receiver,
        )
    }

    pub(crate) fn start_with(
        capacity: usize,
        spawn: impl FnMut(SharedReceiver) -> std::io::Result<JoinHandle<()>>,
    ) -> Result<ReaperClient, ReaperStartError> {
        start_reaper(capacity, spawn).map(|service| service.client)
    }

    pub(crate) fn retained_tasks(client: &ReaperClient) -> usize {
        client.retained_tasks.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::super::{Class, Pool};
    use super::test_support::*;
    use super::*;

    #[test]
    fn reaper_creation_failure_is_fallible() {
        let result = start_with(1, |_| Err(io::Error::other("injected spawn failure")));
        let error = match result {
            Ok(_) => panic!("injected reaper spawn must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "start shared native worker reaper failed"
        );
        assert_eq!(
            packetcraftr_core::error::render(&error),
            "start shared native worker reaper failed: injected spawn failure"
        );
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
        let (client, _receiver) = client_with_receiver(1);
        client.transfer(Box::new(|| {}));
        client.transfer(Box::new(|| {}));
        assert_eq!(retained_tasks(&client), 1);
    }

    #[test]
    fn dead_receiver_retains_complete_task_without_panicking() {
        let (client, receiver) = client_with_receiver(1);
        drop(receiver);
        client.transfer(Box::new(|| {}));
        assert_eq!(retained_tasks(&client), 1);
    }

    #[test]
    fn stalled_task_does_not_block_later_cleanup() {
        let pool = Arc::new(Pool::new(2, 2));
        let client = start_with(2, spawn_reaper_thread).expect("start test reaper");
        let first_permit = pool.admit(Class::Native).expect("first admission");
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

        let second_permit = pool.admit(Class::Native).expect("second admission");
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
