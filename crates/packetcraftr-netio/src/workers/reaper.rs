// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, OnceLock,
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
        client: ReaperClient { tasks },
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
