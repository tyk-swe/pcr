// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        mpsc::{self, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
};

#[cfg(native_layer2)]
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Source;
#[cfg(native_layer2)]
use std::{sync::LazyLock, time::Duration};

#[cfg(native_layer2)]
use super::{Task, Waited, shared};

#[cfg(native_layer2)]
static SHARED_REAPER: LazyLock<Result<ReaperService, ReaperStartError>> =
    LazyLock::new(|| start_reaper(shared().capacity(), spawn_reaper_thread));

type SharedReceiver = Arc<Mutex<mpsc::Receiver<ReapTask>>>;

#[derive(Clone)]
pub(crate) struct ReaperClient {
    tasks: SyncSender<ReapTask>,
}

pub(crate) struct ReaperService {
    client: ReaperClient,
    _workers: Vec<JoinHandle<()>>,
}

#[derive(Clone, Debug, thiserror::Error)]
#[error("start shared native worker reaper failed")]
pub(crate) struct ReaperStartError {
    #[source]
    source: Source,
}

impl From<std::io::Error> for ReaperStartError {
    fn from(error: std::io::Error) -> Self {
        Self {
            source: Source::new(error),
        }
    }
}

impl ReaperService {
    pub(crate) fn client(&self) -> ReaperClient {
        self.client.clone()
    }
}

pub(crate) fn retirement_service(capacity: usize) -> Result<ReaperService, ReaperStartError> {
    start_reaper(capacity, spawn_reaper_thread)
}

pub(crate) type ReapTask = Box<dyn FnOnce() + Send + 'static>;

/// A nudge can arrive before the worker blocks, so it is repeated every `poll_interval`.
#[cfg(native_layer2)]
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
    /// The caller retains ownership on every refusal.
    pub(crate) fn try_transfer(&self, task: ReapTask) -> Result<(), ReapTask> {
        self.tasks.try_send(task).map_err(|error| match error {
            TrySendError::Full(task) | TrySendError::Disconnected(task) => task,
        })
    }

    /// If admission fails, leaks the task so native state outlives workers that may still use it.
    #[cfg(native_layer2)]
    pub(crate) fn transfer(&self, task: ReapTask) {
        if let Err(task) = self.try_transfer(task) {
            self.retain(task);
        }
    }

    #[cfg(native_layer2)]
    fn retain(&self, task: ReapTask) {
        std::mem::forget(task);
    }
}

#[cfg(native_layer2)]
pub(crate) fn shared_reaper() -> Result<ReaperClient, ReaperStartError> {
    SHARED_REAPER
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
