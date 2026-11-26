// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    collections::VecDeque,
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
use std::time::Duration;

use super::lock;
#[cfg(native_layer2)]
use super::{Task, Waited};

type SharedReceiver = Arc<Mutex<mpsc::Receiver<ReapTask>>>;
type SharedSender = Arc<Mutex<Option<SyncSender<ReapTask>>>>;
type Pending = Arc<Mutex<VecDeque<ReapTask>>>;

#[derive(Clone)]
pub(crate) struct ReaperClient {
    tasks: SharedSender,
    pending: Pending,
    capacity: usize,
}

pub(crate) struct ReaperService {
    client: ReaperClient,
    tasks: SharedSender,
    _workers: Vec<JoinHandle<()>>,
}

impl Drop for ReaperService {
    fn drop(&mut self) {
        close_sender(&self.tasks);
    }
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
    start_reaper(capacity)
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
        let sender = lock(&self.tasks).clone();
        let Some(sender) = sender else {
            return Err(task);
        };
        sender.try_send(task).map_err(|error| match error {
            TrySendError::Full(task) | TrySendError::Disconnected(task) => task,
        })
    }

    /// Retain an ownership bundle in the bounded service allocation until a
    /// reaper slot frees. Every retained bundle is backed by a corresponding
    /// native admission slot, so this cannot grow past `capacity` in practice.
    #[cfg(native_layer2)]
    pub(crate) fn transfer(&self, task: ReapTask) {
        self.retry_pending();
        if let Err(task) = self.try_transfer(task) {
            self.retain(task);
        }
    }

    #[cfg(native_layer2)]
    fn retain(&self, task: ReapTask) {
        let mut pending = lock(&self.pending);
        debug_assert!(pending.len() < self.capacity);
        pending.push_back(task);
    }

    fn retry_pending(&self) {
        for _ in 0..self.capacity {
            let mut pending = lock(&self.pending);
            let Some(task) = pending.pop_front() else {
                return;
            };
            match self.try_transfer(task) {
                Ok(()) => drop(pending),
                Err(task) => {
                    pending.push_front(task);
                    return;
                }
            }
        }
    }
}

fn start_reaper(capacity: usize) -> Result<ReaperService, ReaperStartError> {
    // The channel and threads match pool capacity, so every admitted worker can be reaped.
    let (tasks, receiver) = mpsc::sync_channel(capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    let tasks = Arc::new(Mutex::new(Some(tasks)));
    let client = ReaperClient {
        tasks: Arc::clone(&tasks),
        pending: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
        capacity,
    };
    let mut workers = Vec::with_capacity(capacity);
    for _ in 0..capacity {
        match spawn_reaper_thread(Arc::clone(&receiver), client.clone()) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                close_sender(&tasks);
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
        client,
        tasks,
        _workers: workers,
    })
}

fn spawn_reaper_thread(
    receiver: SharedReceiver,
    client: ReaperClient,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("packetcraftr-native-reaper".to_owned())
        .spawn(move || run_reaper(receiver, client))
}

fn run_reaper(receiver: SharedReceiver, client: ReaperClient) {
    loop {
        client.retry_pending();
        let task = lock(&receiver).recv();
        let Ok(task) = task else {
            return;
        };
        // A defective cleanup task must not kill the shared receiver.
        let _ = catch_unwind(AssertUnwindSafe(task));
        client.retry_pending();
    }
}

fn close_sender(tasks: &SharedSender) {
    lock(tasks).take();
}
