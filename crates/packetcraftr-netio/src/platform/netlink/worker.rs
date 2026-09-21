// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded route-netlink execution on a shared worker thread.
//!
//! One worker thread owns its Tokio runtime and route-netlink socket for the
//! process lifetime and holds one shared-budget permit; callers submit
//! operations over a bounded channel and wait on a per-request reply channel
//! instead of paying a thread spawn, a runtime, and a socket per lookup. A
//! planning pass over T targets issues its T requests on a single connection
//! rather than T workers.

use std::{
    any::Any,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{
        Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use packetcraftr_core::budget::remaining_before;
use rtnetlink::{Handle, new_connection};

use crate::{
    platform::{
        os_error,
        workers::{JoinAttempt, RetentionMarker, WorkerPermit, join_with_deadline, shared_budget},
    },
    route::SystemError,
};

const NETLINK_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const NETLINK_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
/// Queued operations are bounded at the native worker capacity, so submission
/// pressure stays coupled to the shared budget the worker draws on.
const NETLINK_QUEUE_DEPTH: usize = crate::platform::workers::CAPACITY;

/// The channel boundary erases each operation's result type behind `Any`; the
/// caller's downcast restores it and can only fail if the worker answered a
/// different call's request.
type OperationResult = Result<Box<dyn Any + Send>, SystemError>;
type OperationFuture = Pin<Box<dyn Future<Output = OperationResult> + Send>>;
type Operation = Box<dyn FnOnce(Handle) -> OperationFuture + Send>;

struct NetlinkRequest {
    operation: Operation,
    respond: SyncSender<OperationResult>,
}

/// The installed worker. `generation` lets a caller that found a dead worker
/// tell "still dead" from "another caller already installed a replacement".
struct WorkerSlot {
    generation: u64,
    requests: SyncSender<NetlinkRequest>,
    retention: RetentionMarker,
    worker: JoinHandle<()>,
}

// One worker serves every lookup in the process. The slot stays empty until
// the first lookup starts it and after a failed start, and is replaced
// wholesale when a worker dies so a dead worker never wedges later lookups.
static SHARED_WORKER: Mutex<Option<WorkerSlot>> = Mutex::new(None);
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

pub(super) fn with_netlink<F, Fut, T>(operation: F) -> Result<T, SystemError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, SystemError>> + Send + 'static,
    T: Send + 'static,
{
    let (respond, finished) = mpsc::sync_channel(1);
    let mut request = NetlinkRequest {
        operation: Box::new(move |handle| {
            Box::pin(async move {
                operation(handle)
                    .await
                    .map(|value| Box::new(value) as Box<dyn Any + Send>)
            })
        }),
        respond,
    };
    let deadline = Instant::now() + NETLINK_RESPONSE_TIMEOUT;
    let mut restarted = false;
    loop {
        let (generation, requests) = worker_requests()?;
        match requests.try_send(request) {
            Ok(()) => break,
            Err(TrySendError::Full(returned)) => {
                request = returned;
                let Some(remaining) = remaining_before(deadline) else {
                    return Err(netlink_timeout("submit netlink request"));
                };
                thread::park_timeout(remaining.min(Duration::from_millis(10)));
            }
            // A disconnected inbox means the worker died; the request came
            // back undelivered, so it is safe to resubmit to a replacement.
            Err(TrySendError::Disconnected(returned)) => {
                request = returned;
                if restarted {
                    return Err(netlink_worker_panicked());
                }
                restarted = true;
                restart_worker(generation)?;
            }
        }
    }
    let result = match finished.recv_timeout(remaining_before(deadline).unwrap_or_default()) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Disconnected) => return Err(netlink_worker_panicked()),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            return Err(netlink_timeout("wait for netlink response"));
        }
    };
    result.and_then(|value| {
        value
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| SystemError::InvalidResponse {
                message: "Linux netlink worker returned a mismatched result type".to_owned(),
            })
    })
}

fn shared_worker() -> MutexGuard<'static, Option<WorkerSlot>> {
    SHARED_WORKER.lock().unwrap_or_else(PoisonError::into_inner)
}

fn worker_requests() -> Result<(u64, SyncSender<NetlinkRequest>), SystemError> {
    let mut slot = shared_worker();
    if slot.is_none() {
        *slot = Some(start_worker()?);
    }
    let worker = slot.as_ref().expect("the worker slot was just initialized");
    Ok((worker.generation, worker.requests.clone()))
}

fn restart_worker(generation: u64) -> Result<(), SystemError> {
    let mut slot = shared_worker();
    if let Some(worker) = slot.as_ref()
        && worker.generation != generation
    {
        // Another caller already swapped in a live worker.
        return Ok(());
    }
    if let Some(dead) = slot.take() {
        // The disconnected inbox means this worker already exited; joining is
        // only to keep the handle owned rather than detached.
        if let JoinAttempt::TimedOut(_) = join_with_deadline(
            dead.worker,
            NETLINK_OPERATION_TIMEOUT,
            Duration::from_millis(10),
        ) {
            dead.retention.mark_retained();
        }
    }
    *slot = Some(start_worker()?);
    Ok(())
}

fn start_worker() -> Result<WorkerSlot, SystemError> {
    let permit = shared_budget()
        .reserve()
        .map_err(|error| SystemError::OperatingSystem {
            operation: "reserve native worker",
            message: format!("native worker capacity {} is exhausted", error.capacity),
            source: None,
        })?;
    let retention = permit.retention_marker();
    let (setup, initialized) = mpsc::sync_channel(1);
    let (requests, inbox) = mpsc::sync_channel(NETLINK_QUEUE_DEPTH);
    // The worker inherits the first caller's network namespace and keeps it:
    // every later lookup shares that one socket. It owns its permit for its
    // whole lifetime; a caller timing out never takes the worker's resources.
    let worker = thread::Builder::new()
        .name("packetcraftr-netlink".to_owned())
        .spawn(move || run_worker(setup, inbox, permit))
        .map_err(|error| os_error("spawn netlink worker", error))?;
    match initialized.recv_timeout(NETLINK_OPERATION_TIMEOUT) {
        Ok(Ok(())) => Ok(WorkerSlot {
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
            requests,
            retention,
            worker,
        }),
        Ok(Err(error)) => {
            // The worker reported its own setup failure and exited; joining
            // keeps the handle owned rather than detached.
            let _ = join_with_deadline(worker, Duration::ZERO, Duration::from_millis(10));
            Err(error)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(netlink_worker_panicked()),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // The worker may still be initializing. Dropping `requests` and
            // `initialized` makes it report to nobody and exit on its own,
            // releasing the permit when its thread finishes.
            retention.mark_retained();
            Err(netlink_timeout("initialize netlink"))
        }
    }
}

fn run_worker(
    setup: SyncSender<Result<(), SystemError>>,
    requests: mpsc::Receiver<NetlinkRequest>,
    permit: WorkerPermit,
) {
    let _permit = permit;
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = setup.send(Err(os_error("create Tokio netlink runtime", error)));
            return;
        }
    };
    let (connection, handle) = match runtime
        .block_on(async { new_connection() })
        .map_err(|error| os_error("open route netlink socket", error))
    {
        Ok((connection, handle, _)) => (connection, handle),
        Err(error) => {
            let _ = setup.send(Err(error));
            return;
        }
    };
    let connection = runtime.spawn(connection);
    if setup.send(Ok(())).is_err() {
        connection.abort();
        return;
    }
    while let Ok(request) = requests.recv() {
        let NetlinkRequest { operation, respond } = request;
        // A panicking operation must not strand every later request behind a
        // dead worker.
        let result = catch_unwind(AssertUnwindSafe(|| {
            runtime.block_on(await_netlink_operation(
                operation(handle.clone()),
                NETLINK_OPERATION_TIMEOUT,
            ))
        }))
        .unwrap_or_else(|_| Err(netlink_worker_panicked()));
        let _ = respond.send(result);
    }
    connection.abort();
}

async fn await_netlink_operation<F, T>(operation: F, timeout: Duration) -> Result<T, SystemError>
where
    F: Future<Output = Result<T, SystemError>>,
{
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| netlink_timeout("execute netlink operation"))?
}

fn netlink_worker_panicked() -> SystemError {
    SystemError::InvalidResponse {
        message: "Linux netlink worker panicked".to_owned(),
    }
}

fn netlink_timeout(operation: &'static str) -> SystemError {
    SystemError::OperatingSystem {
        operation,
        message: "finite operation deadline expired".to_owned(),
        source: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pending_query_is_cancelled_at_its_operation_deadline() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        assert!(matches!(
            runtime.block_on(await_netlink_operation(
                std::future::pending::<Result<(), SystemError>>(),
                Duration::ZERO,
            )),
            Err(SystemError::OperatingSystem {
                operation: "execute netlink operation",
                ..
            })
        ));
    }

    #[test]
    fn a_reused_worker_answers_typed_results_for_sequential_operations() {
        // A host that refuses the socket cannot exercise the worker; that is
        // an environment limit, not a submission-plumbing failure.
        let first: Result<u32, SystemError> = match with_netlink(|_handle| async move { Ok(7_u32) })
        {
            Err(error @ SystemError::OperatingSystem { .. }) => {
                eprintln!("skipping shared-worker round trip: {error}");
                return;
            }
            first => first,
        };
        assert!(matches!(first, Ok(7)));
        let second: Result<String, SystemError> =
            with_netlink(|_handle| async move { Ok("route".to_owned()) });
        assert!(matches!(second, Ok(ref value) if value == "route"));
    }
}
