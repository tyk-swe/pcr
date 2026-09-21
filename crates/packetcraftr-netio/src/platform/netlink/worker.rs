// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded route-netlink execution on namespace-local shared worker threads.
//!
//! Each network namespace has one worker owning its Tokio runtime and socket
//! for the process lifetime, charged to the shared native worker budget; callers submit
//! operations over a bounded channel and wait on a per-request reply channel
//! instead of paying a thread spawn, a runtime, and a socket per lookup. A
//! planning pass over T targets issues its T requests on a single connection
//! rather than T workers.

use std::{
    any::Any,
    collections::BTreeMap,
    fs::File,
    future::Future,
    os::unix::fs::MetadataExt,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{
        Mutex, MutexGuard, TryLockError,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use futures_util::future::{Either, select};
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
    deadline: Instant,
}

/// The installed worker. `generation` lets a caller that found a dead worker
/// tell "still dead" from "another caller already installed a replacement".
struct WorkerSlot {
    generation: u64,
    requests: SyncSender<NetlinkRequest>,
    retention: RetentionMarker,
    worker: JoinHandle<()>,
    // Pin the namespace identity even after its original callers leave.
    _namespace: File,
}

type NamespaceId = (u64, u64);

struct Namespace {
    id: NamespaceId,
    file: File,
}

impl Namespace {
    fn current() -> Result<Self, SystemError> {
        let file = File::open("/proc/thread-self/ns/net")
            .map_err(|error| os_error("open caller network namespace", error))?;
        let metadata = file
            .metadata()
            .map_err(|error| os_error("identify caller network namespace", error))?;
        Ok(Self {
            id: (metadata.dev(), metadata.ino()),
            file,
        })
    }
}

// Both the registry and its live workers are bounded by native capacity.
static SHARED_WORKERS: Mutex<BTreeMap<NamespaceId, WorkerSlot>> = Mutex::new(BTreeMap::new());
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

pub(super) fn with_netlink<F, Fut, T>(operation: F) -> Result<T, SystemError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, SystemError>> + Send + 'static,
    T: Send + 'static,
{
    let deadline = Instant::now() + NETLINK_RESPONSE_TIMEOUT;
    let namespace = Namespace::current()?;
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
        deadline,
    };
    let mut restarted = false;
    loop {
        remaining_before(deadline).ok_or_else(|| netlink_timeout("submit netlink request"))?;
        let (generation, requests) = worker_requests(&namespace, deadline)?;
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
                restart_worker(&namespace, generation, deadline)?;
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

fn shared_workers(
    deadline: Instant,
) -> Result<MutexGuard<'static, BTreeMap<NamespaceId, WorkerSlot>>, SystemError> {
    loop {
        match SHARED_WORKERS.try_lock() {
            Ok(workers) => return Ok(workers),
            Err(TryLockError::Poisoned(error)) => return Ok(error.into_inner()),
            Err(TryLockError::WouldBlock) => {
                let remaining = remaining_before(deadline)
                    .ok_or_else(|| netlink_timeout("wait for netlink worker admission"))?;
                thread::park_timeout(remaining.min(Duration::from_millis(10)));
            }
        }
    }
}

fn worker_requests(
    namespace: &Namespace,
    deadline: Instant,
) -> Result<(u64, SyncSender<NetlinkRequest>), SystemError> {
    let mut workers = shared_workers(deadline)?;
    let finished: Vec<_> = workers
        .iter()
        .filter(|(_, worker)| worker.worker.is_finished())
        .map(|(id, _)| *id)
        .collect();
    for id in finished {
        if let Some(worker) = workers.remove(&id) {
            let _ = worker.worker.join();
        }
    }
    if !workers.contains_key(&namespace.id) {
        check_namespace_capacity(workers.len())?;
        workers.insert(namespace.id, start_worker(namespace, deadline)?);
    }
    let worker = workers
        .get(&namespace.id)
        .expect("the namespace worker was initialized");
    Ok((worker.generation, worker.requests.clone()))
}

fn check_namespace_capacity(count: usize) -> Result<(), SystemError> {
    if count >= crate::platform::workers::CAPACITY {
        return Err(SystemError::OperatingSystem {
            operation: "reserve netlink namespace worker",
            message: "network namespace worker capacity is exhausted".to_owned(),
            source: None,
        });
    }
    Ok(())
}

fn restart_worker(
    namespace: &Namespace,
    generation: u64,
    deadline: Instant,
) -> Result<(), SystemError> {
    let mut workers = shared_workers(deadline)?;
    if workers
        .get(&namespace.id)
        .is_some_and(|worker| worker.generation != generation)
    {
        return Ok(());
    }
    if let Some(dead) = workers.remove(&namespace.id) {
        match join_with_deadline(
            dead.worker,
            remaining_before(deadline)
                .unwrap_or_default()
                .min(NETLINK_OPERATION_TIMEOUT),
            Duration::from_millis(10),
        ) {
            JoinAttempt::Finished(joined) => drop(joined),
            JoinAttempt::TimedOut(worker) => {
                dead.retention.mark_retained();
                drop(worker);
            }
        }
    }
    check_namespace_capacity(workers.len())?;
    workers.insert(namespace.id, start_worker(namespace, deadline)?);
    Ok(())
}

fn start_worker(namespace: &Namespace, deadline: Instant) -> Result<WorkerSlot, SystemError> {
    remaining_before(deadline).ok_or_else(|| netlink_timeout("initialize netlink"))?;
    let namespace = namespace
        .file
        .try_clone()
        .map_err(|error| os_error("retain caller network namespace", error))?;
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
    // Spawn directly from the caller so this worker and every replacement
    // socket inherit the namespace identified by the retained descriptor.
    let worker = thread::Builder::new()
        .name("packetcraftr-netlink".to_owned())
        .spawn(move || run_worker(setup, inbox, permit))
        .map_err(|error| os_error("spawn netlink worker", error))?;
    match initialized.recv_timeout(
        remaining_before(deadline)
            .unwrap_or_default()
            .min(NETLINK_OPERATION_TIMEOUT),
    ) {
        Ok(Ok(())) => Ok(WorkerSlot {
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
            requests,
            retention,
            worker,
            _namespace: namespace,
        }),
        Ok(Err(error)) => {
            // The worker reported its own setup failure and returned, so its
            // thread is already at exit; join reaps it rather than detaching.
            let _ = worker.join();
            Err(error)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = worker.join();
            Err(netlink_worker_panicked())
        }
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
    let (handle, connection) = match open_connection(&runtime) {
        Ok(connection) => connection,
        Err(error) => {
            let _ = setup.send(Err(error));
            return;
        }
    };
    if setup.send(Ok(())).is_err() {
        connection.abort();
        return;
    }
    serve_requests(&runtime, handle, connection, requests);
}

fn open_connection(
    runtime: &tokio::runtime::Runtime,
) -> Result<(Handle, tokio::task::JoinHandle<()>), SystemError> {
    let (connection, handle, _) = runtime
        .block_on(async { new_connection() })
        .map_err(|error| os_error("open route netlink socket", error))?;
    Ok((handle, runtime.spawn(connection)))
}

fn serve_requests(
    runtime: &tokio::runtime::Runtime,
    mut handle: Handle,
    mut connection: tokio::task::JoinHandle<()>,
    requests: mpsc::Receiver<NetlinkRequest>,
) {
    while let Ok(NetlinkRequest {
        operation,
        respond,
        deadline,
    }) = requests.recv()
    {
        if remaining_before(deadline).is_none() {
            let _ = respond.send(Err(netlink_timeout("start netlink operation")));
            continue;
        }
        // Keep unstarted requests in this inbox when a socket fails. The
        // operation already invoked receives its error and is never replayed.
        if connection.is_finished() {
            match open_connection(runtime) {
                Ok((replacement_handle, replacement_connection)) => {
                    handle = replacement_handle;
                    connection = replacement_connection;
                }
                Err(error) => {
                    let _ = respond.send(Err(error));
                    continue;
                }
            }
        }
        let Some(remaining) = remaining_before(deadline) else {
            let _ = respond.send(Err(netlink_timeout("start netlink operation")));
            continue;
        };
        let (result, discard_connection) = match catch_unwind(AssertUnwindSafe(|| {
            runtime.block_on(await_netlink_operation(
                operation(handle.clone()),
                &mut connection,
                remaining.min(NETLINK_OPERATION_TIMEOUT),
            ))
        })) {
            Ok(result) => {
                let timed_out = matches!(
                    &result,
                    Err(SystemError::OperatingSystem {
                        operation: "execute netlink operation",
                        ..
                    })
                );
                (result, timed_out)
            }
            Err(_) => (Err(netlink_worker_panicked()), true),
        };
        if discard_connection {
            // Dropping a request future does not clear netlink-proto's pending
            // reply map. Retire its socket before accepting further work.
            connection.abort();
            if !connection.is_finished() {
                let _ = runtime.block_on(&mut connection);
            }
        }
        let _ = respond.send(result);
    }
    connection.abort();
}

async fn await_netlink_operation<F, T>(
    operation: F,
    connection: &mut tokio::task::JoinHandle<()>,
    timeout: Duration,
) -> Result<T, SystemError>
where
    F: Future<Output = Result<T, SystemError>>,
{
    let operation = std::pin::pin!(tokio::time::timeout(timeout, operation));
    match select(connection, operation).await {
        Either::Left((joined, _)) => {
            joined.map_err(|error| os_error("drive netlink connection", error))?;
            Err(SystemError::OperatingSystem {
                operation: "drive netlink connection",
                message: "route netlink connection stopped".to_owned(),
                source: None,
            })
        }
        Either::Right((result, _)) => {
            result.map_err(|_| netlink_timeout("execute netlink operation"))?
        }
    }
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
        let mut connection = runtime.spawn(std::future::pending());
        assert!(matches!(
            runtime.block_on(await_netlink_operation(
                std::future::pending::<Result<(), SystemError>>(),
                &mut connection,
                Duration::ZERO,
            )),
            Err(SystemError::OperatingSystem {
                operation: "execute netlink operation",
                ..
            })
        ));
    }

    #[test]
    fn a_stopped_connection_releases_pending_queries_for_reconnection() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let mut connection = runtime.spawn(async {});
        let result = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(1),
                await_netlink_operation(
                    std::future::pending::<Result<(), SystemError>>(),
                    &mut connection,
                    Duration::from_secs(60),
                ),
            )
            .await
            .expect("connection failure must not wait for the operation deadline")
        });
        assert!(matches!(
            result,
            Err(SystemError::OperatingSystem {
                operation: "drive netlink connection",
                ..
            })
        ));
        assert!(connection.is_finished());
    }

    fn request_with(
        deadline: Instant,
        operation: Operation,
    ) -> (NetlinkRequest, mpsc::Receiver<OperationResult>) {
        let (respond, result) = mpsc::sync_channel(1);
        (
            NetlinkRequest {
                operation,
                respond,
                deadline,
            },
            result,
        )
    }

    #[test]
    fn expired_queued_operations_are_never_invoked() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (handle, connection) = open_connection(&runtime).unwrap();
        let invoked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = invoked.clone();
        let (request, result) = request_with(
            Instant::now(),
            Box::new(move |_| {
                Box::pin(async move {
                    observed.store(true, Ordering::SeqCst);
                    Ok(Box::new(7_u32) as Box<dyn Any + Send>)
                })
            }),
        );
        let (submit, inbox) = mpsc::sync_channel(1);
        submit.send(request).unwrap();
        drop(submit);
        serve_requests(&runtime, handle, connection, inbox);
        assert!(
            !invoked.load(Ordering::SeqCst),
            "expired operation ran after its caller deadline"
        );
        assert!(result.recv().unwrap().is_err());
    }

    #[test]
    fn queued_operations_survive_a_connection_failure() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (handle, connection) = open_connection(&runtime).unwrap();
        let abort = connection.abort_handle();
        let deadline = Instant::now() + NETLINK_RESPONSE_TIMEOUT;
        let (first, first_result) = request_with(
            deadline,
            Box::new(move |_| {
                Box::pin(async move {
                    abort.abort();
                    std::future::pending().await
                })
            }),
        );
        let (second, second_result) = request_with(
            deadline,
            Box::new(|_| Box::pin(async { Ok(Box::new(9_u32) as Box<dyn Any + Send>) })),
        );
        let (submit, inbox) = mpsc::sync_channel(2);
        submit.send(first).unwrap();
        submit.send(second).unwrap();
        drop(submit);
        serve_requests(&runtime, handle, connection, inbox);
        assert!(first_result.recv().unwrap().is_err());
        assert_eq!(
            *second_result
                .recv()
                .expect("queued operation must retain its reply")
                .unwrap()
                .downcast::<u32>()
                .unwrap(),
            9
        );
    }

    #[test]
    fn execution_uses_the_remaining_request_deadline_and_retires_the_socket() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (handle, connection) = open_connection(&runtime).unwrap();
        let old_connection = connection.abort_handle();
        let started = Instant::now();
        let (first, first_result) = request_with(
            started + Duration::from_millis(20),
            Box::new(|_| Box::pin(std::future::pending())),
        );
        let (second, second_result) = request_with(
            started + NETLINK_RESPONSE_TIMEOUT,
            Box::new(move |_| {
                Box::pin(async move {
                    assert!(
                        old_connection.is_finished(),
                        "timed-out socket must release pending replies"
                    );
                    Ok(Box::new(9_u32) as Box<dyn Any + Send>)
                })
            }),
        );
        let (submit, inbox) = mpsc::sync_channel(2);
        submit.send(first).unwrap();
        submit.send(second).unwrap();
        drop(submit);
        serve_requests(&runtime, handle, connection, inbox);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(first_result.recv().unwrap().is_err());
        assert!(second_result.recv().unwrap().is_ok());
    }

    #[test]
    #[ignore = "requires an isolated Linux namespace with CAP_SYS_ADMIN"]
    #[allow(unsafe_code)]
    fn callers_in_distinct_namespaces_use_their_own_workers() {
        use std::os::unix::fs::MetadataExt;
        let parent: u64 = std::env::var("PACKETCRAFTR_PARENT_NETNS")
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(
            std::fs::metadata("/proc/thread-self/ns/net").unwrap().ino(),
            parent
        );
        let mut namespaces = Vec::new();
        for _ in 0..2 {
            namespaces.push(
                thread::spawn(|| {
                    // SAFETY: CLONE_NEWNET changes only this dedicated test thread's
                    // network namespace; unshare takes no pointers, and the thread
                    // exits without returning to another caller's network context.
                    let changed = unsafe { libc::unshare(libc::CLONE_NEWNET) };
                    assert_eq!(changed, 0, "{}", std::io::Error::last_os_error());
                    let expected = std::fs::metadata("/proc/thread-self/ns/net").unwrap().ino();
                    let observed = with_netlink(|_| async {
                        std::fs::metadata("/proc/thread-self/ns/net")
                            .map(|metadata| metadata.ino())
                            .map_err(|error| os_error("inspect worker namespace", error))
                    })
                    .unwrap();
                    assert_eq!(
                        observed, expected,
                        "worker must inherit its caller's namespace"
                    );
                    expected
                })
                .join()
                .unwrap(),
            );
        }
        assert_ne!(namespaces[0], namespaces[1]);
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
