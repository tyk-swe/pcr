// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded route-netlink execution on namespace-local pooled workers.
//!
//! Each network namespace has one persistent job on the native worker pool,
//! owning its Tokio runtime and socket for the process lifetime and holding
//! one pool slot; callers queue operations in its inbox and wait on a
//! per-request reply channel instead of paying a runtime and a socket per
//! lookup. A planning pass over T targets issues its T requests on a single
//! connection rather than T workers.

use std::{
    any::Any,
    collections::{BTreeMap, VecDeque},
    fs::File,
    future::Future,
    os::unix::fs::MetadataExt,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender},
    },
    time::{Duration, Instant},
};

use crate::deadline::{POLL_INTERVAL, expires_at, remaining_before};
use futures_util::future::{Either, select};
use packetcraftr_core::budget::{Cancellation, Cancelled, Deadline};
use rtnetlink::{Handle, new_connection};

use crate::{
    platform::common::{os_error, refused},
    route,
    workers::{self, Class, Task, Waited},
};

/// Queued operations are bounded at the native worker capacity, so submission
/// pressure stays coupled to the shared pool the worker draws on.
const NETLINK_QUEUE_DEPTH: usize = crate::workers::CAPACITY;

/// The channel boundary erases each operation's result type behind `Any`; the
/// caller's downcast restores it and can only fail if the worker answered a
/// different call's request.
type OperationResult = Result<Box<dyn Any + Send>, route::Error>;
type OperationFuture = Pin<Box<dyn Future<Output = OperationResult> + Send>>;
type Operation = Box<dyn FnOnce(Handle) -> OperationFuture + Send>;

struct NetlinkRequest {
    operation: Operation,
    respond: SyncSender<OperationResult>,
    deadline: Instant,
    /// The caller's stop signal; a cancelled operation is abandoned like an
    /// expired one.
    cancellation: Option<Cancellation>,
}

/// The installed worker. `generation` lets a caller that found a dead worker
/// tell "still dead" from "another caller already installed a replacement".
struct WorkerSlot {
    generation: u64,
    inbox: Arc<Inbox>,
    worker: Task<()>,
    // Pin the namespace identity even after its original callers leave.
    _namespace: File,
}

/// One worker's bounded request queue. Submitters and the worker wait on its
/// condvar for room and for work.
struct Inbox {
    state: Mutex<InboxState>,
    changed: Condvar,
}

struct InboxState {
    queue: VecDeque<NetlinkRequest>,
    /// Cleared when the worker stops; queued requests are then dropped, so
    /// their callers see the worker end.
    serving: bool,
    /// Cleared when no owner will submit again; the worker then stops once
    /// the queue is empty.
    owned: bool,
}

enum Refused {
    /// The worker stopped; the undelivered request comes back.
    Stopped(NetlinkRequest),
    Interrupted(route::Error),
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Inbox {
    fn new() -> Self {
        Self {
            state: Mutex::new(InboxState {
                queue: VecDeque::new(),
                serving: true,
                owned: true,
            }),
            changed: Condvar::new(),
        }
    }

    /// Queues `request`, waiting for room until `deadline`.
    fn submit(
        &self,
        request: NetlinkRequest,
        caller: &Deadline,
        deadline: Instant,
    ) -> Result<(), Refused> {
        let mut state = lock(&self.state);
        loop {
            if !state.serving {
                return Err(Refused::Stopped(request));
            }
            if state.queue.len() < NETLINK_QUEUE_DEPTH {
                state.queue.push_back(request);
                self.changed.notify_all();
                return Ok(());
            }
            let Some(remaining) = remaining_before(deadline) else {
                return Err(Refused::Interrupted(netlink_timeout(
                    "submitting the netlink request",
                )));
            };
            // The condvar signals room; the caller's cancellation has no
            // waker, so the wait is sliced to notice it.
            state = self
                .changed
                .wait_timeout(state, remaining.min(POLL_INTERVAL))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
            if let Err(cancelled) = caller.check_cancelled() {
                return Err(Refused::Interrupted(cancelled.into()));
            }
        }
    }

    /// The next request, or `None` once no owner remains and none is queued.
    fn next(&self) -> Option<NetlinkRequest> {
        let mut state = lock(&self.state);
        loop {
            if let Some(request) = state.queue.pop_front() {
                self.changed.notify_all();
                return Some(request);
            }
            if !state.owned {
                return None;
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn abandon(&self) {
        lock(&self.state).owned = false;
        self.changed.notify_all();
    }

    /// Stops accepting requests and drops the queued ones outside the lock.
    fn stop(&self) {
        let queued = {
            let mut state = lock(&self.state);
            state.serving = false;
            std::mem::take(&mut state.queue)
        };
        self.changed.notify_all();
        drop(queued);
    }
}

/// Stops the inbox however the worker ends, including by unwinding.
struct StopOnExit<'a>(&'a Inbox);

impl Drop for StopOnExit<'_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}

type NamespaceId = (u64, u64);

struct Namespace {
    id: NamespaceId,
    file: File,
}

impl Namespace {
    fn current() -> Result<Self, route::Error> {
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

type Workers = BTreeMap<NamespaceId, WorkerSlot>;

/// The namespace workers. A caller checks the map out for as long as it
/// starts a worker, so others wait for it on a condvar, bounded by their own
/// deadlines, instead of blocking on a lock.
struct Registry {
    workers: Mutex<Option<Workers>>,
    returned: Condvar,
}

/// Exclusive use of the registry's map, returned on drop (including by
/// unwinding).
struct Checkout {
    workers: Option<Workers>,
}

impl std::ops::Deref for Checkout {
    type Target = Workers;

    fn deref(&self) -> &Workers {
        self.workers.as_ref().expect("a checkout holds the map")
    }
}

impl std::ops::DerefMut for Checkout {
    fn deref_mut(&mut self) -> &mut Workers {
        self.workers.as_mut().expect("a checkout holds the map")
    }
}

impl Drop for Checkout {
    fn drop(&mut self) {
        *lock(&REGISTRY.workers) = self.workers.take();
        REGISTRY.returned.notify_one();
    }
}

// Both the registry and its live workers are bounded by native capacity.
static REGISTRY: Registry = Registry {
    workers: Mutex::new(Some(BTreeMap::new())),
    returned: Condvar::new(),
};
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Runs `operation` on this namespace's worker. The caller's deadline bounds
/// every step (admission, worker start, queueing, execution, and the reply);
/// cancellation is checked while the caller waits.
pub(in crate::platform) fn with_netlink<F, Fut, T>(
    caller: &Deadline,
    operation: F,
) -> Result<T, route::Error>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, route::Error>> + Send + 'static,
    T: Send + 'static,
{
    let deadline = expires_at(caller).map_err(|interrupted| {
        route::Error::interrupted(interrupted, "submitting the netlink request")
    })?;
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
        cancellation: caller.cancellation().cloned(),
    };
    let mut restarted = false;
    loop {
        caller.check_cancelled()?;
        remaining_before(deadline)
            .ok_or_else(|| netlink_timeout("submitting the netlink request"))?;
        let (generation, inbox) = worker_inbox(&namespace, caller, deadline)?;
        match inbox.submit(request, caller, deadline) {
            Ok(()) => break,
            Err(Refused::Interrupted(error)) => return Err(error),
            // A stopped inbox means the worker died; the request came back
            // undelivered, so it is safe to resubmit to a replacement.
            Err(Refused::Stopped(returned)) => {
                request = returned;
                if restarted {
                    return Err(netlink_worker_panicked());
                }
                restarted = true;
                restart_worker(&namespace, generation, caller, deadline)?;
            }
        }
    }
    // The worker bounds the operation by the same deadline; waiting in
    // slices lets a cancelled caller leave without waiting it out.
    let result = loop {
        let Some(remaining) = remaining_before(deadline) else {
            return Err(netlink_timeout("waiting for the netlink response"));
        };
        match finished.recv_timeout(remaining.min(POLL_INTERVAL)) {
            Ok(result) => break result,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(netlink_worker_panicked()),
            Err(mpsc::RecvTimeoutError::Timeout) => caller.check_cancelled()?,
        }
    };
    result.and_then(|value| {
        value
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| route::Error::InvalidResponse {
                message: "Linux netlink worker returned a mismatched result type".to_owned(),
            })
    })
}

fn shared_workers(caller: &Deadline, deadline: Instant) -> Result<Checkout, route::Error> {
    let mut workers = lock(&REGISTRY.workers);
    loop {
        if let Some(checked_out) = workers.take() {
            return Ok(Checkout {
                workers: Some(checked_out),
            });
        }
        let remaining = remaining_before(deadline)
            .ok_or_else(|| netlink_timeout("waiting for netlink worker admission"))?;
        // The condvar signals the map's return; the caller's cancellation
        // has no waker, so the wait is sliced to notice it.
        workers = REGISTRY
            .returned
            .wait_timeout(workers, remaining.min(POLL_INTERVAL))
            .unwrap_or_else(PoisonError::into_inner)
            .0;
        caller.check_cancelled()?;
    }
}

fn worker_inbox(
    namespace: &Namespace,
    caller: &Deadline,
    deadline: Instant,
) -> Result<(u64, Arc<Inbox>), route::Error> {
    let mut workers = shared_workers(caller, deadline)?;
    // A finished worker's pooled thread has already returned to the pool.
    workers.retain(|_, worker| worker.worker.try_take().is_none());
    if !workers.contains_key(&namespace.id) {
        check_namespace_capacity(workers.len())?;
        let worker = start_worker(namespace, deadline)?;
        workers.insert(namespace.id, worker);
    }
    let worker = workers
        .get(&namespace.id)
        .expect("the namespace worker was initialized");
    Ok((worker.generation, Arc::clone(&worker.inbox)))
}

fn check_namespace_capacity(count: usize) -> Result<(), route::Error> {
    if count >= crate::workers::CAPACITY {
        return Err(route::Error::OperatingSystem {
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
    caller: &Deadline,
    deadline: Instant,
) -> Result<(), route::Error> {
    let mut workers = shared_workers(caller, deadline)?;
    if workers
        .get(&namespace.id)
        .is_some_and(|worker| worker.generation != generation)
    {
        return Ok(());
    }
    if let Some(dead) = workers.remove(&namespace.id) {
        settle(dead.worker, deadline);
    }
    check_namespace_capacity(workers.len())?;
    let worker = start_worker(namespace, deadline)?;
    workers.insert(namespace.id, worker);
    Ok(())
}

fn start_worker(namespace: &Namespace, deadline: Instant) -> Result<WorkerSlot, route::Error> {
    remaining_before(deadline).ok_or_else(|| netlink_timeout("initializing netlink"))?;
    let namespace = namespace
        .file
        .try_clone()
        .map_err(|error| os_error("retain caller network namespace", error))?;
    let permit = workers::shared().admit(Class::Native).map_err(refused)?;
    let (setup, initialized) = mpsc::sync_channel(1);
    let inbox = Arc::new(Inbox::new());
    let worker_inbox = Arc::clone(&inbox);
    // Dispatch from the caller so the pooled thread, and every replacement
    // socket it opens, is in the namespace the retained descriptor names.
    let worker = permit
        .spawn(move || run_worker(&setup, &worker_inbox))
        .map_err(|error| os_error("spawn netlink worker", error))?;
    drop(permit);
    match initialized.recv_timeout(remaining_before(deadline).unwrap_or_default()) {
        Ok(Ok(())) => Ok(WorkerSlot {
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
            inbox,
            worker,
            _namespace: namespace,
        }),
        Ok(Err(error)) => {
            settle(worker, deadline);
            Err(error)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            settle(worker, deadline);
            Err(netlink_worker_panicked())
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // The worker may still be initializing. Abandoning its inbox and
            // dropping `initialized` makes it report to nobody and stop on
            // its own, releasing its slot when the job ends.
            worker.retention_marker().mark_retained();
            inbox.abandon();
            Err(netlink_timeout("initializing netlink"))
        }
    }
}

/// Waits, within the caller's deadline, for a worker that stopped serving to
/// return its slot; one still running is left to finish as retained cleanup.
fn settle(worker: Task<()>, deadline: Instant) {
    let remaining = remaining_before(deadline).unwrap_or_default();
    if let Waited::Pending(worker) = worker.wait(&Deadline::new(remaining)) {
        worker.retention_marker().mark_retained();
    }
}

fn run_worker(setup: &SyncSender<Result<(), route::Error>>, inbox: &Inbox) {
    let _stop = StopOnExit(inbox);
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
    serve_requests(&runtime, handle, connection, inbox);
}

fn open_connection(
    runtime: &tokio::runtime::Runtime,
) -> Result<(Handle, tokio::task::JoinHandle<()>), route::Error> {
    let (connection, handle, _) = runtime
        .block_on(async { new_connection() })
        .map_err(|error| os_error("open route netlink socket", error))?;
    Ok((handle, runtime.spawn(connection)))
}

fn serve_requests(
    runtime: &tokio::runtime::Runtime,
    mut handle: Handle,
    mut connection: tokio::task::JoinHandle<()>,
    inbox: &Inbox,
) {
    while let Some(NetlinkRequest {
        operation,
        respond,
        deadline,
        cancellation,
    }) = inbox.next()
    {
        if remaining_before(deadline).is_none() {
            let _ = respond.send(Err(netlink_timeout(STARTING_OPERATION)));
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
            let _ = respond.send(Err(netlink_timeout(STARTING_OPERATION)));
            continue;
        };
        let (result, discard_connection) = match catch_unwind(AssertUnwindSafe(|| {
            runtime.block_on(await_netlink_operation(
                operation(handle.clone()),
                &mut connection,
                remaining,
                cancellation.as_ref(),
            ))
        })) {
            Ok(result) => {
                let timed_out = matches!(
                    &result,
                    Err(route::Error::DeadlineExceeded {
                        operation: EXECUTING_OPERATION,
                    } | route::Error::Cancelled(_))
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
    cancellation: Option<&Cancellation>,
) -> Result<T, route::Error>
where
    F: Future<Output = Result<T, route::Error>>,
{
    let operation = std::pin::pin!(tokio::time::timeout(timeout, operation));
    let cancelled = std::pin::pin!(cancelled(cancellation));
    match select(connection, select(operation, cancelled)).await {
        Either::Left((joined, _)) => {
            joined.map_err(|error| os_error("drive netlink connection", error))?;
            Err(route::Error::OperatingSystem {
                operation: "drive netlink connection",
                message: "route netlink connection stopped".to_owned(),
                source: None,
            })
        }
        Either::Right((Either::Left((result, _)), _)) => {
            result.map_err(|_| netlink_timeout(EXECUTING_OPERATION))?
        }
        Either::Right((Either::Right((cancelled, _)), _)) => Err(cancelled.into()),
    }
}

/// Resolves once the caller's signal is observed; the signal has no waker,
/// so it is polled at the shared interval.
async fn cancelled(cancellation: Option<&Cancellation>) -> Cancelled {
    let Some(cancellation) = cancellation else {
        return std::future::pending().await;
    };
    loop {
        if let Err(cancelled) = cancellation.check() {
            return cancelled;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn netlink_worker_panicked() -> route::Error {
    route::Error::InvalidResponse {
        message: "Linux netlink worker panicked".to_owned(),
    }
}

const STARTING_OPERATION: &str = "starting the netlink operation";
const EXECUTING_OPERATION: &str = "executing the netlink operation";

/// The caller's deadline expired during `operation`.
fn netlink_timeout(operation: &'static str) -> route::Error {
    route::Error::DeadlineExceeded { operation }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use packetcraftr_core::error::Classified as _;

    use super::*;

    /// A deadline far beyond any operation these tests expect to finish.
    const LONG_ENOUGH: Duration = Duration::from_secs(3);

    fn caller() -> Deadline {
        Deadline::new(LONG_ENOUGH)
    }

    #[test]
    fn a_lookup_that_outlives_the_callers_deadline_reports_the_deadline() {
        let started = Instant::now();
        let result: Result<(), route::Error> =
            with_netlink(&Deadline::new(Duration::from_millis(100)), |_handle| {
                std::future::pending()
            });
        match result {
            // A host that refuses the socket cannot exercise the worker.
            Err(error @ route::Error::OperatingSystem { .. }) => {
                eprintln!("skipping netlink deadline check: {error}");
            }
            Err(error @ route::Error::DeadlineExceeded { .. }) => {
                assert_eq!(error.classification().code, "io.deadline_exceeded");
                assert!(started.elapsed() < Duration::from_secs(2));
            }
            other => panic!("a stalled netlink operation must report the deadline: {other:?}"),
        }
    }

    #[test]
    fn a_cancelled_caller_stops_waiting_for_a_stalled_operation() {
        let signal = packetcraftr_core::budget::Cancellation::default();
        let caller = Deadline::new(Duration::from_secs(30)).with_cancellation(Some(signal.clone()));
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            signal.cancel();
        });
        let started = Instant::now();
        let result: Result<(), route::Error> =
            with_netlink(&caller, |_handle| std::future::pending());
        canceller.join().unwrap();
        match result {
            Err(error @ route::Error::OperatingSystem { .. }) => {
                eprintln!("skipping netlink cancellation check: {error}");
            }
            Err(route::Error::Cancelled(_)) => {
                assert!(started.elapsed() < Duration::from_secs(5));
            }
            other => panic!("a cancelled caller must stop waiting: {other:?}"),
        }
    }

    #[test]
    fn a_pending_query_is_cancelled_at_its_operation_deadline() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let mut connection = runtime.spawn(std::future::pending());
        assert!(matches!(
            runtime.block_on(await_netlink_operation(
                std::future::pending::<Result<(), route::Error>>(),
                &mut connection,
                Duration::ZERO,
                None,
            )),
            Err(route::Error::DeadlineExceeded {
                operation: EXECUTING_OPERATION,
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
                    std::future::pending::<Result<(), route::Error>>(),
                    &mut connection,
                    Duration::from_secs(60),
                    None,
                ),
            )
            .await
            .expect("connection failure must not wait for the operation deadline")
        });
        assert!(matches!(
            result,
            Err(route::Error::OperatingSystem {
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
                cancellation: None,
            },
            result,
        )
    }

    /// An inbox holding `requests` whose owner has already left, so a worker
    /// serves them and then stops.
    fn queued(requests: impl IntoIterator<Item = NetlinkRequest>) -> Inbox {
        let inbox = Inbox::new();
        let deadline = Instant::now() + LONG_ENOUGH;
        for request in requests {
            assert!(inbox.submit(request, &caller(), deadline).is_ok());
        }
        inbox.abandon();
        inbox
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
        serve_requests(&runtime, handle, connection, &queued([request]));
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
        let deadline = Instant::now() + LONG_ENOUGH;
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
        serve_requests(&runtime, handle, connection, &queued([first, second]));
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
            started + LONG_ENOUGH,
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
        serve_requests(&runtime, handle, connection, &queued([first, second]));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(first_result.recv().unwrap().is_err());
        assert!(second_result.recv().unwrap().is_ok());
    }

    #[test]
    fn a_full_inbox_holds_submitters_until_their_deadline_or_room() {
        let noop = || -> Operation {
            Box::new(|_| Box::pin(async { Ok(Box::new(()) as Box<dyn Any + Send>) }))
        };
        let inbox = Inbox::new();
        let later = Instant::now() + LONG_ENOUGH;
        for _ in 0..NETLINK_QUEUE_DEPTH {
            assert!(
                inbox
                    .submit(request_with(later, noop()).0, &caller(), later)
                    .is_ok()
            );
        }
        let started = Instant::now();
        let soon = started + Duration::from_millis(30);
        let (request, _) = request_with(later, noop());
        match inbox.submit(request, &caller(), soon) {
            Err(Refused::Interrupted(error @ route::Error::DeadlineExceeded { .. })) => {
                assert_eq!(error.classification().code, "io.deadline_exceeded");
            }
            _ => panic!("a full inbox must hold the submitter until its deadline"),
        }
        assert!(started.elapsed() < Duration::from_secs(2));

        let inbox = Arc::new(inbox);
        let worker = {
            let inbox = Arc::clone(&inbox);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(20));
                inbox.next().is_some()
            })
        };
        let (request, _) = request_with(later, noop());
        assert!(
            inbox.submit(request, &caller(), later).is_ok(),
            "room wakes the submitter"
        );
        assert!(worker.join().unwrap());

        inbox.stop();
        let (request, _) = request_with(later, noop());
        assert!(matches!(
            inbox.submit(request, &caller(), later),
            Err(Refused::Stopped(_))
        ));
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
                    let observed = with_netlink(&caller(), |_| async {
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
        let first: Result<u32, route::Error> =
            match with_netlink(&caller(), |_handle| async move { Ok(7_u32) }) {
                Err(error @ route::Error::OperatingSystem { .. }) => {
                    eprintln!("skipping shared-worker round trip: {error}");
                    return;
                }
                first => first,
            };
        assert!(matches!(first, Ok(7)));
        let second: Result<String, route::Error> =
            with_netlink(&caller(), |_handle| async move { Ok("route".to_owned()) });
        assert!(matches!(second, Ok(ref value) if value == "route"));
    }
}
