// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded route-netlink execution on namespace-local pooled workers.

use std::{
    any::Any,
    collections::{BTreeMap, VecDeque},
    fs::File,
    future::Future,
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
use packetcraftr_core::budget::{Deadline, Interrupted};
use rtnetlink::{Handle, new_connection};

use crate::{
    platform::common::{os_error, refused},
    route,
    workers::{self, ExecutionContext, NAMESPACE_PATH, Task, Waited},
};

const NETLINK_QUEUE_DEPTH: usize = crate::workers::CAPACITY;
// Namespace services are a bounded cache, rather than immortal historical work.
const RESIDENT_CAPACITY: usize = crate::workers::CAPACITY / 4;
const IDLE_RETIREMENT: Duration = Duration::from_millis(250);

type OperationResult = Result<Box<dyn Any + Send>, route::Error>;
type OperationFuture = Pin<Box<dyn Future<Output = OperationResult> + Send>>;
type Operation = Box<dyn FnOnce(Handle) -> OperationFuture + Send>;

struct NetlinkRequest {
    operation: Operation,
    respond: SyncSender<OperationResult>,
    deadline: Instant,
    control: Arc<Deadline>,
}

struct WorkerSlot {
    generation: u64,
    inbox: Arc<Inbox>,
    worker: Task<()>,
}

struct Inbox {
    state: Mutex<InboxState>,
    changed: Condvar,
}

struct InboxState {
    queue: VecDeque<NetlinkRequest>,
    serving: bool,
    owned: bool,
    active: bool,
}

enum Refused {
    Retired(NetlinkRequest),
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
                active: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn submit(
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

    fn next(&self) -> Option<NetlinkRequest> {
        self.next_with_idle(IDLE_RETIREMENT)
    }

    fn next_with_idle(&self, idle: Duration) -> Option<NetlinkRequest> {
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

    fn retire_if_idle(&self) -> bool {
        let mut state = lock(&self.state);
        if state.active || !state.queue.is_empty() {
            return false;
        }
        state.serving = false;
        state.owned = false;
        self.changed.notify_all();
        true
    }

    fn complete_request(&self) {
        lock(&self.state).active = false;
        self.changed.notify_all();
    }

    fn abandon(&self) {
        lock(&self.state).owned = false;
        self.changed.notify_all();
    }

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

struct RequestInFlight<'a>(&'a Inbox);

impl Drop for RequestInFlight<'_> {
    fn drop(&mut self) {
        self.0.complete_request();
    }
}

struct StopOnExit<'a>(&'a Inbox);

impl Drop for StopOnExit<'_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}

type NamespaceId = ExecutionContext;

struct Namespace {
    id: NamespaceId,
    file: File,
}

impl Namespace {
    fn current() -> Result<Self, route::Error> {
        let file = File::open(NAMESPACE_PATH)
            .map_err(|error| os_error("open caller network namespace", error))?;
        let id = ExecutionContext::of_namespace(&file)
            .map_err(|error| os_error("identify caller network namespace", error))?;
        Ok(Self { id, file })
    }
}

type Workers = BTreeMap<NamespaceId, WorkerSlot>;

struct Registry {
    workers: Mutex<Option<Workers>>,
    returned: Condvar,
}

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
        control: Arc::new(caller.clone()),
    };
    let mut restarted = false;
    loop {
        wait_remaining(caller, deadline, "submitting the netlink request")?;
        let (generation, inbox) = worker_inbox(&namespace, caller, deadline)?;
        match inbox.submit(request, caller, deadline) {
            Ok(()) => break,
            Err(Refused::Interrupted(error)) => return Err(error),
            // Healthy retirement is expected cache churn, not worker failure.
            // Retrying remains bounded by the original caller control.
            Err(Refused::Retired(returned)) => {
                request = returned;
                restart_worker(&namespace, generation, caller, deadline)?;
            }
            // The request came back undelivered, so it is safe to resubmit to a replacement.
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
    let result = loop {
        let remaining = wait_remaining(caller, deadline, "waiting for the netlink response")?;
        let received = finished.recv_timeout(remaining.min(POLL_INTERVAL));
        wait_remaining(caller, deadline, "waiting for the netlink response")?;
        match received {
            Ok(result) => break result,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(netlink_worker_panicked()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
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
        let remaining = wait_remaining(caller, deadline, "waiting for netlink worker admission")?;
        if let Some(checked_out) = workers.take() {
            return Ok(Checkout {
                workers: Some(checked_out),
            });
        }
        workers = REGISTRY
            .returned
            .wait_timeout(workers, remaining.min(POLL_INTERVAL))
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

fn worker_inbox(
    namespace: &Namespace,
    caller: &Deadline,
    deadline: Instant,
) -> Result<(u64, Arc<Inbox>), route::Error> {
    wait_remaining(caller, deadline, "reserving netlink namespace worker")?;
    let mut workers = shared_workers(caller, deadline)?;
    ensure_worker(
        &mut workers,
        namespace,
        caller,
        deadline,
        workers::shared(),
        start_worker,
    )
}

fn ensure_worker(
    workers: &mut Workers,
    namespace: &Namespace,
    caller: &Deadline,
    deadline: Instant,
    pool: &Arc<workers::Pool>,
    start: impl FnOnce(&Namespace, &Deadline, Instant) -> Result<WorkerSlot, route::Error>,
) -> Result<(u64, Arc<Inbox>), route::Error> {
    wait_remaining(caller, deadline, "reserving netlink namespace worker")?;
    // A finished service no longer needs a resident registry entry. Its pooled
    // executor can still retain the namespace until actual thread retirement.
    workers.retain(|_, worker| worker.worker.try_take().is_none());
    if !workers.contains_key(&namespace.id) {
        // Reclaim healthy idle historical services before refusing a fresh
        // namespace. Keep the slot and descriptor owned until actual completion.
        while workers.len() >= RESIDENT_CAPACITY
            || pool.snapshot().active >= pool.snapshot().capacity
        {
            let idle = workers
                .iter()
                .find_map(|(id, worker)| worker.inbox.retire_if_idle().then_some(*id));
            let Some(idle) = idle else { break };
            let worker = workers.get_mut(&idle).expect("the idle worker is retained");
            let remaining = wait_remaining(caller, deadline, "retiring idle netlink worker")?;
            let wait = caller
                .for_wait(remaining)
                .map_err(|_| netlink_timeout("retiring idle netlink worker"))?;
            worker.worker.wait_ready(&wait);
            if worker.worker.try_take().is_none() {
                worker.worker.retention_marker().mark_retained();
                check_control(caller, "retiring idle netlink worker")?;
                return Err(netlink_timeout("retiring idle netlink worker"));
            }
            workers.remove(&idle);
        }
        check_namespace_capacity(workers.len())?;
        let worker = start(namespace, caller, deadline)?;
        workers.insert(namespace.id, worker);
    }
    let worker = workers
        .get(&namespace.id)
        .expect("the namespace worker was initialized");
    wait_remaining(caller, deadline, "reserving netlink namespace worker")?;
    Ok((worker.generation, Arc::clone(&worker.inbox)))
}

fn check_namespace_capacity(count: usize) -> Result<(), route::Error> {
    if count >= RESIDENT_CAPACITY {
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
        wait_remaining(caller, deadline, "restarting netlink worker")?;
        return Ok(());
    }
    if let Some(dead) = workers.remove(&namespace.id) {
        settle(dead.worker, caller, deadline);
    }
    check_namespace_capacity(workers.len())?;
    let worker = start_worker(namespace, caller, deadline)?;
    workers.insert(namespace.id, worker);
    wait_remaining(caller, deadline, "restarting netlink worker")?;
    Ok(())
}

fn start_worker(
    namespace: &Namespace,
    caller: &Deadline,
    deadline: Instant,
) -> Result<WorkerSlot, route::Error> {
    start_worker_with(namespace, caller, deadline, workers::shared(), run_worker)
}

fn start_worker_with(
    namespace: &Namespace,
    caller: &Deadline,
    deadline: Instant,
    pool: &Arc<workers::Pool>,
    initialize: impl FnOnce(&SyncSender<Result<(), route::Error>>, &Inbox) + Send + 'static,
) -> Result<WorkerSlot, route::Error> {
    let remaining = wait_remaining(caller, deadline, "initializing netlink")?;
    let dispatch_control = caller
        .for_wait(remaining)
        .map_err(|_| netlink_timeout("initializing netlink"))?;
    let namespace = namespace
        .file
        .try_clone()
        .map_err(|error| os_error("retain caller network namespace", error))?;
    let permit = pool.admit().map_err(refused)?;
    let (setup, initialized) = mpsc::sync_channel(1);
    let inbox = Arc::new(Inbox::new());
    let worker_inbox = Arc::clone(&inbox);
    // Dispatch from the caller so the pooled thread is in the namespace the descriptor names.
    let worker = permit
        .spawn_with_control(&dispatch_control, move || {
            // Pin identity through service cleanup, then close the descriptor
            // before the worker releases its native root admission.
            let _namespace = namespace;
            let _stop = StopOnExit(&worker_inbox);
            initialize(&setup, &worker_inbox);
        })
        .map_err(|error| match dispatch_control.enforce() {
            Err(interrupted) => route::Error::interrupted(interrupted, "initializing netlink"),
            Ok(()) => os_error("spawn netlink worker", error),
        })?;
    let result = loop {
        let remaining = match wait_remaining(caller, deadline, "initializing netlink") {
            Ok(remaining) => remaining,
            Err(error) => break Err(error),
        };
        let received = initialized.recv_timeout(remaining.min(POLL_INTERVAL));
        if let Err(error) = wait_remaining(caller, deadline, "initializing netlink") {
            break Err(error);
        }
        match received {
            Ok(result) => break Ok(result),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break Err(netlink_worker_panicked()),
        }
    };
    match result {
        Ok(Ok(())) => Ok(WorkerSlot {
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
            inbox,
            worker,
        }),
        Ok(Err(error)) => {
            settle(worker, caller, deadline);
            Err(error)
        }
        Err(error) => {
            // Initialization may still be running. Stop waiting cooperatively,
            // but retain its charge until the initializer and cleanup return.
            worker.retention_marker().mark_retained();
            inbox.abandon();
            settle(worker, caller, deadline);
            Err(error)
        }
    }
}

fn settle(worker: Task<()>, caller: &Deadline, deadline: Instant) {
    let remaining = remaining_before(deadline).unwrap_or_default();
    let wait = caller
        .for_wait(remaining)
        .unwrap_or_else(|_| Deadline::new(Duration::ZERO));
    if let Waited::Pending(worker) = worker.wait(&wait) {
        worker.retention_marker().mark_retained();
    }
}

fn run_worker(setup: &SyncSender<Result<(), route::Error>>, inbox: &Inbox) {
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
        control,
    }) = inbox.next()
    {
        let _in_flight = RequestInFlight(inbox);
        if let Err(error) = check_control(&control, STARTING_OPERATION) {
            let _ = respond.send(Err(error));
            continue;
        }
        if remaining_before(deadline).is_none() {
            let _ = respond.send(Err(netlink_timeout(STARTING_OPERATION)));
            continue;
        }
        // Keep unstarted requests when a socket fails; an invoked operation is never replayed.
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
        let remaining = match wait_remaining(&control, deadline, STARTING_OPERATION) {
            Ok(remaining) => remaining,
            Err(error) => {
                let _ = respond.send(Err(error));
                continue;
            }
        };
        let (result, discard_connection) = match catch_unwind(AssertUnwindSafe(|| {
            runtime.block_on(await_netlink_operation(
                operation(handle.clone()),
                &mut connection,
                remaining,
                &control,
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
            // Dropping a request future does not clear netlink-proto's pending reply map.
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
    control: &Deadline,
) -> Result<T, route::Error>
where
    F: Future<Output = Result<T, route::Error>>,
{
    check_control(control, EXECUTING_OPERATION)?;
    let operation = std::pin::pin!(tokio::time::timeout(timeout, operation));
    let interrupted = std::pin::pin!(interrupted(control));
    let result = match select(connection, select(operation, interrupted)).await {
        Either::Left((joined, _)) => match joined {
            Ok(()) => Err(route::Error::OperatingSystem {
                operation: "drive netlink connection",
                message: "route netlink connection stopped".to_owned(),
                source: None,
            }),
            Err(error) => Err(os_error("drive netlink connection", error)),
        },
        Either::Right((Either::Left((result, _)), _)) => {
            result.unwrap_or_else(|_| Err(netlink_timeout(EXECUTING_OPERATION)))
        }
        Either::Right((Either::Right((interrupted, _)), _)) => {
            Err(route::Error::interrupted(interrupted, EXECUTING_OPERATION))
        }
    };
    check_control(control, EXECUTING_OPERATION)?;
    result
}

async fn interrupted(control: &Deadline) -> Interrupted {
    loop {
        if let Err(interrupted) = control.enforce() {
            return interrupted;
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

fn netlink_timeout(operation: &'static str) -> route::Error {
    route::Error::DeadlineExceeded { operation }
}

fn check_control(caller: &Deadline, operation: &'static str) -> Result<(), route::Error> {
    caller
        .enforce()
        .map_err(|interrupted| route::Error::interrupted(interrupted, operation))
}

fn wait_remaining(
    caller: &Deadline,
    deadline: Instant,
    operation: &'static str,
) -> Result<Duration, route::Error> {
    check_control(caller, operation)?;
    remaining_before(deadline).ok_or_else(|| netlink_timeout(operation))
}

#[cfg(test)]
mod tests;
