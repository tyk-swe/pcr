// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Namespace-aware netlink worker, cache, channel, and runtime lifecycle.

#![forbid(unsafe_code)]

use std::{
    any::Any,
    cell::RefCell,
    fs,
    future::Future,
    os::unix::fs::MetadataExt,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::mpsc::{self, Receiver, Sender, SyncSender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use rtnetlink::{Handle, new_connection};

use super::os_error;
use crate::route::NativeRouteError;

const NETLINK_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const NETLINK_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const NETLINK_REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) fn with_netlink<F, Fut, T>(operation: F) -> Result<T, NativeRouteError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, NativeRouteError>> + Send + 'static,
    T: Send + 'static,
{
    with_netlink_for_namespace(current_network_namespace(), operation)
}

pub(super) fn with_netlink_for_namespace<F, Fut, T>(
    namespace: Option<NetworkNamespaceId>,
    operation: F,
) -> Result<T, NativeRouteError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, NativeRouteError>> + Send + 'static,
    T: Send + 'static,
{
    match namespace {
        Some(namespace) => with_netlink_in_namespace(namespace, operation),
        None => {
            // Without namespace metadata, do not cache workers; fresh threads inherit the caller's namespace.
            NETLINK_WORKER.with(|worker| retire_cached_worker(&mut worker.borrow_mut()))?;
            with_uncached_netlink(operation)
        }
    }
}

pub(super) fn with_netlink_in_namespace<F, Fut, T>(
    namespace: NetworkNamespaceId,
    operation: F,
) -> Result<T, NativeRouteError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, NativeRouteError>> + Send + 'static,
    T: Send + 'static,
{
    NETLINK_WORKER.with(|worker| {
        let mut worker = worker.borrow_mut();
        if worker
            .as_ref()
            .is_none_or(|worker| worker.namespace != namespace)
        {
            // Replace workers created in another per-thread network namespace.
            retire_cached_worker(&mut worker)?;
            *worker = Some(NetlinkWorker::start(namespace)?);
        }
        let result = worker
            .as_ref()
            .expect("the netlink worker was initialized above")
            .execute(operation);
        match result {
            Ok(value) => Ok(value),
            Err(NetlinkExecutionError::Operation(error)) => Err(error),
            Err(NetlinkExecutionError::Worker(error)) => {
                // A broken channel makes this worker unusable. Retire it before
                // the slot is reused; a finite cleanup timeout transfers any
                // unfinished thread to the reaper.
                match retire_cached_worker(&mut worker) {
                    Err(cleanup_error) => Err(cleanup_error),
                    Ok(()) => Err(error),
                }
            }
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NetworkNamespaceId {
    pub(super) device: u64,
    pub(super) inode: u64,
}

pub(super) fn current_network_namespace() -> Option<NetworkNamespaceId> {
    let metadata = fs::metadata("/proc/thread-self/ns/net").ok()?;
    Some(NetworkNamespaceId {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn with_uncached_netlink<F, Fut, T>(operation: F) -> Result<T, NativeRouteError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, NativeRouteError>> + Send + 'static,
    T: Send + 'static,
{
    thread::Builder::new()
        .name("packetcraftr-netlink".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|error| os_error("create Tokio netlink runtime", error))?;
            runtime.block_on(async move {
                let (connection, handle, _) = new_connection()
                    .map_err(|error| os_error("open route netlink socket", error))?;
                let connection = tokio::spawn(connection);
                let result =
                    await_netlink_operation(operation(handle), NETLINK_OPERATION_TIMEOUT).await;
                connection.abort();
                result
            })
        })
        .map_err(|error| os_error("spawn netlink worker", error))?
        .join()
        .map_err(|_| netlink_worker_panicked())?
}

thread_local! {
    pub(super) static NETLINK_WORKER: RefCell<Option<NetlinkWorker>> =
        const { RefCell::new(None) };
}

fn retire_cached_worker(worker: &mut Option<NetlinkWorker>) -> Result<(), NativeRouteError> {
    let shutdown_result = worker.as_mut().map(NetlinkWorker::shutdown);
    if let Some(mut worker) = worker.take() {
        worker.transfer_to_reaper();
    }
    shutdown_result.unwrap_or(Ok(()))
}

type ErasedNetlinkResult = Result<Box<dyn Any + Send>, NativeRouteError>;

type NetlinkFuture = Pin<Box<dyn Future<Output = ErasedNetlinkResult> + Send>>;

type NetlinkOperation = Box<dyn FnOnce(Handle) -> NetlinkFuture + Send>;

pub(super) enum NetlinkCommand {
    Execute {
        operation: NetlinkOperation,
        response: SyncSender<ErasedNetlinkResult>,
    },
    Shutdown,
}

pub(super) struct NetlinkWorker {
    pub(super) namespace: NetworkNamespaceId,
    pub(super) commands: Sender<NetlinkCommand>,
    pub(super) thread: Option<JoinHandle<()>>,
    shutdown_timeout: Duration,
    shutdown_result: Option<Result<(), NativeRouteError>>,
    shutdown_sent: bool,
}

impl NetlinkWorker {
    pub(super) fn start(namespace: NetworkNamespaceId) -> Result<Self, NativeRouteError> {
        let (commands, command_receiver) = mpsc::channel();
        let (setup_sender, setup_receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("packetcraftr-netlink".to_owned())
            .spawn(move || netlink_worker(command_receiver, setup_sender))
            .map_err(|error| os_error("spawn netlink worker", error))?;

        finish_netlink_start(
            namespace,
            commands,
            setup_receiver,
            thread,
            NETLINK_OPERATION_TIMEOUT,
        )
    }

    pub(super) fn execute<F, Fut, T>(&self, operation: F) -> Result<T, NetlinkExecutionError>
    where
        F: FnOnce(Handle) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, NativeRouteError>> + Send + 'static,
        T: Send + 'static,
    {
        let operation = Box::new(move |handle| {
            Box::pin(async move {
                operation(handle)
                    .await
                    .map(|value| Box::new(value) as Box<dyn Any + Send>)
            }) as NetlinkFuture
        });
        let (response, receiver) = mpsc::sync_channel(1);
        self.commands
            .send(NetlinkCommand::Execute {
                operation,
                response,
            })
            .map_err(|_| {
                NetlinkExecutionError::Worker(netlink_channel_error("command channel closed"))
            })?;
        let response =
            receiver
                .recv_timeout(NETLINK_RESPONSE_TIMEOUT)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Disconnected => NetlinkExecutionError::Worker(
                        netlink_channel_error("response channel closed"),
                    ),
                    mpsc::RecvTimeoutError::Timeout => {
                        NetlinkExecutionError::Worker(netlink_timeout("wait for netlink response"))
                    }
                })?;
        let value = response.map_err(NetlinkExecutionError::Operation)?;
        value.downcast::<T>().map(|value| *value).map_err(|_| {
            NetlinkExecutionError::Worker(netlink_channel_error(
                "returned an unexpected response type",
            ))
        })
    }

    pub(super) fn shutdown(&mut self) -> Result<(), NativeRouteError> {
        self.shutdown_with_timeout(self.shutdown_timeout)
    }

    fn shutdown_with_timeout(&mut self, timeout: Duration) -> Result<(), NativeRouteError> {
        if let Some(result) = &self.shutdown_result {
            return result.clone();
        }
        if self.thread.is_none() {
            let result = Ok(());
            self.shutdown_result = Some(result.clone());
            return result;
        }
        let send_result = if self.shutdown_sent {
            Ok(())
        } else {
            match self.commands.send(NetlinkCommand::Shutdown) {
                Ok(()) => {
                    self.shutdown_sent = true;
                    Ok(())
                }
                Err(_) => Err(netlink_channel_error("shutdown command channel closed")),
            }
        };
        let join_result = match join_netlink_worker(&mut self.thread, timeout) {
            NetlinkJoinAttempt::TimedOut(error) => return Err(error),
            NetlinkJoinAttempt::Finished(result) => result,
        };
        let result = join_result.and(send_result);
        self.shutdown_result = Some(result.clone());
        result
    }

    fn transfer_to_reaper(&mut self) {
        if let Some(thread) = self.thread.take() {
            transfer_netlink_worker(thread, self.commands.clone());
        }
    }
}

impl Drop for NetlinkWorker {
    fn drop(&mut self) {
        let _ = self.shutdown();
        self.transfer_to_reaper();
    }
}

fn finish_netlink_start(
    namespace: NetworkNamespaceId,
    commands: Sender<NetlinkCommand>,
    setup_receiver: Receiver<Result<(), NativeRouteError>>,
    thread: JoinHandle<()>,
    setup_timeout: Duration,
) -> Result<NetlinkWorker, NativeRouteError> {
    finish_netlink_start_with_callback(
        namespace,
        commands,
        setup_receiver,
        thread,
        setup_timeout,
        NETLINK_RESPONSE_TIMEOUT,
        || {},
    )
}

fn finish_netlink_start_with_callback<F>(
    namespace: NetworkNamespaceId,
    commands: Sender<NetlinkCommand>,
    setup_receiver: Receiver<Result<(), NativeRouteError>>,
    thread: JoinHandle<()>,
    setup_timeout: Duration,
    shutdown_timeout: Duration,
    after_reap: F,
) -> Result<NetlinkWorker, NativeRouteError>
where
    F: FnOnce() + Send + 'static,
{
    match setup_receiver.recv_timeout(setup_timeout) {
        Ok(Ok(())) => Ok(NetlinkWorker {
            namespace,
            commands,
            thread: Some(thread),
            shutdown_timeout,
            shutdown_result: None,
            shutdown_sent: false,
        }),
        Ok(Err(error)) => {
            finish_failed_netlink_start(commands, thread, error, shutdown_timeout, after_reap)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => finish_failed_netlink_start(
            commands,
            thread,
            netlink_channel_error("setup response channel closed"),
            shutdown_timeout,
            after_reap,
        ),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            transfer_netlink_worker_with_callback(thread, commands, after_reap);
            Err(netlink_timeout("initialize netlink"))
        }
    }
}

fn finish_failed_netlink_start<F>(
    commands: Sender<NetlinkCommand>,
    thread: JoinHandle<()>,
    startup_error: NativeRouteError,
    shutdown_timeout: Duration,
    after_reap: F,
) -> Result<NetlinkWorker, NativeRouteError>
where
    F: FnOnce() + Send + 'static,
{
    let _ = commands.send(NetlinkCommand::Shutdown);
    let mut thread = Some(thread);
    match join_netlink_worker(&mut thread, shutdown_timeout) {
        NetlinkJoinAttempt::Finished(Ok(())) => Err(startup_error),
        NetlinkJoinAttempt::Finished(Err(error)) => Err(error),
        NetlinkJoinAttempt::TimedOut(error) => {
            let thread = thread
                .take()
                .expect("timed-out netlink startup worker handle disappeared");
            transfer_netlink_worker_with_callback(thread, commands, after_reap);
            Err(error)
        }
    }
}

fn transfer_netlink_worker(thread: JoinHandle<()>, commands: Sender<NetlinkCommand>) {
    transfer_netlink_worker_with_callback(thread, commands, || {});
}

fn transfer_netlink_worker_with_callback<F>(
    thread: JoinHandle<()>,
    commands: Sender<NetlinkCommand>,
    after_join: F,
) where
    F: FnOnce() + Send + 'static,
{
    let _ = thread::Builder::new()
        .name("packetcraftr-netlink-reaper".to_owned())
        .spawn(move || {
            let _ = commands.send(NetlinkCommand::Shutdown);
            while !thread.is_finished() {
                thread::park_timeout(NETLINK_REAPER_POLL_INTERVAL);
            }
            let _ = thread.join();
            after_join();
        })
        .expect("could not start the Linux netlink worker reaper");
}

#[derive(Debug)]
pub(super) enum NetlinkExecutionError {
    Operation(NativeRouteError),
    Worker(NativeRouteError),
}

fn netlink_worker(
    commands: Receiver<NetlinkCommand>,
    setup: SyncSender<Result<(), NativeRouteError>>,
) {
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
    let (connection, handle, _) = match runtime.block_on(async { new_connection() }) {
        Ok(parts) => parts,
        Err(error) => {
            let _ = setup.send(Err(os_error("open route netlink socket", error)));
            return;
        }
    };
    let connection = runtime.spawn(connection);
    if setup.send(Ok(())).is_err() {
        connection.abort();
        return;
    }

    while let Ok(command) = commands.recv() {
        match command {
            NetlinkCommand::Execute {
                operation,
                response,
            } => {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    runtime.block_on(await_netlink_operation(
                        operation(handle.clone()),
                        NETLINK_OPERATION_TIMEOUT,
                    ))
                }))
                .unwrap_or_else(|_| Err(netlink_worker_panicked()));
                let _ = response.send(result);
            }
            NetlinkCommand::Shutdown => break,
        }
    }
    connection.abort();
}

async fn await_netlink_operation<F, T>(
    operation: F,
    timeout: Duration,
) -> Result<T, NativeRouteError>
where
    F: Future<Output = Result<T, NativeRouteError>>,
{
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| netlink_timeout("execute netlink operation"))?
}

fn netlink_worker_panicked() -> NativeRouteError {
    NativeRouteError::InvalidResponse {
        message: "Linux netlink worker panicked".to_owned(),
    }
}

fn netlink_channel_error(message: &'static str) -> NativeRouteError {
    NativeRouteError::InvalidResponse {
        message: format!("Linux netlink worker {message}"),
    }
}

fn netlink_timeout(operation: &'static str) -> NativeRouteError {
    NativeRouteError::OperatingSystem {
        operation,
        message: "finite operation deadline expired".to_owned(),
    }
}

enum NetlinkJoinAttempt {
    Finished(Result<(), NativeRouteError>),
    TimedOut(NativeRouteError),
}

fn join_netlink_worker(
    thread: &mut Option<JoinHandle<()>>,
    timeout: Duration,
) -> NetlinkJoinAttempt {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return NetlinkJoinAttempt::TimedOut(netlink_timeout("shut down netlink worker"));
    };
    loop {
        let Some(handle) = thread.as_ref() else {
            return NetlinkJoinAttempt::Finished(Ok(()));
        };
        if handle.is_finished() {
            break;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return NetlinkJoinAttempt::TimedOut(netlink_timeout("shut down netlink worker"));
        };
        thread::park_timeout(remaining.min(NETLINK_REAPER_POLL_INTERVAL));
    }
    let handle = thread
        .take()
        .expect("finished netlink worker handle disappeared");
    NetlinkJoinAttempt::Finished(handle.join().map_err(|_| netlink_worker_panicked()))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    const TEST_NAMESPACE: NetworkNamespaceId = NetworkNamespaceId {
        device: 1,
        inode: 2,
    };
    const TEST_TIMEOUT: Duration = Duration::from_millis(5);

    fn worker_from_parts(
        commands: Sender<NetlinkCommand>,
        thread: JoinHandle<()>,
        shutdown_timeout: Duration,
    ) -> NetlinkWorker {
        NetlinkWorker {
            namespace: TEST_NAMESPACE,
            commands,
            thread: Some(thread),
            shutdown_timeout,
            shutdown_result: None,
            shutdown_sent: false,
        }
    }

    fn retryable_worker() -> (NetlinkWorker, Sender<()>, Receiver<()>) {
        let (commands, command_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (finished_sender, finished_receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            let _ = command_receiver.recv();
            let _ = release_receiver.recv();
            drop(command_receiver);
            let _ = finished_sender.send(());
        });
        (
            worker_from_parts(commands, thread, TEST_TIMEOUT),
            release_sender,
            finished_receiver,
        )
    }

    fn reapable_worker() -> (NetlinkWorker, Sender<()>, Receiver<()>) {
        let (commands, command_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let (finished_sender, finished_receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            let _ = command_receiver.recv();
            let _ = release_receiver.recv();
            let _ = finished_sender.send(());
        });
        (
            worker_from_parts(commands, thread, TEST_TIMEOUT),
            release_sender,
            finished_receiver,
        )
    }

    #[test]
    fn shutdown_timeout_preserves_netlink_ownership_for_retry() {
        let (mut worker, release_sender, finished_receiver) = retryable_worker();

        assert!(matches!(
            worker.shutdown(),
            Err(NativeRouteError::OperatingSystem {
                operation: "shut down netlink worker",
                ..
            })
        ));
        assert!(worker.thread.is_some());
        assert!(worker.shutdown_result.is_none());

        release_sender
            .send(())
            .expect("release fake netlink worker");
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("queued shutdown should close the fake netlink worker");
        assert_eq!(worker.shutdown(), Ok(()));
        assert!(worker.thread.is_none());
        assert_eq!(worker.shutdown(), Ok(()));
    }

    #[test]
    fn netlink_worker_panic_is_terminal_and_cached() {
        let (commands, command_receiver) = mpsc::channel();
        drop(command_receiver);
        let thread = thread::spawn(|| panic!("fake netlink worker panic"));
        let mut worker = worker_from_parts(commands, thread, Duration::from_millis(100));

        let first = worker
            .shutdown()
            .expect_err("worker panic must be reported");
        let second = worker
            .shutdown()
            .expect_err("cached worker panic must remain terminal");
        assert_eq!(first, second);
        assert_eq!(
            first,
            NativeRouteError::InvalidResponse {
                message: "Linux netlink worker panicked".to_owned()
            }
        );
        assert!(worker.thread.is_none());
    }

    #[test]
    fn startup_timeout_transfers_spawned_worker_to_reaper() {
        let (commands, command_receiver) = mpsc::channel();
        let (setup_sender, setup_receiver) = mpsc::sync_channel(1);
        let (finished_sender, finished_receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            let _setup_sender = setup_sender;
            let _ = command_receiver.recv();
            let _ = finished_sender.send(());
        });
        let (reaped_sender, reaped_receiver) = mpsc::channel();

        let result = finish_netlink_start_with_callback(
            TEST_NAMESPACE,
            commands,
            setup_receiver,
            thread,
            TEST_TIMEOUT,
            TEST_TIMEOUT,
            move || {
                let _ = reaped_sender.send(());
            },
        );
        assert!(matches!(
            result,
            Err(NativeRouteError::OperatingSystem {
                operation: "initialize netlink",
                ..
            })
        ));
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("startup reaper should release the fake worker");
        reaped_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("startup reaper should join the fake worker");
    }

    #[test]
    fn thread_local_replacement_transfers_old_worker() {
        let (worker, release_sender, finished_receiver) = reapable_worker();

        NETLINK_WORKER.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.replace(worker).is_none());
            assert!(matches!(
                retire_cached_worker(&mut slot),
                Err(NativeRouteError::OperatingSystem {
                    operation: "shut down netlink worker",
                    ..
                })
            ));
            assert!(slot.is_none());
        });

        release_sender
            .send(())
            .expect("release replaced netlink worker");
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("replacement reaper should join the old worker");
    }

    #[test]
    fn broken_channel_transfers_still_running_worker() {
        let (commands, command_receiver) = mpsc::channel();
        drop(command_receiver);
        let (release_sender, release_receiver) = mpsc::channel();
        let (finished_sender, finished_receiver) = mpsc::channel();
        let thread = thread::spawn(move || {
            let _ = release_receiver.recv();
            let _ = finished_sender.send(());
        });
        let mut slot = Some(worker_from_parts(commands, thread, TEST_TIMEOUT));
        let worker_error = slot
            .as_ref()
            .expect("worker should exist")
            .execute(|_handle| async { Ok::<(), NativeRouteError>(()) })
            .expect_err("closed command channel must be a worker error");
        assert!(matches!(worker_error, NetlinkExecutionError::Worker(_)));

        assert!(matches!(
            retire_cached_worker(&mut slot),
            Err(NativeRouteError::OperatingSystem {
                operation: "shut down netlink worker",
                ..
            })
        ));
        assert!(slot.is_none());
        release_sender
            .send(())
            .expect("release broken-channel worker");
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("broken-channel reaper should join the worker");
    }

    #[test]
    fn setup_failure_joins_worker_before_returning() {
        let (commands, command_receiver) = mpsc::channel();
        let (setup_sender, setup_receiver) = mpsc::sync_channel(1);
        let (finished_sender, finished_receiver) = mpsc::channel();
        setup_sender
            .send(Err(NativeRouteError::InvalidResponse {
                message: "fake setup failure".to_owned(),
            }))
            .expect("send fake setup failure");
        let thread = thread::spawn(move || {
            let _ = command_receiver.recv();
            let _ = finished_sender.send(());
        });

        let result = finish_netlink_start(
            TEST_NAMESPACE,
            commands,
            setup_receiver,
            thread,
            TEST_TIMEOUT,
        );
        assert!(matches!(
            result,
            Err(NativeRouteError::InvalidResponse { message })
                if message == "fake setup failure"
        ));
        finished_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("setup failure should join the worker");
    }

    #[test]
    fn reaper_test_support_keeps_ownership_until_join() {
        let finished = Arc::new(AtomicBool::new(false));
        let (release_sender, release_receiver) = mpsc::channel();
        let finished_for_worker = Arc::clone(&finished);
        let thread = thread::spawn(move || {
            let _ = release_receiver.recv();
            finished_for_worker.store(true, Ordering::Release);
        });
        let (reaped_sender, reaped_receiver) = mpsc::channel();

        transfer_netlink_worker_with_callback(thread, commands_for_reaper_test(), move || {
            let _ = reaped_sender.send(());
        });
        assert!(!finished.load(Ordering::Acquire));
        release_sender.send(()).expect("release reaper test worker");
        reaped_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("reaper should eventually join its worker");
        assert!(finished.load(Ordering::Acquire));
    }

    fn commands_for_reaper_test() -> Sender<NetlinkCommand> {
        let (commands, receiver) = mpsc::channel();
        drop(receiver);
        commands
    }
}
