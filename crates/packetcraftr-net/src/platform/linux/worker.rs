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
            // Namespace metadata is only needed to cache workers safely. A
            // fresh thread inherits the caller's current network namespace,
            // so netlink remains usable when procfs is not mounted.
            NETLINK_WORKER.with(|worker| worker.borrow_mut().take());
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
            // Linux network namespaces are selected per calling thread. Drop
            // and join a worker inherited from an earlier namespace before
            // opening a netlink socket in the caller's current namespace.
            worker.take();
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
                // A broken command or response channel means this worker can
                // no longer make progress. Joining it here lets the next call
                // initialize a fresh worker instead of retaining a dead one.
                worker.take();
                Err(error)
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
}

impl NetlinkWorker {
    pub(super) fn start(namespace: NetworkNamespaceId) -> Result<Self, NativeRouteError> {
        let (commands, command_receiver) = mpsc::channel();
        let (setup_sender, setup_receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("packetcraftr-netlink".to_owned())
            .spawn(move || netlink_worker(command_receiver, setup_sender))
            .map_err(|error| os_error("spawn netlink worker", error))?;

        match setup_receiver.recv_timeout(NETLINK_OPERATION_TIMEOUT) {
            Ok(Ok(())) => Ok(Self {
                namespace,
                commands,
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if thread.join().is_err() {
                    Err(netlink_worker_panicked())
                } else {
                    Err(netlink_channel_error("setup response channel closed"))
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(netlink_timeout("initialize netlink")),
        }
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
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        let send_result = self.commands.send(NetlinkCommand::Shutdown);
        join_netlink_worker(thread, NETLINK_RESPONSE_TIMEOUT)?;
        send_result.map_err(|_| netlink_channel_error("shutdown command channel closed"))
    }
}

impl Drop for NetlinkWorker {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
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

fn join_netlink_worker(thread: JoinHandle<()>, timeout: Duration) -> Result<(), NativeRouteError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| netlink_timeout("shut down netlink worker"))?;
    while !thread.is_finished() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(netlink_timeout("shut down netlink worker"));
        };
        thread::park_timeout(remaining.min(Duration::from_millis(10)));
    }
    thread.join().map_err(|_| netlink_worker_panicked())
}

#[cfg(test)]
mod tests {
    use std::{
        future,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    use super::*;

    #[test]
    fn netlink_operation_timeout_cancels_pending_future() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let error = runtime
            .block_on(await_netlink_operation(
                future::pending::<Result<(), NativeRouteError>>(),
                Duration::ZERO,
            ))
            .unwrap_err();

        assert!(matches!(
            error,
            NativeRouteError::OperatingSystem {
                operation: "execute netlink operation",
                ..
            }
        ));
    }

    #[test]
    fn netlink_worker_shutdown_wait_is_bounded() {
        let release = Arc::new(AtomicBool::new(false));
        let worker_release = Arc::clone(&release);
        let worker = thread::spawn(move || {
            while !worker_release.load(Ordering::Acquire) {
                thread::park_timeout(Duration::from_millis(1));
            }
        });

        assert!(matches!(
            join_netlink_worker(worker, Duration::ZERO),
            Err(NativeRouteError::OperatingSystem {
                operation: "shut down netlink worker",
                ..
            })
        ));
        release.store(true, Ordering::Release);
    }
}
