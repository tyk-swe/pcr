// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded route-netlink execution on a caller-namespace worker thread.

use std::{
    future::Future,
    sync::mpsc::{self, SyncSender},
    thread,
    time::Duration,
};

use crate::{
    platform::{
        os_error,
        workers::{JoinAttempt, join_with_deadline, shared_budget},
    },
    route::SystemError,
};
use rtnetlink::{Handle, new_connection};

const NETLINK_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const NETLINK_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

pub(super) fn with_netlink<F, Fut, T>(operation: F) -> Result<T, SystemError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, SystemError>> + Send + 'static,
    T: Send + 'static,
{
    let permit = shared_budget()
        .reserve()
        .map_err(|error| SystemError::OperatingSystem {
            operation: "reserve native worker",
            message: format!("native worker capacity {} is exhausted", error.capacity),
            source: None,
        })?;
    let (setup, initialized) = mpsc::sync_channel(1);
    let (response, finished) = mpsc::sync_channel(1);
    // The new thread inherits the caller's network namespace. It owns the
    // runtime and socket; response publication follows their destruction.
    // A caller timeout releases its wait, while the worker retains its permit.
    let worker = thread::Builder::new()
        .name("packetcraftr-netlink".to_owned())
        .spawn(move || {
            let _permit = permit;
            let result = netlink_worker(operation, setup);
            let _ = response.send(result);
        })
        .map_err(|error| os_error("spawn netlink worker", error))?;
    match initialized.recv_timeout(NETLINK_OPERATION_TIMEOUT) {
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => return Err(netlink_timeout("initialize netlink")),
    }
    let result = match finished.recv_timeout(NETLINK_RESPONSE_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(netlink_worker_panicked()),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            return Err(netlink_timeout("wait for netlink response"));
        }
    };
    match join_with_deadline(worker, NETLINK_RESPONSE_TIMEOUT, Duration::from_millis(10)) {
        JoinAttempt::Finished(Ok(())) => result,
        JoinAttempt::Finished(Err(_)) => Err(netlink_worker_panicked()),
        JoinAttempt::TimedOut(worker) => {
            // The worker, including its permit, still owns its resources.
            drop(worker);
            Err(netlink_timeout("shut down netlink worker"))
        }
    }
}

fn netlink_worker<F, Fut, T>(operation: F, setup: SyncSender<()>) -> Result<T, SystemError>
where
    F: FnOnce(Handle) -> Fut,
    Fut: Future<Output = Result<T, SystemError>>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| os_error("create Tokio netlink runtime", error))?;
    let (connection, handle, _) = runtime
        .block_on(async { new_connection() })
        .map_err(|error| os_error("open route netlink socket", error))?;
    let connection = runtime.spawn(connection);
    if setup.send(()).is_err() {
        connection.abort();
        return Err(netlink_channel_error(
            "caller stopped waiting during initialization",
        ));
    }
    let result = runtime.block_on(await_netlink_operation(
        operation(handle),
        NETLINK_OPERATION_TIMEOUT,
    ));
    connection.abort();
    result
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

fn netlink_channel_error(message: &'static str) -> SystemError {
    SystemError::InvalidResponse {
        message: format!("Linux netlink worker {message}"),
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
}
