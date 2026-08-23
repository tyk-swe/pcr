// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded route-netlink execution on a caller-namespace worker thread.

#![forbid(unsafe_code)]

use std::{
    future::Future,
    sync::mpsc::{self, SyncSender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use rtnetlink::{Handle, new_connection};

use crate::route::SystemError;

const NETLINK_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const NETLINK_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const NETLINK_REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(in crate::platform) fn os_error(
    operation: &'static str,
    error: impl std::fmt::Display,
) -> SystemError {
    SystemError::OperatingSystem {
        operation,
        message: error.to_string(),
    }
}

pub(super) fn with_netlink<F, Fut, T>(operation: F) -> Result<T, SystemError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, SystemError>> + Send + 'static,
    T: Send + 'static,
{
    // ponytail: one worker per call; restore namespace-local reuse only if route benchmarks show
    // startup dominates.
    let (setup, setup_receiver) = mpsc::sync_channel(1);
    let (response, response_receiver) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("packetcraftr-netlink".to_owned())
        .spawn(move || netlink_worker(operation, setup, response))
        .map_err(|error| os_error("spawn netlink worker", error))?;

    match setup_receiver.recv_timeout(NETLINK_OPERATION_TIMEOUT) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return finish_failed_start(worker, error),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return finish_failed_start(
                worker,
                netlink_channel_error("setup response channel closed"),
            );
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            transfer_netlink_worker(worker);
            return Err(netlink_timeout("initialize netlink"));
        }
    }

    let result = match response_receiver.recv_timeout(NETLINK_RESPONSE_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            join_netlink_worker(worker, NETLINK_RESPONSE_TIMEOUT)?;
            return Err(netlink_channel_error("response channel closed"));
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            transfer_netlink_worker(worker);
            return Err(netlink_timeout("wait for netlink response"));
        }
    };
    join_netlink_worker(worker, NETLINK_RESPONSE_TIMEOUT)?;
    result
}

fn finish_failed_start<T>(worker: JoinHandle<()>, error: SystemError) -> Result<T, SystemError> {
    join_netlink_worker(worker, NETLINK_RESPONSE_TIMEOUT)?;
    Err(error)
}

fn netlink_worker<F, Fut, T>(
    operation: F,
    setup: SyncSender<Result<(), SystemError>>,
    response: SyncSender<Result<T, SystemError>>,
) where
    F: FnOnce(Handle) -> Fut,
    Fut: Future<Output = Result<T, SystemError>>,
{
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
    let result = runtime.block_on(await_netlink_operation(
        operation(handle),
        NETLINK_OPERATION_TIMEOUT,
    ));
    connection.abort();
    let _ = response.send(result);
}

async fn await_netlink_operation<F, T>(operation: F, timeout: Duration) -> Result<T, SystemError>
where
    F: Future<Output = Result<T, SystemError>>,
{
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| netlink_timeout("execute netlink operation"))?
}

fn join_netlink_worker(worker: JoinHandle<()>, timeout: Duration) -> Result<(), SystemError> {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        transfer_netlink_worker(worker);
        return Err(netlink_timeout("shut down netlink worker"));
    };
    while !worker.is_finished() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            transfer_netlink_worker(worker);
            return Err(netlink_timeout("shut down netlink worker"));
        };
        thread::park_timeout(remaining.min(NETLINK_REAPER_POLL_INTERVAL));
    }
    worker.join().map_err(|_| netlink_worker_panicked())
}

fn transfer_netlink_worker(worker: JoinHandle<()>) {
    let _ = thread::Builder::new()
        .name("packetcraftr-netlink-reaper".to_owned())
        .spawn(move || {
            while !worker.is_finished() {
                thread::park_timeout(NETLINK_REAPER_POLL_INTERVAL);
            }
            let _ = worker.join();
        })
        .expect("could not start the Linux netlink worker reaper");
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
    }
}

#[cfg(test)]
mod tests {
    use std::future;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;

    #[test]
    fn operation_and_join_waits_are_bounded() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        assert!(matches!(
            runtime.block_on(await_netlink_operation(
                future::pending::<Result<(), SystemError>>(),
                Duration::ZERO,
            )),
            Err(SystemError::OperatingSystem {
                operation: "execute netlink operation",
                ..
            })
        ));

        let release = Arc::new(AtomicBool::new(false));
        let worker_release = Arc::clone(&release);
        let worker = thread::spawn(move || {
            while !worker_release.load(Ordering::Acquire) {
                thread::park_timeout(Duration::from_millis(1));
            }
        });
        assert!(matches!(
            join_netlink_worker(worker, Duration::ZERO),
            Err(SystemError::OperatingSystem {
                operation: "shut down netlink worker",
                ..
            })
        ));
        release.store(true, Ordering::Release);
    }
}
