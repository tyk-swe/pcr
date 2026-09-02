// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded route-netlink execution on a caller-namespace worker thread.

use std::{
    future::Future,
    sync::Arc,
    sync::mpsc::{self, SyncSender},
    thread::{self, JoinHandle},
    time::Duration,
};

use rtnetlink::{Handle, new_connection};

use crate::platform::os_error;
use crate::{
    platform::worker_reaper::{
        JoinAttempt, ReapTask, ReaperClient, ReaperPermit, TransferOutcome, join_with_deadline,
        shared_reaper, wait_until_finished,
    },
    route::SystemError,
};

const NETLINK_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const NETLINK_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const NETLINK_REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) fn with_netlink<F, Fut, T>(operation: F) -> Result<T, SystemError>
where
    F: FnOnce(Handle) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, SystemError>> + Send + 'static,
    T: Send + 'static,
{
    let reaper = shared_reaper().map_err(|error| SystemError::OperatingSystem {
        operation: "initialize native worker cleanup",
        message: "the shared native worker cleanup service is unavailable".to_owned(),
        source: Some(Arc::new(error)),
    })?;
    let permit = reaper
        .reserve()
        .map_err(|error| SystemError::OperatingSystem {
            operation: "reserve native worker cleanup",
            message: format!(
                "shared native worker cleanup capacity {} is exhausted",
                error.capacity
            ),
            source: None,
        })?;
    let (setup, setup_receiver) = mpsc::sync_channel(1);
    let (response, response_receiver) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("packetcraftr-netlink".to_owned())
        .spawn(move || netlink_worker(operation, setup, response))
        .map_err(|error| os_error("spawn netlink worker", error))?;

    match setup_receiver.recv_timeout(NETLINK_OPERATION_TIMEOUT) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return finish_failed_start(worker, permit, &reaper, error),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return finish_failed_start(
                worker,
                permit,
                &reaper,
                netlink_channel_error("setup response channel closed"),
            );
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = transfer_netlink_worker(worker, permit, &reaper);
            return Err(netlink_timeout("initialize netlink"));
        }
    }

    let result = match response_receiver.recv_timeout(NETLINK_RESPONSE_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            join_netlink_worker(worker, permit, &reaper, NETLINK_RESPONSE_TIMEOUT)?;
            return Err(netlink_channel_error("response channel closed"));
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = transfer_netlink_worker(worker, permit, &reaper);
            return Err(netlink_timeout("wait for netlink response"));
        }
    };
    join_netlink_worker(worker, permit, &reaper, NETLINK_RESPONSE_TIMEOUT)?;
    result
}

fn finish_failed_start<T>(
    worker: JoinHandle<()>,
    permit: ReaperPermit,
    reaper: &ReaperClient,
    error: SystemError,
) -> Result<T, SystemError> {
    join_netlink_worker(worker, permit, reaper, NETLINK_RESPONSE_TIMEOUT)?;
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

fn join_netlink_worker(
    worker: JoinHandle<()>,
    permit: ReaperPermit,
    reaper: &ReaperClient,
    timeout: Duration,
) -> Result<(), SystemError> {
    match join_with_deadline(worker, timeout, NETLINK_REAPER_POLL_INTERVAL) {
        JoinAttempt::TimedOut(worker) => {
            let _ = transfer_netlink_worker(worker, permit, reaper);
            Err(netlink_timeout("shut down netlink worker"))
        }
        JoinAttempt::Finished(result) => {
            drop(permit);
            result.map_err(|_| netlink_worker_panicked())
        }
    }
}

fn transfer_netlink_worker(
    worker: JoinHandle<()>,
    permit: ReaperPermit,
    reaper: &ReaperClient,
) -> TransferOutcome {
    reaper.transfer(ReapTask::new(move || {
        let _permit = permit;
        wait_until_finished(worker, NETLINK_REAPER_POLL_INTERVAL, || {});
    }))
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
    use std::future;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use super::*;
    use crate::platform::worker_reaper::test_support::client_with_receiver;

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
        let (reaper, receiver) = client_with_receiver(1, 1);
        let permit = reaper.reserve().expect("test reaper reservation");
        assert!(matches!(
            join_netlink_worker(worker, permit, &reaper, Duration::ZERO),
            Err(SystemError::OperatingSystem {
                operation: "shut down netlink worker",
                ..
            })
        ));
        release.store(true, Ordering::Release);
        let task = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("timed-out worker transferred to the reaper");
        task.run();
    }
}
