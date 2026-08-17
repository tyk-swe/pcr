// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Tests for netlink worker startup, shutdown, and reaping.

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
    let (mut worker, release_sender, finished_receiver) = reapable_worker();

    assert!(matches!(
        worker.shutdown(),
        Err(SystemError::OperatingSystem {
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
        SystemError::InvalidResponse {
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
        Err(SystemError::OperatingSystem {
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
            Err(SystemError::OperatingSystem {
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
        .execute(|_handle| async { Ok::<(), SystemError>(()) })
        .expect_err("closed command channel must be a worker error");
    assert!(matches!(worker_error, NetlinkExecutionError::Worker(_)));

    assert!(matches!(
        retire_cached_worker(&mut slot),
        Err(SystemError::OperatingSystem {
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
        .send(Err(SystemError::InvalidResponse {
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
        Err(SystemError::InvalidResponse { message })
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
