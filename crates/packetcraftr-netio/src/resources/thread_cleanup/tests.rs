// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::{
    cell::RefCell,
    sync::mpsc,
    time::{Duration, Instant},
};

struct Owner {
    completed: mpsc::Sender<usize>,
    value: usize,
}
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.completed.send(self.value);
    }
}

fn owner(value: usize) -> (Owner, mpsc::Receiver<usize>) {
    let (completed, result) = mpsc::channel();
    (Owner { completed, value }, result)
}

fn complete_replacements(cleanup: &ThreadCleanup, expected: &[usize]) -> Vec<usize> {
    let slots: Vec<_> = expected.iter().map(|_| wait_for_slot(cleanup)).collect();
    assert!(cleanup.reserve().is_err());
    let completed: Vec<_> = slots
        .into_iter()
        .zip(expected)
        .map(|(slot, value)| {
            let (owner, completed) = owner(*value);
            assert!(slot.attach(std::thread::spawn(|| ()), owner));
            completed
        })
        .collect();
    completed
        .into_iter()
        .map(|result| result.recv_timeout(Duration::from_secs(5)).unwrap())
        .collect()
}

thread_local! {
    static CLEANUP_EXIT: RefCell<Option<Owner>> = const { RefCell::new(None) };
}

fn wait_for_slot(cleanup: &ThreadCleanup) -> ThreadJoinSlot {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match cleanup.reserve() {
            Ok(slot) => return slot,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "cleanup admission did not recover"
                );
                std::thread::yield_now();
            }
            Err(error) => panic!("unexpected cleanup admission error: {error}"),
        }
    }
}

#[test]
fn reservations_and_failed_transfers_keep_the_join_owner_until_actual_completion() {
    let cleanup = ThreadCleanup::new(1).unwrap();
    let slot = cleanup.reserve().unwrap();
    assert!(cleanup.reserve().is_err());
    drop(slot);
    let slot = cleanup.reserve().unwrap();
    let (owner, completed) = owner(7);
    let (release, held) = mpsc::channel();
    let thread = std::thread::spawn(move || held.recv().unwrap());
    cleanup.inner.refuse_next.store(true, Ordering::Release);
    assert!(!slot.attach(thread, owner));
    assert!(matches!(
        completed.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(cleanup.reserve().is_err());
    release.send(()).unwrap();
    assert_eq!(completed.recv_timeout(Duration::from_secs(5)).unwrap(), 7);
    assert_eq!(complete_replacements(&cleanup, &[11]), [11]);
}

#[test]
fn one_blocked_join_does_not_serialize_independent_cleanup_slots() {
    let cleanup = ThreadCleanup::new(2).unwrap();
    let (owner, completed) = owner(7);
    let (release, held) = mpsc::channel();
    cleanup
        .reserve()
        .unwrap()
        .attach(std::thread::spawn(move || held.recv().unwrap()), owner);
    for value in 0..8 {
        let (owner, other) = self::owner(value);
        assert!(wait_for_slot(&cleanup).attach(std::thread::spawn(|| ()), owner));
        assert_eq!(other.recv_timeout(Duration::from_secs(5)).unwrap(), value);
        assert!(matches!(
            completed.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }
    release.send(()).unwrap();
    assert_eq!(completed.recv_timeout(Duration::from_secs(5)).unwrap(), 7);
    assert_eq!(complete_replacements(&cleanup, &[11, 13]), [11, 13]);
}

#[test]
fn dropping_last_cleanup_owner_retries_and_releases_worker_resources() {
    let cleanup = ThreadCleanup::new(1).unwrap();
    let (thread_exit, exited) = owner(13);
    let (installed, ready) = mpsc::channel();
    assert!(
        cleanup
            .inner
            .service
            .client()
            .try_transfer(Box::new(move || {
                CLEANUP_EXIT.with(|slot| *slot.borrow_mut() = Some(thread_exit));
                installed.send(()).unwrap();
            }))
            .is_ok()
    );
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    let (owner, completed) = owner(7);
    let (release, held) = mpsc::channel();
    cleanup.inner.refuse_next.store(true, Ordering::Release);
    assert!(
        !cleanup
            .reserve()
            .unwrap()
            .attach(std::thread::spawn(move || held.recv().unwrap()), owner,)
    );
    assert!(matches!(
        completed.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(matches!(exited.try_recv(), Err(mpsc::TryRecvError::Empty)));
    drop(cleanup);
    release.send(()).unwrap();
    assert_eq!(completed.recv_timeout(Duration::from_secs(5)).unwrap(), 7);
    assert_eq!(exited.recv_timeout(Duration::from_secs(5)).unwrap(), 13);
}

struct BlockingOwner {
    entered: mpsc::Sender<()>,
    released: mpsc::Receiver<()>,
}
impl Drop for BlockingOwner {
    fn drop(&mut self) {
        self.entered.send(()).unwrap();
        self.released.recv_timeout(Duration::from_secs(5)).unwrap();
    }
}

#[test]
fn arbitrary_owner_drop_remains_charged_to_cleanup_after_the_thread_has_joined() {
    let cleanup = ThreadCleanup::new(1).unwrap();
    let (entered, dropping) = mpsc::channel();
    let (release, released) = mpsc::channel();
    cleanup.reserve().unwrap().attach(
        std::thread::spawn(|| ()),
        BlockingOwner { entered, released },
    );
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(cleanup.reserve().is_err());
    release.send(()).unwrap();
    assert_eq!(complete_replacements(&cleanup, &[17]), [17]);
}
