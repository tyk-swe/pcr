// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

struct Owner(Arc<AtomicUsize>);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[test]
fn reservations_and_failed_transfers_keep_the_join_owner_until_actual_completion() {
    let cleanup = ThreadCleanup::new(1).unwrap();
    let slot = cleanup.reserve().unwrap();
    assert!(cleanup.reserve().is_err());
    drop(slot);
    let slot = cleanup.reserve().unwrap();
    let active = Arc::new(AtomicUsize::new(1));
    let (release, held) = mpsc::channel();
    let thread = std::thread::spawn(move || held.recv().unwrap());
    cleanup.inner.refuse_next.store(true, Ordering::Release);
    slot.attach(thread, Owner(Arc::clone(&active)));
    assert_eq!(cleanup.inner.pending.lock().unwrap().len(), 1);
    assert_eq!(active.load(Ordering::Acquire), 1);
    assert!(cleanup.reserve().is_err());
    assert!(cleanup.inner.pending.lock().unwrap().is_empty());
    release.send(()).unwrap();
    let guard = Instant::now() + Duration::from_secs(5);
    while active.load(Ordering::Acquire) != 0 || cleanup.inner.active.load(Ordering::Acquire) != 0 {
        assert!(Instant::now() < guard);
        std::thread::yield_now();
    }
    assert!(cleanup.reserve().is_ok());
}

#[test]
fn one_blocked_join_does_not_serialize_independent_cleanup_slots() {
    let cleanup = ThreadCleanup::new(2).unwrap();
    let active = Arc::new(AtomicUsize::new(1));
    let (release, held) = mpsc::channel();
    cleanup.reserve().unwrap().attach(
        std::thread::spawn(move || held.recv().unwrap()),
        Owner(Arc::clone(&active)),
    );
    for _ in 0..8 {
        let other = Arc::new(AtomicUsize::new(1));
        cleanup
            .reserve()
            .unwrap()
            .attach(std::thread::spawn(|| ()), Owner(Arc::clone(&other)));
        let guard = Instant::now() + Duration::from_secs(5);
        while other.load(Ordering::Acquire) != 0
            || cleanup.inner.active.load(Ordering::Acquire) != 1
        {
            assert!(Instant::now() < guard);
            std::thread::yield_now();
        }
        assert_eq!(active.load(Ordering::Acquire), 1);
    }
    release.send(()).unwrap();
}

#[test]
fn dropping_last_cleanup_owner_retries_a_failed_transfer_without_an_arc_cycle() {
    let cleanup = ThreadCleanup::new(1).unwrap();
    let weak = Arc::downgrade(&cleanup.inner);
    let active = Arc::new(AtomicUsize::new(1));
    let (release, held) = mpsc::channel();
    cleanup.inner.refuse_next.store(true, Ordering::Release);
    cleanup.reserve().unwrap().attach(
        std::thread::spawn(move || held.recv().unwrap()),
        Owner(Arc::clone(&active)),
    );
    assert_eq!(cleanup.inner.pending.lock().unwrap().len(), 1);
    drop(cleanup);
    release.send(()).unwrap();
    let guard = Instant::now() + Duration::from_secs(5);
    while active.load(Ordering::Acquire) != 0 || weak.upgrade().is_some() {
        assert!(
            Instant::now() < guard,
            "failed transfer retained a self-cycle after last cleanup owner dropped"
        );
        std::thread::yield_now();
    }
}

struct BlockingOwner {
    entered: mpsc::Sender<()>,
    released: Arc<(Mutex<bool>, std::sync::Condvar)>,
}
impl Drop for BlockingOwner {
    fn drop(&mut self) {
        self.entered.send(()).unwrap();
        let mut released = self.released.0.lock().unwrap();
        while !*released {
            released = self.released.1.wait(released).unwrap();
        }
    }
}

#[test]
fn arbitrary_owner_drop_remains_charged_to_cleanup_after_the_thread_has_joined() {
    let cleanup = ThreadCleanup::new(1).unwrap();
    let (entered, dropping) = mpsc::channel();
    let released = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    cleanup.reserve().unwrap().attach(
        std::thread::spawn(|| ()),
        BlockingOwner {
            entered,
            released: Arc::clone(&released),
        },
    );
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(cleanup.inner.active.load(Ordering::Acquire), 1);
    assert!(cleanup.reserve().is_err());
    *released.0.lock().unwrap() = true;
    released.1.notify_all();
    let guard = Instant::now() + Duration::from_secs(5);
    while cleanup.inner.active.load(Ordering::Acquire) != 0 {
        assert!(Instant::now() < guard);
        std::thread::yield_now();
    }
    assert!(cleanup.reserve().is_ok());
}
