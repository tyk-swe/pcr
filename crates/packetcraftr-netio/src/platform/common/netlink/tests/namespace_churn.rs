// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit opt-in runtime evidence. This test is never an ordinary-suite pass.

use super::super::{NAMESPACE_PATH, RESIDENT_CAPACITY, shared_workers, with_netlink};
use crate::{resources, tcp, workers};
use futures_util::TryStreamExt;
use packetcraftr_core::budget::Deadline;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io,
    marker::PhantomData,
    net::TcpListener,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

struct RestoreNamespace {
    original: File,
    restored: bool,
    // A namespace belongs to this OS thread; this guard must never migrate.
    _thread: PhantomData<Rc<()>>,
}

impl RestoreNamespace {
    #[allow(unsafe_code)]
    fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        // SAFETY: `original` owns an open network-namespace FD throughout the
        // call. The non-Send guard restores only its creating test thread,
        // inside a launcher-verified isolated process. No memory pointers or
        // host-wide network settings are passed to the kernel.
        if unsafe { libc::setns(self.original.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.restored = true;
        Ok(())
    }
}
impl Drop for RestoreNamespace {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("failed to restore isolated test-thread namespace: {error}");
            // Never allow any further test work in an unexpected namespace.
            std::process::abort();
        }
    }
}

fn only_loopback() -> io::Result<bool> {
    let devices = fs::read_to_string("/proc/thread-self/net/dev")?;
    let names: Vec<_> = devices
        .lines()
        .skip(2)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .collect();
    Ok(names == ["lo"])
}

#[allow(unsafe_code)]
fn new_namespace(_restore: &RestoreNamespace) -> io::Result<File> {
    // SAFETY: this changes only the calling test thread's network namespace,
    // after the isolated launcher and loopback-only guard have been checked.
    // Existing worker threads retain their previous namespaces intentionally.
    // A live non-Send RestoreNamespace guard owns the original FD on all paths.
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return Err(io::Error::last_os_error());
    }
    assert!(
        only_loopback()?,
        "fresh namespace contains a non-loopback interface"
    );
    File::open(NAMESPACE_PATH)
}

fn namespace_fds() -> io::Result<usize> {
    Ok(fs::read_dir("/proc/self/fd")?
        .filter_map(Result::ok)
        .filter(|entry| {
            fs::read_link(entry.path())
                .is_ok_and(|target| target.to_string_lossy().starts_with("net:["))
        })
        .count())
}

fn query_loopback(up: bool) -> u32 {
    with_netlink(
        &Deadline::new(Duration::from_secs(5)),
        move |handle| async move {
            let mut links = handle.link().get().match_name("lo").execute();
            let link = links
                .try_next()
                .await
                .map_err(|error| super::super::os_error("query isolated loopback", error))?
                .ok_or_else(|| crate::route::Error::InvalidResponse {
                    message: "isolated namespace has no loopback".to_owned(),
                })?;
            if up {
                handle
                    .link()
                    .change(
                        rtnetlink::LinkUnspec::new_with_index(link.header.index)
                            .up()
                            .build(),
                    )
                    .execute()
                    .await
                    .map_err(|error| super::super::os_error("enable isolated loopback", error))?;
            }
            Ok(link.header.index)
        },
    )
    .expect("production native netlink lookup must complete")
}

fn resident_count() -> usize {
    let deadline = Deadline::new(Duration::from_secs(5));
    let end = Instant::now() + Duration::from_secs(5);
    shared_workers(&deadline, end).unwrap().len()
}

#[test]
#[ignore = "requires scripts/test-native-namespace-lifecycle.py in an authorized isolated Linux namespace"]
fn real_namespace_churn_recovers_resources() {
    let parent_fd: i32 = std::env::var("PACKETCRAFTR_N1_PARENT_FD")
        .expect("run only through the isolated lifecycle launcher")
        .parse()
        .unwrap();
    assert!(parent_fd >= 3);
    assert!(
        fs::read_link(format!("/proc/self/fd/{parent_fd}"))
            .unwrap()
            .to_string_lossy()
            .starts_with("net:[")
    );
    let parent = File::open(format!("/proc/self/fd/{parent_fd}"))
        .unwrap()
        .metadata()
        .unwrap()
        .ino();
    let original = File::open(NAMESPACE_PATH).unwrap();
    let initial_namespace = original.metadata().unwrap().ino();
    assert_ne!(initial_namespace, parent, "refusing non-fresh namespace");
    assert!(
        only_loopback().unwrap(),
        "refusing a namespace with non-loopback interfaces"
    );
    assert_eq!(
        resources::native_snapshot().active,
        0,
        "run this exact ignored test in a separate process"
    );
    let mut restore = RestoreNamespace {
        original,
        restored: false,
        _thread: PhantomData,
    };
    let baseline_fds = namespace_fds().unwrap();
    assert!(
        baseline_fds >= 2,
        "inherited parent and restore descriptors must be observable"
    );
    let mut pinned = Vec::new();
    let mut identities = BTreeSet::new();
    let mut resident_peak = 0;
    let mut root_peak = 0;
    let mut fd_peak = baseline_fds;
    let mut fd_bound_peak = baseline_fds;
    let visits = resources::WORKER_CAPACITY + RESIDENT_CAPACITY + 1;
    for index in 0..visits {
        let namespace = new_namespace(&restore).expect("create test-thread network namespace");
        assert!(
            identities.insert(namespace.metadata().unwrap().ino()),
            "pinned namespace identity was reused"
        );
        pinned.push(namespace);
        assert!(query_loopback(false) > 0);
        let resident = resident_count();
        resident_peak = resident_peak.max(resident);
        assert!(
            resident <= RESIDENT_CAPACITY,
            "resident service allocation exceeded at visit {index}"
        );
        root_peak = root_peak.max(resources::native_snapshot().active);
        let fds = namespace_fds().unwrap();
        let bound = baseline_fds + pinned.len() + resident;
        assert!(
            fds <= bound,
            "namespace descriptors escaped their actual owners at visit {index}: {fds} > {bound}"
        );
        fd_peak = fd_peak.max(fds);
        fd_bound_peak = fd_bound_peak.max(bound);
    }
    // Race a real request in the previous namespace against pressure retirement
    // for a new namespace. Deterministic inbox races live in the ordinary tests.
    for _ in 0..4 {
        std::thread::scope(|scope| {
            let previous = scope.spawn(|| query_loopback(false));
            let namespace = new_namespace(&restore).unwrap();
            assert!(identities.insert(namespace.metadata().unwrap().ino()));
            pinned.push(namespace);
            assert!(query_loopback(false) > 0);
            assert!(previous.join().unwrap() > 0);
        });
        let resident = resident_count();
        resident_peak = resident_peak.max(resident);
        assert!(resident <= RESIDENT_CAPACITY);
        root_peak = root_peak.max(resources::native_snapshot().active);
        let fds = namespace_fds().unwrap();
        let bound = baseline_fds + pinned.len() + resident;
        assert!(
            fds <= bound,
            "racing namespace descriptors escaped ownership: {fds} > {bound}"
        );
        fd_peak = fd_peak.max(fds);
        fd_bound_peak = fd_bound_peak.max(bound);
    }
    assert!(identities.len() > resources::WORKER_CAPACITY);
    // No production/public endpoints: only this last isolated loopback is up.
    query_loopback(true);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let deadline = Deadline::new(Duration::from_secs(5));
    let mut connect = tcp::start_connect(
        Arc::new(tcp::SystemProvider),
        listener.local_addr().unwrap(),
        &deadline,
    )
    .unwrap();
    let connection = connect
        .wait(&deadline)
        .unwrap()
        .expect("loopback connect finished")
        .result
        .unwrap();
    assert_eq!(resources::socket_snapshot().active, 1);
    root_peak = root_peak.max(resources::native_snapshot().active);
    let (accepted, _) = listener.accept().unwrap();
    drop(accepted);
    drop(connection);
    drop(connect);
    drop(listener);
    let permit = workers::shared().admit().unwrap();
    let control = permit.spawn(|| 7_u8).unwrap();
    assert!(matches!(
        control.wait(&deadline),
        workers::Waited::Finished(Ok(7))
    ));
    let guard = Instant::now() + Duration::from_secs(5);
    while resources::native_snapshot().active != 0 {
        assert!(
            Instant::now() < guard,
            "native ownership did not actually release"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(resources::socket_snapshot().active, 0);
    assert_eq!(resources::native_snapshot().cleanup_retaining_capacity, 0);
    assert!(resident_count() <= RESIDENT_CAPACITY);
    restore.restore().unwrap();
    assert_eq!(
        File::open(NAMESPACE_PATH)
            .unwrap()
            .metadata()
            .unwrap()
            .ino(),
        initial_namespace
    );
    let visited: Vec<_> = pinned
        .iter()
        .map(|namespace| namespace.metadata().unwrap().ino())
        .collect();
    println!(
        "N1_NAMESPACE_LIFECYCLE {{\"initial_namespace\":{initial_namespace},\"parent_namespace\":{parent},\"namespace_ids\":{:?},\"resident_capacity\":{RESIDENT_CAPACITY},\"resident_peak\":{resident_peak},\"native_capacity\":{},\"root_peak\":{root_peak},\"root_recovered\":0,\"fd_peak\":{fd_peak},\"fd_bound_peak\":{fd_bound_peak},\"concurrent_request_rounds\":4,\"loopback_connected\":true,\"control_completed\":true}}",
        visited,
        resources::WORKER_CAPACITY
    );
}
