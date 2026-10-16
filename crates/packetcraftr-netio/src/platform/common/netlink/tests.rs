// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Inbox, NetlinkRequest, Refused};
use packetcraftr_core::budget::Deadline;
use std::{
    sync::{Arc, Barrier, mpsc},
    time::{Duration, Instant},
};

mod namespace_churn;

fn request() -> NetlinkRequest {
    let (respond, _) = mpsc::sync_channel(1);
    NetlinkRequest {
        operation: Box::new(|_| {
            Box::pin(async { Ok(Box::new(()) as Box<dyn std::any::Any + Send>) })
        }),
        respond,
        deadline: Instant::now() + Duration::from_secs(5),
        control: Arc::new(Deadline::new(Duration::from_secs(5))),
    }
}

#[test]
fn queued_and_executing_requests_prevent_idle_retirement() {
    let inbox = Inbox::new();
    let deadline = Deadline::new(Duration::from_secs(5));
    assert!(
        inbox
            .submit(
                request(),
                &deadline,
                Instant::now() + Duration::from_secs(5)
            )
            .is_ok()
    );
    assert!(!inbox.retire_if_idle());
    let request = inbox.next().unwrap();
    assert!(!inbox.retire_if_idle());
    drop(request);
    inbox.complete_request();
    assert!(inbox.retire_if_idle());
    assert!(inbox.next().is_none());
    assert!(matches!(
        inbox.submit(
            self::request(),
            &deadline,
            Instant::now() + Duration::from_secs(5)
        ),
        Err(Refused::Retired(_))
    ));
}

#[test]
fn request_arrival_and_retirement_have_no_unreachable_accepted_request() {
    for _ in 0..128 {
        let inbox = Arc::new(Inbox::new());
        let start = Arc::new(Barrier::new(2));
        let retire = Arc::clone(&inbox);
        let barrier = Arc::clone(&start);
        let worker = std::thread::spawn(move || {
            barrier.wait();
            retire.retire_if_idle()
        });
        start.wait();
        let submitted = inbox.submit(
            request(),
            &Deadline::new(Duration::from_secs(5)),
            Instant::now() + Duration::from_secs(5),
        );
        let retired = worker.join().unwrap();
        match submitted {
            Ok(()) => {
                assert!(!retired);
                assert!(inbox.next().is_some());
                inbox.complete_request();
                assert!(inbox.retire_if_idle());
            }
            Err(Refused::Retired(_)) => assert!(retired),
            Err(Refused::Interrupted(_)) => panic!("controlled submission expired"),
            Err(Refused::Stopped(_)) => panic!("controlled worker unexpectedly failed"),
        }
    }
}

#[test]
fn an_empty_inbox_retires_and_an_abandoned_initializer_stops() {
    let idle = Inbox::new();
    assert!(idle.next_with_idle(Duration::ZERO).is_none());
    assert!(!super::lock(&idle.state).serving);
    let failed = Inbox::new();
    failed.abandon();
    assert!(failed.next().is_none());
    // The exit guard also rejects any queued submissions after initialization fails.
    failed.stop();
    assert!(!super::lock(&failed.state).serving);
    let failed = Inbox::new();
    failed.stop();
    assert!(matches!(
        failed.submit(
            request(),
            &Deadline::new(Duration::from_secs(5)),
            Instant::now() + Duration::from_secs(5)
        ),
        Err(Refused::Stopped(_))
    ));
}

fn fake_worker(
    namespace: &super::Namespace,
    pool: &Arc<crate::workers::Pool>,
) -> super::WorkerSlot {
    let permit = pool.admit(crate::workers::Class::Native).unwrap();
    let inbox = Arc::new(Inbox::new());
    let worker_inbox = Arc::clone(&inbox);
    let namespace = namespace.file.try_clone().unwrap();
    let worker = permit
        .spawn(move || {
            let _namespace = namespace;
            let _stop = super::StopOnExit(&worker_inbox);
            while let Some(request) = worker_inbox.next() {
                let _in_flight = super::RequestInFlight(&worker_inbox);
                let _ = request.respond.send(Ok(Box::new(())));
            }
        })
        .unwrap();
    drop(permit);
    super::WorkerSlot {
        generation: super::NEXT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        inbox,
        worker,
    }
}

#[test]
fn sequential_historical_identities_recover_resident_capacity_and_root_headroom() {
    let pool = Arc::new(crate::workers::Pool::new(8));
    let mut workers = super::Workers::new();
    let directory = std::env::temp_dir().join(format!(
        "packetcraftr-namespace-registry-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    for number in 0..(super::RESIDENT_CAPACITY * 5) {
        // Files provide distinct pinned identities to exercise the registry with
        // controlled workers; this does not establish actual namespace runtime.
        let path = directory.join(number.to_string());
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let namespace = super::Namespace {
            id: super::ExecutionContext::of_namespace(&file).unwrap(),
            file,
        };
        let deadline = Deadline::new(Duration::from_secs(5));
        let (_, inbox) = super::ensure_worker(
            &mut workers,
            &namespace,
            &deadline,
            Instant::now() + Duration::from_secs(5),
            &pool,
            |namespace, _, _| Ok(fake_worker(namespace, &pool)),
        )
        .unwrap();
        let (respond, reply) = mpsc::sync_channel(1);
        let mut request = self::request();
        request.respond = respond;
        assert!(
            inbox
                .submit(request, &deadline, Instant::now() + Duration::from_secs(5))
                .is_ok()
        );
        assert!(reply.recv_timeout(Duration::from_secs(5)).unwrap().is_ok());
        // Wait until the completion guard has returned the service to idle.
        let guard = Instant::now() + Duration::from_secs(5);
        while super::lock(&inbox.state).active {
            assert!(Instant::now() < guard);
            std::thread::yield_now();
        }
        assert!(workers.len() <= super::RESIDENT_CAPACITY);
        assert!(pool.snapshot().active <= super::RESIDENT_CAPACITY);
        std::fs::remove_file(path).unwrap();
    }
    let unrelated = pool.admit(crate::workers::Class::Native).unwrap();
    drop(unrelated);
    for (_, worker) in workers {
        assert!(worker.inbox.retire_if_idle());
        assert!(matches!(
            worker.worker.wait(&Deadline::new(Duration::from_secs(5))),
            crate::workers::Waited::Finished(Ok(()))
        ));
    }
    assert_eq!(pool.snapshot().active, 0);
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn initializer_failure_and_panic_release_the_admitted_service() {
    let file = std::fs::File::open(super::NAMESPACE_PATH).unwrap();
    let namespace = super::Namespace {
        id: super::ExecutionContext::of_namespace(&file).unwrap(),
        file,
    };
    let pool = Arc::new(crate::workers::Pool::new(2));
    let result = super::start_worker_with(
        &namespace,
        &Deadline::new(Duration::from_secs(5)),
        Instant::now() + Duration::from_secs(5),
        &pool,
        |setup, _| {
            let _ = setup.send(Err(super::route::Error::InvalidResponse {
                message: "injected initialization failure".into(),
            }));
        },
    );
    assert!(result.is_err());
    assert_eq!(pool.snapshot().active, 0);
    let result = super::start_worker_with(
        &namespace,
        &Deadline::new(Duration::from_secs(5)),
        Instant::now() + Duration::from_secs(5),
        &pool,
        |_, _| panic!("injected initializer panic"),
    );
    assert!(result.is_err());
    assert_eq!(pool.snapshot().active, 0);
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    cancellation.cancel();
    let cancelled = Deadline::new(Duration::from_secs(5)).with_cancellation(Some(cancellation));
    let result = super::start_worker_with(
        &namespace,
        &cancelled,
        Instant::now() + Duration::from_secs(5),
        &pool,
        |_, _| panic!("cancelled initialization must not start"),
    );
    assert!(matches!(result, Err(super::route::Error::Cancelled(_))));
    assert_eq!(pool.snapshot().active, 0);
}

#[test]
fn parent_cancellation_stops_waiting_for_initialization_without_hiding_its_work() {
    let file = std::fs::File::open(super::NAMESPACE_PATH).unwrap();
    let namespace = super::Namespace {
        id: super::ExecutionContext::of_namespace(&file).unwrap(),
        file,
    };
    let pool = Arc::new(crate::workers::Pool::new(2));
    let caller_pool = Arc::clone(&pool);
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    let parent =
        Deadline::new(Duration::from_secs(30)).with_cancellation(Some(cancellation.clone()));
    let caller = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let (started, running) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(1);
    let (returned, result) = mpsc::sync_channel(1);
    let waiter = std::thread::spawn(move || {
        let result = super::start_worker_with(
            &namespace,
            &caller,
            Instant::now() + Duration::from_secs(30),
            &caller_pool,
            move |setup, _| {
                started.send(()).unwrap();
                held.recv().unwrap();
                let _ = setup.send(Ok(()));
            },
        );
        returned.send(result.is_err()).unwrap();
    });
    running.recv_timeout(Duration::from_secs(5)).unwrap();
    cancellation.cancel();
    assert!(result.recv_timeout(Duration::from_secs(5)).unwrap());
    waiter.join().unwrap();
    assert_eq!(pool.snapshot().active, 1);
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 1);
    release.send(()).unwrap();
    let guard = Instant::now() + Duration::from_secs(5);
    while pool.snapshot().active != 0 {
        assert!(Instant::now() < guard);
        std::thread::yield_now();
    }
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 0);
}

#[test]
fn inherited_elapsed_control_stops_waiting_for_initialization_without_hiding_its_work() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let file = std::fs::File::open(super::NAMESPACE_PATH).unwrap();
    let namespace = super::Namespace {
        id: super::ExecutionContext::of_namespace(&file).unwrap(),
        file,
    };
    let pool = Arc::new(crate::workers::Pool::new(2));
    let caller_pool = Arc::clone(&pool);
    let advanced = Arc::new(AtomicU64::new(0));
    let clock = Arc::clone(&advanced);
    let origin = Instant::now();
    let parent = Deadline::with_time_source(Duration::from_secs(30), move || {
        origin + Duration::from_secs(clock.load(Ordering::SeqCst))
    });
    let caller = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let (started, running) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(1);
    let (returned, result) = mpsc::sync_channel(1);
    let waiter = std::thread::spawn(move || {
        let result = super::start_worker_with(
            &namespace,
            &caller,
            Instant::now() + Duration::from_secs(30),
            &caller_pool,
            move |setup, _| {
                started.send(()).unwrap();
                held.recv().unwrap();
                let _ = setup.send(Ok(()));
            },
        );
        returned.send(result.map(|_| ())).unwrap();
    });
    running.recv_timeout(Duration::from_secs(5)).unwrap();
    advanced.store(31, Ordering::SeqCst);
    let returned_under_control = result.recv_timeout(Duration::from_secs(5));
    let retained = pool.snapshot();
    // Always release before asserting so a failing old implementation cannot
    // leave its initializer or cleanup owner blocked.
    release.send(()).unwrap();
    waiter.join().unwrap();
    let guard = Instant::now() + Duration::from_secs(5);
    while pool.snapshot().active != 0 {
        assert!(Instant::now() < guard);
        std::thread::yield_now();
    }
    assert!(matches!(
        returned_under_control.expect("initialization ignored inherited elapsed control"),
        Err(super::route::Error::DeadlineExceeded {
            operation: "initializing netlink"
        })
    ));
    assert_eq!(retained.active, 1);
    assert_eq!(retained.cleanup_retaining_capacity, 1);
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 0);
}

#[test]
fn checked_out_registry_wait_observes_inherited_elapsed_control() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let held_registry = super::shared_workers(
        &Deadline::new(Duration::from_secs(5)),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    let advanced = Arc::new(AtomicU64::new(0));
    let clock = Arc::clone(&advanced);
    let origin = Instant::now();
    let parent = Deadline::with_time_source(Duration::from_secs(30), move || {
        origin + Duration::from_secs(clock.load(Ordering::SeqCst))
    });
    let caller = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let (started, starting) = mpsc::sync_channel(1);
    let (returned, result) = mpsc::sync_channel(1);
    let waiter = std::thread::spawn(move || {
        started.send(()).unwrap();
        returned
            .send(
                super::shared_workers(&caller, Instant::now() + Duration::from_secs(30))
                    .map(|_| ()),
            )
            .unwrap();
    });
    starting.recv_timeout(Duration::from_secs(5)).unwrap();
    advanced.store(31, Ordering::SeqCst);
    let returned_under_control = result.recv_timeout(Duration::from_secs(5));
    drop(held_registry);
    waiter.join().unwrap();
    assert!(matches!(
        returned_under_control.expect("checked-out registry ignored inherited elapsed control"),
        Err(super::route::Error::DeadlineExceeded {
            operation: "waiting for netlink worker admission"
        })
    ));
}

#[test]
fn full_inbox_wait_observes_inherited_elapsed_control_without_accepting_an_expired_request() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let inbox = Arc::new(Inbox::new());
    for _ in 0..super::NETLINK_QUEUE_DEPTH {
        inbox
            .submit(
                request(),
                &Deadline::new(Duration::from_secs(5)),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap_or_else(|_| panic!("a bounded inbox must admit its declared allocation"));
    }
    let advanced = Arc::new(AtomicU64::new(0));
    let clock = Arc::clone(&advanced);
    let origin = Instant::now();
    let parent = Deadline::with_time_source(Duration::from_secs(30), move || {
        origin + Duration::from_secs(clock.load(Ordering::SeqCst))
    });
    let caller = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let submitting = Arc::clone(&inbox);
    let (started, starting) = mpsc::sync_channel(1);
    let (returned, result) = mpsc::sync_channel(1);
    let waiter = std::thread::spawn(move || {
        started.send(()).unwrap();
        let observed =
            match submitting.submit(request(), &caller, Instant::now() + Duration::from_secs(30)) {
                Err(Refused::Interrupted(super::route::Error::DeadlineExceeded { operation })) => {
                    Some(operation)
                }
                _ => None,
            };
        returned.send(observed).unwrap();
    });
    starting.recv_timeout(Duration::from_secs(5)).unwrap();
    advanced.store(31, Ordering::SeqCst);
    let returned_under_control = result.recv_timeout(Duration::from_secs(5));
    let retained = super::lock(&inbox.state).queue.len();
    inbox.stop();
    waiter.join().unwrap();
    assert_eq!(
        returned_under_control.expect("full inbox ignored inherited elapsed control"),
        Some("submitting the netlink request")
    );
    assert_eq!(retained, super::NETLINK_QUEUE_DEPTH);
}

#[test]
fn finished_service_releases_its_namespace_descriptor_before_root_release() {
    let path = std::env::temp_dir().join(format!(
        "packetcraftr-netlink-descriptor-{}",
        std::process::id()
    ));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let path = path.canonicalize().unwrap();
    let namespace = super::Namespace {
        id: super::ExecutionContext::of_namespace(&file).unwrap(),
        file,
    };
    let descriptors = || {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| std::fs::read_link(entry.path()).is_ok_and(|target| target == path))
            .count()
    };
    let pool = Arc::new(crate::workers::Pool::new(2));
    let (release, held) = mpsc::sync_channel(1);
    let worker = super::start_worker_with(
        &namespace,
        &Deadline::new(Duration::from_secs(5)),
        Instant::now() + Duration::from_secs(5),
        &pool,
        move |setup, _| {
            setup.send(Ok(())).unwrap();
            held.recv().unwrap();
        },
    )
    .unwrap();
    assert_eq!(descriptors(), 2);
    assert_eq!(pool.snapshot().active, 1);
    release.send(()).unwrap();
    worker
        .worker
        .wait_ready(&Deadline::new(Duration::from_secs(5)));
    let after_service = descriptors();
    let ended = pool.snapshot().active;
    drop(worker);
    drop(namespace);
    std::fs::remove_file(path).unwrap();
    assert_eq!(ended, 0);
    assert_eq!(
        after_service, 1,
        "finished registry metadata retained a descriptor after root release"
    );
}

#[test]
fn native_operation_wait_checks_parent_cancellation() {
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    let parent =
        Deadline::new(Duration::from_secs(30)).with_cancellation(Some(cancellation.clone()));
    let control = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let mut connection = runtime.spawn(std::future::pending::<()>());
    cancellation.cancel();
    let result = runtime.block_on(super::await_netlink_operation(
        std::future::pending::<Result<(), super::route::Error>>(),
        &mut connection,
        Duration::from_secs(30),
        &control,
    ));
    assert!(matches!(result, Err(super::route::Error::Cancelled(_))));
    connection.abort();
}

#[test]
fn native_operation_wait_retains_inherited_elapsed_control_as_well_as_wall_timeout() {
    let advanced = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let time = Arc::clone(&advanced);
    let origin = Instant::now();
    let parent = Deadline::with_time_source(Duration::from_millis(100), move || {
        origin + Duration::from_millis(time.load(std::sync::atomic::Ordering::SeqCst))
    });
    let control = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let mut connection = runtime.spawn(std::future::pending::<()>());
    let result = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(5),
            super::await_netlink_operation(
                async move {
                    advanced.store(1_000, std::sync::atomic::Ordering::SeqCst);
                    std::future::pending::<Result<(), super::route::Error>>().await
                },
                &mut connection,
                Duration::from_secs(30),
                &control,
            ),
        )
        .await
        .unwrap()
    });
    assert!(matches!(
        result,
        Err(super::route::Error::DeadlineExceeded {
            operation: super::EXECUTING_OPERATION
        })
    ));
    connection.abort();
}

#[test]
fn ready_native_operation_cannot_report_success_after_it_interrupts_its_parent() {
    use std::sync::atomic::{AtomicU64, Ordering};
    for elapsed in [false, true] {
        let advanced = Arc::new(AtomicU64::new(0));
        let clock = Arc::clone(&advanced);
        let origin = Instant::now();
        let cancellation = packetcraftr_core::budget::Cancellation::default();
        let parent = Deadline::with_time_source(Duration::from_secs(30), move || {
            origin + Duration::from_secs(clock.load(Ordering::SeqCst))
        })
        .with_cancellation(Some(cancellation.clone()));
        let control = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let mut connection = runtime.spawn(std::future::pending::<()>());
        let result = runtime.block_on(super::await_netlink_operation(
            async move {
                if elapsed {
                    advanced.store(31, Ordering::SeqCst);
                } else {
                    cancellation.cancel();
                }
                Ok(7)
            },
            &mut connection,
            Duration::from_secs(30),
            &control,
        ));
        if elapsed {
            assert!(matches!(
                result,
                Err(super::route::Error::DeadlineExceeded {
                    operation: super::EXECUTING_OPERATION
                })
            ));
        } else {
            assert!(matches!(result, Err(super::route::Error::Cancelled(_))));
        }
        connection.abort();
    }
}
