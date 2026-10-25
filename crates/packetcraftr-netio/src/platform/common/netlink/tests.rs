// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Inbox, NetlinkRequest, Refused};
use packetcraftr_core::budget::Deadline;
use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

fn request() -> NetlinkRequest {
    request_with_reply().0
}

fn request_with_reply() -> (NetlinkRequest, mpsc::Receiver<super::OperationResult>) {
    let (respond, reply) = mpsc::sync_channel(1);
    (
        NetlinkRequest {
            operation: Box::new(|_| {
                Box::pin(async { Ok(Box::new(()) as Box<dyn std::any::Any + Send>) })
            }),
            respond,
            deadline: Instant::now() + Duration::from_secs(5),
            control: Arc::new(Deadline::new(Duration::from_secs(5))),
        },
        reply,
    )
}

fn received_value<T: Send + 'static>(reply: mpsc::Receiver<super::OperationResult>) -> T {
    *reply
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap()
        .downcast::<T>()
        .unwrap()
}

fn admit_after_cleanup(pool: &Arc<crate::workers::Pool>) -> crate::workers::Permit {
    let expires = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(permit) = pool.admit() {
            return permit;
        }
        assert!(
            Instant::now() < expires,
            "worker cleanup did not restore admission"
        );
        std::thread::yield_now();
    }
}

fn observed_parent() -> (
    Deadline,
    Arc<AtomicU64>,
    Arc<AtomicBool>,
    mpsc::Receiver<()>,
) {
    let advanced = Arc::new(AtomicU64::new(0));
    let time = Arc::clone(&advanced);
    let armed = Arc::new(AtomicBool::new(false));
    let observe = Arc::clone(&armed);
    let (sampled, sample) = mpsc::sync_channel(1);
    let origin = Instant::now();
    let parent = Deadline::with_time_source(Duration::from_secs(30), move || {
        let seconds = time.load(Ordering::SeqCst);
        if observe.swap(false, Ordering::SeqCst) {
            let _ = sampled.send(());
        }
        origin + Duration::from_secs(seconds)
    });
    (parent, advanced, armed, sample)
}

#[test]
fn queued_and_executing_requests_prevent_idle_retirement() {
    let inbox = Inbox::new();
    let deadline = Deadline::new(Duration::from_secs(5));
    let (submitted, reply) = request_with_reply();
    assert!(
        inbox
            .submit(
                submitted,
                &deadline,
                Instant::now() + Duration::from_secs(5)
            )
            .is_ok()
    );
    assert!(!inbox.retire_if_idle());
    let request = inbox.next().unwrap();
    assert!(!inbox.retire_if_idle());
    request.respond.send(Ok(Box::new(7_u64))).unwrap();
    assert_eq!(received_value::<u64>(reply), 7);
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
        let (request, reply) = request_with_reply();
        let submitted = inbox.submit(
            request,
            &Deadline::new(Duration::from_secs(5)),
            Instant::now() + Duration::from_secs(5),
        );
        let retired = worker.join().unwrap();
        match submitted {
            Ok(()) => {
                assert!(!retired);
                inbox
                    .next()
                    .unwrap()
                    .respond
                    .send(Ok(Box::new(7_u64)))
                    .unwrap();
                assert_eq!(received_value::<u64>(reply), 7);
                inbox.complete_request();
                assert!(inbox.retire_if_idle());
            }
            Err(Refused::Retired(request)) => {
                assert!(retired);
                request.respond.send(Ok(Box::new(7_u64))).unwrap();
                assert_eq!(received_value::<u64>(reply), 7);
            }
            Err(Refused::Interrupted(_)) => panic!("controlled submission expired"),
            Err(Refused::Stopped(_)) => panic!("controlled worker unexpectedly failed"),
        }
    }
}

#[test]
fn an_empty_inbox_retires_and_an_abandoned_initializer_stops() {
    let idle = Inbox::new();
    assert!(idle.next_with_idle(Duration::ZERO).is_none());
    assert!(matches!(
        idle.submit(
            request(),
            &Deadline::new(Duration::from_secs(5)),
            Instant::now() + Duration::from_secs(5)
        ),
        Err(Refused::Retired(_))
    ));
    let failed = Inbox::new();
    let (queued, reply) = request_with_reply();
    assert!(
        failed
            .submit(
                queued,
                &Deadline::new(Duration::from_secs(5)),
                Instant::now() + Duration::from_secs(5)
            )
            .is_ok()
    );
    failed.abandon();
    failed.stop();
    assert!(matches!(
        reply.recv_timeout(Duration::from_secs(5)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
    assert!(failed.next().is_none());
    assert!(matches!(
        failed.submit(
            request(),
            &Deadline::new(Duration::from_secs(5)),
            Instant::now() + Duration::from_secs(5)
        ),
        Err(Refused::Retired(_))
    ));
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
    response: usize,
) -> super::WorkerSlot {
    let permit = pool.admit().unwrap();
    let inbox = Arc::new(Inbox::new());
    let worker_inbox = Arc::clone(&inbox);
    let namespace = namespace.file.try_clone().unwrap();
    let worker = permit
        .spawn(move || {
            let _namespace = namespace;
            let _stop = super::StopOnExit(&worker_inbox);
            // Registry retirement controls this worker throughout the bounded test.
            while let Some(request) = worker_inbox.next_with_idle(Duration::from_secs(3600)) {
                let in_flight = super::RequestInFlight(&worker_inbox);
                drop(in_flight);
                let _ = request.respond.send(Ok(Box::new(response)));
            }
        })
        .unwrap();
    super::WorkerSlot {
        generation: super::NEXT_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        inbox,
        worker,
    }
}

#[test]
fn sequential_historical_identities_recover_resident_capacity_and_root_headroom() {
    let capacity = super::RESIDENT_CAPACITY + 1;
    let pool = Arc::new(crate::workers::Pool::new(capacity));
    let mut workers = super::Workers::new();
    // Keep every anonymous file alive so historical identities cannot be recycled.
    let namespaces = (0..(super::RESIDENT_CAPACITY * 5))
        .map(|_| {
            let file = tempfile::tempfile().unwrap();
            super::Namespace {
                id: super::ExecutionContext::of_namespace(&file).unwrap(),
                file,
            }
        })
        .collect::<Vec<_>>();
    for (number, namespace) in namespaces.iter().enumerate() {
        let deadline = Deadline::new(Duration::from_secs(5));
        let (_, inbox) = super::ensure_worker(
            &mut workers,
            namespace,
            &deadline,
            Instant::now() + Duration::from_secs(5),
            &pool,
            |namespace, _, _| Ok(fake_worker(namespace, &pool, number)),
        )
        .unwrap();
        let (request, reply) = request_with_reply();
        assert!(
            inbox
                .submit(request, &deadline, Instant::now() + Duration::from_secs(5))
                .is_ok()
        );
        assert_eq!(received_value::<usize>(reply), number);
        let unrelated = admit_after_cleanup(&pool).spawn(move || number).unwrap();
        assert!(
            matches!(unrelated.wait(&Deadline::new(Duration::from_secs(5))),
            crate::workers::Waited::Finished(Ok(value)) if value == number)
        );
    }
    for (_, worker) in workers {
        assert!(worker.inbox.retire_if_idle());
        assert!(matches!(
            worker.worker.wait(&Deadline::new(Duration::from_secs(5))),
            crate::workers::Waited::Finished(Ok(()))
        ));
    }
    let reclaimed = (0..capacity)
        .map(|_| admit_after_cleanup(&pool))
        .collect::<Vec<_>>();
    assert!(pool.admit().is_err());
    let tasks = reclaimed
        .into_iter()
        .enumerate()
        .map(|(index, permit)| permit.spawn(move || index).unwrap())
        .collect::<Vec<_>>();
    for (index, task) in tasks.into_iter().enumerate() {
        assert!(matches!(task.wait(&Deadline::new(Duration::from_secs(5))),
            crate::workers::Waited::Finished(Ok(value)) if value == index));
    }
}

#[test]
fn checked_out_registry_wait_observes_inherited_elapsed_control() {
    let held_registry = super::shared_workers(
        &Deadline::new(Duration::from_secs(5)),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    let (parent, advanced, armed, sampled) = observed_parent();
    let caller = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let (returned, result) = mpsc::sync_channel(1);
    let waiter = std::thread::spawn(move || {
        armed.store(true, Ordering::SeqCst);
        returned
            .send(
                super::shared_workers(&caller, Instant::now() + Duration::from_secs(30))
                    .map(|_| ()),
            )
            .unwrap();
    });
    sampled.recv_timeout(Duration::from_secs(5)).unwrap();
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
    let inbox = Arc::new(Inbox::new());
    let replies = (0..super::NETLINK_QUEUE_DEPTH)
        .map(|_| {
            let (request, reply) = request_with_reply();
            inbox
                .submit(
                    request,
                    &Deadline::new(Duration::from_secs(5)),
                    Instant::now() + Duration::from_secs(5),
                )
                .unwrap_or_else(|_| panic!("a bounded inbox must admit its declared allocation"));
            reply
        })
        .collect::<Vec<_>>();
    let (parent, advanced, armed, sampled) = observed_parent();
    let caller = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let submitting = Arc::clone(&inbox);
    let (returned, result) = mpsc::sync_channel(1);
    let waiter = std::thread::spawn(move || {
        armed.store(true, Ordering::SeqCst);
        let observed =
            match submitting.submit(request(), &caller, Instant::now() + Duration::from_secs(30)) {
                Err(Refused::Interrupted(super::route::Error::DeadlineExceeded { operation })) => {
                    Some(operation)
                }
                _ => None,
            };
        returned.send(observed).unwrap();
    });
    sampled.recv_timeout(Duration::from_secs(5)).unwrap();
    advanced.store(31, Ordering::SeqCst);
    let returned_under_control = result.recv_timeout(Duration::from_secs(5));
    let delivered = (0..super::NETLINK_QUEUE_DEPTH)
        .map(|_| {
            inbox.next_with_idle(Duration::ZERO).map(|request| {
                let _in_flight = super::RequestInFlight(&inbox);
                request.respond.send(Ok(Box::new(7_u64)))
            })
        })
        .collect::<Vec<_>>();
    let unexpected_request = inbox.next_with_idle(Duration::ZERO).is_some();
    inbox.stop();
    waiter.join().unwrap();
    assert_eq!(
        returned_under_control.expect("full inbox ignored inherited elapsed control"),
        Some("submitting the netlink request")
    );
    assert!(!unexpected_request);
    assert!(
        delivered
            .into_iter()
            .all(|result| matches!(result, Some(Ok(()))))
    );
    for reply in replies {
        assert_eq!(received_value::<u64>(reply), 7);
    }
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
