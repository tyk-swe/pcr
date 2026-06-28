// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

fn new_task_executor() -> Arc<BoundedExecutor> {
    Arc::new(
        BoundedExecutor::new(
            "rule-worker-test",
            crate::rules::config::RULE_EXECUTOR_WORKERS,
            crate::rules::config::RULE_EXECUTOR_WORKERS
                + crate::rules::config::RULE_EXECUTOR_QUEUE_CAPACITY,
        )
        .expect("create test task executor"),
    )
}

#[test]
fn send_template_applies_context_placeholders() {
    use std::time::SystemTime;

    let template = RuleSendTemplate::new(PacketRequest {
        destination: crate::engine::request::DestinationRequest {
            destination: Some("{source}".to_string()),
            ..Default::default()
        },
        payload: crate::engine::request::PayloadRequest {
            data: Some("echo {description}".to_string()),
            ..Default::default()
        },
        ..Default::default()
    });

    let ctx = PacketContext {
        description: "icmp reply".to_string(),
        source: Some("2001:db8::1".to_string()),
        destination: Some("2001:db8::2".to_string()),
        length: 64,
        timestamp: SystemTime::now(),
    };

    let rendered = template.render(Some(&ctx));
    assert_eq!(
        rendered.destination.destination.as_deref(),
        Some("2001:db8::1")
    );
    assert_eq!(rendered.payload.data.as_deref(), Some("echo icmp reply"));
}

#[test]
fn send_template_applies_context_placeholders_to_nested_string_fields() {
    use crate::engine::request::{
        Ipv6Request, LoggingRequest, PayloadRequest, TcpRequest, TransportProtocolRequest,
        TransportRequest,
    };
    use std::time::SystemTime;

    let template = RuleSendTemplate::new(PacketRequest {
        ipv6: Ipv6Request {
            extensions: vec!["routing:{destination}".to_string()],
        },
        transport: TransportRequest {
            command: Some(TransportProtocolRequest::Tcp(TcpRequest {
                flags: Some("syn,{description}".to_string()),
                timestamps: Some("{length}:0".to_string()),
                options_hex: Some("{source}".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        },
        payload: PayloadRequest {
            dns_query: Some("{source}.example".to_string()),
            dns_type: Some("{description}".to_string()),
            http_method: Some("{description}".to_string()),
            http_path: Some("/{length}".to_string()),
            http_host: Some("{destination}".to_string()),
            tls_client_hello: Some("{source}".to_string()),
            ..Default::default()
        },
        logging: LoggingRequest {
            metrics_json: Some("/tmp/{length}.json".to_string()),
            prometheus_bind: Some("{destination}:9000".to_string()),
            ..Default::default()
        },
        ..Default::default()
    });

    let ctx = PacketContext {
        description: "ack".to_string(),
        source: Some("192.0.2.10".to_string()),
        destination: Some("198.51.100.20".to_string()),
        length: 128,
        timestamp: SystemTime::now(),
    };

    let rendered = template.render(Some(&ctx));
    assert_eq!(rendered.ipv6.extensions, vec!["routing:198.51.100.20"]);
    match rendered.transport.command {
        Some(TransportProtocolRequest::Tcp(tcp)) => {
            assert_eq!(tcp.flags.as_deref(), Some("syn,ack"));
            assert_eq!(tcp.timestamps.as_deref(), Some("128:0"));
            assert_eq!(tcp.options_hex.as_deref(), Some("192.0.2.10"));
        }
        other => panic!("expected tcp transport, got {other:?}"),
    }
    assert_eq!(
        rendered.payload.dns_query.as_deref(),
        Some("192.0.2.10.example")
    );
    assert_eq!(rendered.payload.dns_type.as_deref(), Some("ack"));
    assert_eq!(rendered.payload.http_method.as_deref(), Some("ack"));
    assert_eq!(rendered.payload.http_path.as_deref(), Some("/128"));
    assert_eq!(rendered.payload.http_host.as_deref(), Some("198.51.100.20"));
    assert_eq!(
        rendered.payload.tls_client_hello.as_deref(),
        Some("192.0.2.10")
    );
    assert_eq!(
        rendered.logging.metrics_json.as_deref(),
        Some("/tmp/128.json")
    );
    assert_eq!(
        rendered.logging.prometheus_bind.as_deref(),
        Some("198.51.100.20:9000")
    );
}

#[test]
fn bounded_executor_enforces_queue_capacity_under_load() {
    let _executor_guard = test_support::executor_lock();

    let workers = 2;
    let queue_capacity = 3;
    let executor = Arc::new(
        BoundedExecutor::new("queue-test", workers, workers + queue_capacity)
            .expect("create queue test executor"),
    );

    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (ready_tx, ready_rx) = mpsc::channel();
    for _ in 0..workers {
        let ready_tx = ready_tx.clone();
        let release = Arc::clone(&release);
        executor
            .spawn(move || {
                let _ = ready_tx.send(());
                let (lock, cvar) = &*release;
                let mut released = lock.lock().expect("lock poisoned");
                while !*released {
                    released = cvar.wait(released).expect("lock poisoned");
                }
            })
            .expect("spawn blocking worker task");
    }
    drop(ready_tx);
    for _ in 0..workers {
        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker start");
    }

    let (queued_tx, queued_rx) = mpsc::channel();
    for _ in 0..queue_capacity {
        let queued_tx = queued_tx.clone();
        executor
            .spawn(move || {
                let _ = queued_tx.send(());
            })
            .expect("enqueue queued task");
    }
    drop(queued_tx);

    let overflow = executor.spawn(|| {});
    assert!(
        matches!(overflow, Err(ExecutorError::QueueFull)),
        "expected queue to reject tasks beyond capacity"
    );

    let (lock, cvar) = &*release;
    let mut released = lock.lock().expect("lock poisoned");
    *released = true;
    cvar.notify_all();
    drop(released);

    for _ in 0..queue_capacity {
        queued_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("queued task completion");
    }
}

#[test]
fn bounded_executor_recovers_from_panicking_job() {
    let _executor_guard = test_support::executor_lock();

    let executor = new_task_executor();
    executor
        .spawn(|| panic!("intentional panic"))
        .expect("enqueue panicking task");

    let (tx, rx) = mpsc::channel();
    executor
        .spawn(move || {
            let _ = tx.send(());
        })
        .expect("enqueue follow-up task");

    rx.recv_timeout(Duration::from_secs(1))
        .expect("follow-up task completion");
}

#[test]
fn bounded_executor_supports_tokio_time_and_io() {
    let _executor_guard = test_support::executor_lock();
    let executor = new_task_executor();
    let (tx, rx) = mpsc::channel();

    // This task requires the time driver
    executor
        .spawn_async(move || async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx.send(());
        })
        .expect("spawn async task");

    // Without time driver, the task will panic and nothing will be sent.
    // With time driver, it should succeed.
    rx.recv_timeout(Duration::from_secs(1))
        .expect("Task failed to complete (likely due to missing time driver)");
}

#[test]
fn send_hook_guard_clears_hook_after_panic_path() {
    let _executor_guard = test_support::executor_lock();

    let result = std::panic::catch_unwind(|| {
        let _hook_guard = test_support::send_hook_guard(Some(Arc::new(|_, _| Ok(()))));
        assert!(test_support::send_hook().is_some());
        panic!("exercise send hook guard drop");
    });

    assert!(result.is_err());
    assert!(test_support::send_hook().is_none());
}

#[test]
fn executor_lock_recovers_from_poison_and_clears_stale_hook() {
    let _ = std::thread::spawn(|| {
        let _executor_guard = test_support::executor_lock();
        test_support::set_send_hook(Some(Arc::new(|_, _| Ok(()))));
        panic!("poison executor lock");
    })
    .join();

    let _executor_guard = test_support::executor_lock();
    assert!(test_support::send_hook().is_none());
}
