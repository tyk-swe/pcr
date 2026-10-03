// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(all(packetcraftr_test_netns, native_layer2))]
#![forbid(unsafe_code)]

use std::net::UdpSocket;
use std::os::unix::fs::MetadataExt;
use std::process::Command;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_netio::{
    Error,
    capture::{self, Provider, Session},
    interface::{self, Id, Provider as _},
    resources::native_snapshot,
};

const SHARED_ROUTE_WORKERS: usize = 1;

fn isolated() {
    let parent: u64 = std::env::var("PACKETCRAFTR_PARENT_NETNS")
        .expect("run scripts/test-native-isolated.py, never enable this suite on a host network")
        .parse()
        .unwrap();
    assert_ne!(
        std::fs::metadata("/proc/self/ns/net").unwrap().ino(),
        parent
    );
    let interfaces = ip(&["-o", "link", "show"]);
    assert_eq!(
        interfaces.lines().count(),
        1,
        "suite must start with only loopback"
    );
    assert!(interfaces.contains(": lo:"));
    assert_eq!(native_snapshot().active, 0);
    // Warm the persistent route service before measuring capture admission.
    interface::SystemProvider.interfaces(&live()).unwrap();
    assert_eq!(native_snapshot().active, SHARED_ROUTE_WORKERS);
}
fn ip(args: &[&str]) -> String {
    let result = Command::new("ip").args(args).output().unwrap();
    assert!(
        result.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
fn request() -> capture::Request {
    capture::Request {
        interface: Id {
            name: "lo".to_owned(),
            index: 1,
        },
        limits: capture::Limits {
            max_frames: 64,
            max_bytes: 65536,
            snap_length: 2048,
            overflow_policy: capture::OverflowPolicy::Fail,
        },
        filter: Some("udp".to_owned()),
        promiscuous: false,
        native: Default::default(),
    }
}
fn live() -> Deadline {
    Deadline::new(Duration::from_secs(5))
}
fn within(timeout: Duration) -> Deadline {
    Deadline::new(timeout)
}
fn ready(request: &capture::Request) -> capture::SystemSession {
    let mut session = capture::SystemProvider
        .arm_capture(request, &live())
        .unwrap();
    session.wait_ready(&within(Duration::from_secs(2))).unwrap();
    assert_eq!(native_snapshot().active, SHARED_ROUTE_WORKERS + 1);
    session
}
fn released() {
    let deadline = Instant::now() + Duration::from_secs(3);
    while native_snapshot().active != SHARED_ROUTE_WORKERS && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(native_snapshot().active, SHARED_ROUTE_WORKERS);
    assert_eq!(native_snapshot().cleanup_retaining_capacity, 0);
}

#[test]
#[ignore = "requires the isolated Linux launcher"]
fn idle_deadline_and_cancellation() {
    isolated();
    let mut request = request();
    request.filter = Some("udp port 9".to_owned());
    let mut capture = ready(&request);
    let started = Instant::now();
    assert!(
        capture
            .next_captured_frame(&within(Duration::from_millis(50)))
            .unwrap()
            .is_none()
    );
    assert!(started.elapsed() >= Duration::from_millis(40));
    assert!(started.elapsed() < Duration::from_secs(2));
    let signal = Cancellation::default();
    let caller = within(Duration::from_secs(5)).with_cancellation(Some(signal.clone()));
    std::thread::scope(|scope| {
        scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            signal.cancel();
        });
        let started = Instant::now();
        assert!(matches!(
            capture.next_captured_frame(&caller),
            Err(Error::Cancelled(_))
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    });
    capture.shutdown().unwrap();
    drop(capture);
    released();
}

#[test]
#[ignore = "requires the isolated Linux launcher"]
fn bounded_queue_reports_real_capture_loss() {
    isolated();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut request = request();
    request.limits.max_frames = 1;
    request.filter = Some(format!(
        "udp dst port {}",
        receiver.local_addr().unwrap().port()
    ));
    let mut capture = ready(&request);
    for _ in 0..64 {
        sender
            .send_to(b"overflow", receiver.local_addr().unwrap())
            .unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while capture.stats().overflow_events == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let statistics = capture.stats();
    assert!(statistics.overflow_events > 0, "{statistics:?}");
    assert!(statistics.dropped_frames > 0);
    assert!(statistics.evidence_loss_error().is_some());
    let _ = capture.shutdown();
    drop(capture);
    released();
}

#[test]
#[ignore = "requires the isolated Linux launcher"]
fn native_filter_error_preserves_diagnostic_and_releases_admission() {
    isolated();
    let mut request = request();
    request.filter = Some("udp and (".to_owned());
    let error = match capture::SystemProvider.arm_capture(&request, &live()) {
        Ok(_) => panic!("invalid BPF unexpectedly installed"),
        Err(error) => error,
    };
    assert!(
        matches!(error, Error::InvalidCaptureFilter { .. }),
        "{error:?}"
    );
    match error {
        Error::InvalidCaptureFilter { message, .. } => assert!(!message.is_empty()),
        _ => unreachable!(),
    }
    released();
}
