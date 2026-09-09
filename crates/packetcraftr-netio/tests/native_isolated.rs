// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Real Linux native scenarios. The launcher proves isolation before enabling
//! these ignored tests; every test rechecks it before touching native I/O.
#![cfg(all(target_os = "linux", feature = "native-layer2"))]
#![forbid(unsafe_code)]

use std::net::UdpSocket;
use std::os::unix::fs::MetadataExt;
use std::process::Command;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Cancellation;
use packetcraftr_netio::{
    Error,
    capture::{self, Provider, Session},
    interface::Id,
    resources::native_snapshot,
};

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
    }
}
fn ready(request: &capture::Request) -> capture::SystemSession {
    let mut session = capture::SystemProvider.arm_capture(request).unwrap();
    session.wait_ready(Duration::from_secs(2)).unwrap();
    assert_eq!(native_snapshot().active, 1);
    session
}
fn released() {
    let deadline = Instant::now() + Duration::from_secs(3);
    while native_snapshot().active != 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(native_snapshot().active, 0);
    assert_eq!(native_snapshot().cleanup_retaining_capacity, 0);
}

#[test]
#[ignore = "requires the isolated Linux launcher"]
fn readiness_and_repeated_cleanup() {
    isolated();
    for _ in 0..4 {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut request = request();
        request.filter = Some(format!(
            "udp dst port {}",
            receiver.local_addr().unwrap().port()
        ));
        let mut capture = ready(&request);
        sender
            .send_to(b"isolated-readiness", receiver.local_addr().unwrap())
            .unwrap();
        let frame = capture
            .next_captured_frame(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert!(
            frame
                .frame
                .bytes()
                .windows(b"isolated-readiness".len())
                .any(|bytes| bytes == b"isolated-readiness")
        );
        capture.shutdown().unwrap();
        capture.shutdown().unwrap();
        drop(capture);
        released();
    }
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
            .next_captured_frame(Duration::from_millis(50))
            .unwrap()
            .is_none()
    );
    assert!(started.elapsed() >= Duration::from_millis(40));
    assert!(started.elapsed() < Duration::from_secs(2));
    let signal = Cancellation::default();
    let mut capture = capture::Cancellable::new(capture, Some(signal.clone()));
    std::thread::scope(|scope| {
        scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            signal.cancel();
        });
        let started = Instant::now();
        assert!(matches!(
            capture.next_captured_frame(Duration::from_secs(5)),
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
    while capture.statistics().overflow_events == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let statistics = capture.statistics();
    assert!(statistics.overflow_events > 0, "{statistics:?}");
    assert!(statistics.dropped_frames > 0);
    assert!(statistics.evidence_loss_error().is_some());
    // Shutdown may repeat the unobserved queue failure; it must still clean up.
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
    let error = match capture::SystemProvider.arm_capture(&request) {
        Ok(_) => panic!("invalid BPF unexpectedly installed"),
        Err(error) => error,
    };
    assert!(
        matches!(error, Error::InvalidCaptureFilter { .. }),
        "{error:?}"
    );
    // libpcap's filter compiler returns its diagnostic through pcap_geterr;
    // unlike packet reads there is no typed source error to preserve.
    match error {
        Error::InvalidCaptureFilter { message, .. } => assert!(!message.is_empty()),
        _ => unreachable!(),
    }
    released();
}

#[test]
#[ignore = "requires the isolated Linux launcher"]
fn interface_disappearance_reports_driver_failure_and_cleans_up() {
    isolated();
    ip(&["link", "add", "pcr-test", "type", "dummy"]);
    struct Remove;
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["link", "del", "pcr-test"])
                .output();
        }
    }
    let _remove = Remove;
    ip(&["link", "set", "pcr-test", "up"]);
    let index = ip(&["-o", "link", "show", "dev", "pcr-test"])
        .split(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut request = request();
    request.interface = Id {
        name: "pcr-test".to_owned(),
        index,
    };
    let mut capture = ready(&request);
    ip(&["link", "del", "pcr-test"]);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut failed = false;
    while Instant::now() < deadline {
        if capture
            .next_captured_frame(Duration::from_millis(50))
            .is_err()
        {
            failed = true;
            break;
        }
    }
    assert!(
        failed,
        "disappeared interface did not surface a native error"
    );
    let _ = capture.shutdown();
    drop(capture);
    released();
}
