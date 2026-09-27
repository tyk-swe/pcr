// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Real Linux native scenarios. The launcher proves isolation before enabling
//! these ignored tests; every test rechecks it before touching native I/O.
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
    // Its thread and socket remain owned while every capture must be released.
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
/// A deadline no isolated operation here comes close to spending.
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
            .next_captured_frame(&within(Duration::from_secs(2)))
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
    // Shutdown may repeat the unobserved queue failure; it must still clean up.
    let _ = capture.shutdown();
    drop(capture);
    released();
}

#[test]
#[ignore = "requires the isolated Linux launcher"]
fn native_settings_apply_before_activation_and_report_realized_values() {
    isolated();
    // Timestamp discovery runs on an unactivated handle and admits no capture.
    let interface = Id {
        name: "lo".to_owned(),
        index: 1,
    };
    let types = capture::SystemProvider
        .timestamp_types(&interface, &live())
        .unwrap();
    assert!(
        types
            .iter()
            .any(|kind| kind.source == Some(capture::TimestampSource::Host)),
        "{types:?}"
    );
    assert_eq!(native_snapshot().active, SHARED_ROUTE_WORKERS);

    // Loopback advertises only the host clock, so an adapter-synchronized
    // request must be rejected typed before any activation.
    let mut unsupported = request();
    unsupported.native.timestamp_source = Some(capture::TimestampSource::Adapter);
    let error = match capture::SystemProvider.arm_capture(&unsupported, &live()) {
        Ok(_) => panic!("an unadvertised timestamp source was silently ignored"),
        Err(error) => error,
    };
    assert!(
        matches!(error, Error::UnsupportedCaptureSetting { .. }),
        "{error:?}"
    );
    assert_eq!(native_snapshot().active, SHARED_ROUTE_WORKERS);

    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut request = request();
    request.filter = Some(format!(
        "udp dst port {}",
        receiver.local_addr().unwrap().port()
    ));
    request.native = capture::NativeSettings {
        buffer_size: Some(4 * 1024 * 1024),
        timestamp_source: Some(capture::TimestampSource::Host),
        timestamp_precision: Some(capture::TimestampPrecision::Nano),
    };
    let mut capture = ready(&request);
    let native = &capture.metadata().native;
    assert_eq!(native.buffer_size.requested, Some(4 * 1024 * 1024));
    assert_eq!(native.buffer_size.applied, Some(4 * 1024 * 1024));
    // The pcap API has no post-activation buffer-size query.
    assert_eq!(native.buffer_size.effective, None);
    assert_eq!(
        native.timestamp_source.applied,
        Some(capture::TimestampSource::Host)
    );
    assert_eq!(
        native.timestamp_precision.effective,
        Some(capture::TimestampPrecision::Nano)
    );
    sender
        .send_to(b"isolated-native-settings", receiver.local_addr().unwrap())
        .unwrap();
    let frame = capture
        .next_captured_frame(&within(Duration::from_secs(2)))
        .unwrap()
        .unwrap();
    // A nanosecond fraction misread as microseconds either fails the fraction
    // bound or lands 1000x off; a sane timestamp proves the delivered unit.
    let stamp = frame
        .frame
        .timestamp
        .expect("captured frames are timestamped");
    let age = std::time::SystemTime::now()
        .duration_since(stamp)
        .unwrap_or(Duration::ZERO);
    assert!(age < Duration::from_secs(60), "{stamp:?}");
    capture.shutdown().unwrap();
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
    struct Remove;
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["link", "del", "pcr-test"])
                .output();
        }
    }
    isolated();
    ip(&["link", "add", "pcr-test", "type", "dummy"]);
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
            .next_captured_frame(&within(Duration::from_millis(50)))
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
