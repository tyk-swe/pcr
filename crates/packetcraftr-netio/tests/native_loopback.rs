// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::frame::Frame;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_netio::capture::{
    self, Limits as CaptureLimits, NativeSettings, OverflowPolicy, Request as CaptureRequest,
    Session as _, TimestampPrecision, TimestampSource,
};
use packetcraftr_netio::interface;
use packetcraftr_netio::link::Mode;
use packetcraftr_netio::resources::{NativeSnapshot, native_snapshot};
use packetcraftr_netio::route;
use packetcraftr_netio::transmit;
use packetcraftr_netio::{
    Error, capture::Provider as _, interface::Provider as _, route::Provider as _,
    transmit::Provider as _,
};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const PAYLOAD: &[u8] = b"reviewed-native-loopback";
const MAX_WAIT: Duration = Duration::from_secs(2);
const RELEASE_WAIT: Duration = Duration::from_secs(3);

fn deadline(limit: Duration) -> Deadline {
    Deadline::new(limit)
}

struct Unavailable {
    reason_code: &'static str,
    reason: &'static str,
}

impl Unavailable {
    const fn unsupported(reason: &'static str) -> Self {
        Self {
            reason_code: "unsupported_capability",
            reason,
        }
    }

    const fn backend(reason: &'static str) -> Self {
        Self {
            reason_code: "backend_not_installed",
            reason,
        }
    }

    fn emit(self) {
        println!(
            "PACKETCRAFTR_NATIVE_UNAVAILABLE={{\"reason_code\":\"{}\",\"reason\":\"{}\"}}",
            self.reason_code, self.reason
        );
    }
}

fn valid_uuid(token: &str) -> bool {
    let parts: Vec<&str> = token.split('-').collect();
    parts.len() == 5
        && [8usize, 4, 4, 4, 12]
            .into_iter()
            .zip(&parts)
            .all(|(length, part)| {
                part.len() == length && part.chars().all(|c| c.is_ascii_hexdigit())
            })
}

fn gate() {
    if !cfg!(packetcraftr_test_host_loopback) {
        panic!("the host loopback cfg is emitted only on macOS/Windows builds");
    }
    let token = std::env::var("PACKETCRAFTR_NATIVE_LOOPBACK_TOKEN")
        .expect("the launcher sets PACKETCRAFTR_NATIVE_LOOPBACK_TOKEN");
    assert!(valid_uuid(&token), "loopback token is not a UUID");
    let platform = std::env::var("PACKETCRAFTR_NATIVE_LOOPBACK_PLATFORM")
        .expect("the launcher sets PACKETCRAFTR_NATIVE_LOOPBACK_PLATFORM");
    assert!(
        platform == "macOS" || platform == "Windows",
        "host loopback evidence runs only on macOS or Windows, not {platform}"
    );
}

fn loopback() -> Result<interface::Info, Unavailable> {
    let deadline = deadline(MAX_WAIT);
    let interfaces = match interface::SystemProvider.interfaces(&deadline) {
        Ok(interfaces) => interfaces,
        Err(interface::Error::Discovery { source, .. }) => match source.downcast_ref::<Error>() {
            Some(error @ Error::MissingDependency { .. }) => {
                eprintln!("native loopback: interface enumeration backend error: {error}");
                return Err(Unavailable::backend(
                    "interface enumeration backend dependency is absent",
                ));
            }
            _ => panic!("loopback interface enumeration failed: {source}"),
        },
        Err(error) => panic!("loopback interface enumeration failed: {error}"),
    };
    let mut matches = interfaces.into_iter().filter(|info| {
        info.flags.loopback
            && info
                .addresses
                .iter()
                .any(|address| address.address == LOOPBACK)
    });
    let loopback = match (matches.next(), matches.next()) {
        (Some(loopback), None) => loopback,
        (None, _) => {
            return Err(Unavailable::unsupported(
                "no interface with the loopback flag owns 127.0.0.1",
            ));
        }
        (Some(_), Some(_)) => {
            return Err(Unavailable::unsupported(
                "more than one interface with the loopback flag owns 127.0.0.1",
            ));
        }
    };
    assert_ne!(loopback.id.index, 0, "the loopback index is a real index");
    Ok(loopback)
}

fn await_release(baseline: NativeSnapshot) {
    let started = Instant::now();
    loop {
        let snapshot = native_snapshot();
        if snapshot.active <= baseline.active && snapshot.cleanup_retaining_capacity == 0 {
            return;
        }
        assert!(
            started.elapsed() < RELEASE_WAIT,
            "native capture capacity did not release: {snapshot:?} vs baseline {baseline:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn warm_baseline() -> NativeSnapshot {
    let _ = interface::SystemProvider.interfaces(&deadline(MAX_WAIT));
    let deadline_at = Instant::now() + RELEASE_WAIT;
    loop {
        let snapshot = native_snapshot();
        if snapshot.active == 0 && snapshot.cleanup_retaining_capacity == 0 {
            return snapshot;
        }
        assert!(
            Instant::now() < deadline_at,
            "native baseline retained initialization capacity: {snapshot:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn bound_udp() -> (UdpSocket, u16) {
    let socket = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).expect("bind 127.0.0.1:0");
    let port = socket.local_addr().expect("local address").port();
    (socket, port)
}

fn capture_filter(destination_port: u16) -> String {
    format!("udp and src host 127.0.0.1 and dst host 127.0.0.1 and dst port {destination_port}")
}

fn capture_request(
    loopback: &interface::Info,
    destination_port: u16,
    limits: CaptureLimits,
    native: NativeSettings,
) -> CaptureRequest {
    CaptureRequest {
        interface: loopback.id.clone(),
        limits,
        filter: Some(capture_filter(destination_port)),
        promiscuous: false,
        native,
    }
}

fn bounded_limits() -> CaptureLimits {
    CaptureLimits {
        max_frames: 64,
        max_bytes: 65_536,
        snap_length: 2_048,
        overflow_policy: OverflowPolicy::Fail,
    }
}

fn arm_or_unavailable(
    request: &CaptureRequest,
    deadline_at: &Deadline,
) -> Result<capture::SystemSession, Unavailable> {
    match capture::SystemProvider.arm_capture(request, deadline_at) {
        Ok(session) => Ok(session),
        Err(error @ Error::MissingDependency { .. }) => {
            eprintln!("native loopback: capture backend error: {error}");
            Err(Unavailable::backend("capture backend dependency is absent"))
        }
        Err(error @ Error::UnsupportedCaptureSetting { .. }) => {
            eprintln!("native loopback: capture setting rejected: {error}");
            Err(Unavailable::unsupported(
                "the requested native capture settings are unsupported by this backend",
            ))
        }
        Err(error @ Error::Unsupported(_)) => {
            eprintln!("native loopback: capture capability unsupported: {error}");
            Err(Unavailable::unsupported(
                "capture capability is unsupported on this platform",
            ))
        }
        Err(error) => panic!("arming the native loopback capture failed: {error}"),
    }
}

fn frame_contains(frame: &Frame, needle: &[u8]) -> bool {
    frame
        .bytes()
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
#[ignore = "native host loopback evidence runs only via scripts/test-native-platform.py"]
fn loopback_exchange() {
    gate();
    if !cfg!(native_layer3) {
        return Unavailable::unsupported(
            "Layer 3 raw transmission is not enabled in this build profile",
        )
        .emit();
    }
    let baseline = warm_baseline();
    let loopback = match loopback() {
        Ok(loopback) => loopback,
        Err(unavailable) => {
            await_release(baseline);
            return unavailable.emit();
        }
    };
    let (receiver, receiver_port) = bound_udp();
    let (_source_socket, source_port) = bound_udp();
    receiver
        .set_read_timeout(Some(MAX_WAIT))
        .expect("read timeout");

    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::LOCALHOST,
        destination: Ipv4Addr::LOCALHOST,
        identification: 1,
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port,
        destination_port: receiver_port,
        ..Udp::default()
    });
    packet.push(Raw::new(PAYLOAD));
    let built = packetcraftr_core::build::Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .expect("the loopback packet builds");
    let bytes = built.bytes;

    let route_deadline = deadline(MAX_WAIT);
    let decision = route::SystemProvider
        .lookup_with_preferences(
            LOOPBACK,
            Some(&loopback.id),
            Some(LOOPBACK),
            &route_deadline,
        )
        .expect("loopback route lookup");
    assert_eq!(
        decision.interface, loopback.id,
        "the route uses the loopback Id"
    );
    assert_eq!(
        decision.selected_source,
        Some(LOOPBACK),
        "the preferred source is selected"
    );

    let mut session = if cfg!(native_layer2) {
        let request = capture_request(
            &loopback,
            receiver_port,
            bounded_limits(),
            NativeSettings::default(),
        );
        match arm_or_unavailable(&request, &deadline(MAX_WAIT)) {
            Ok(mut session) => {
                session
                    .wait_ready(&deadline(MAX_WAIT))
                    .expect("capture readiness");
                Some(session)
            }
            Err(unavailable) => {
                await_release(baseline);
                return unavailable.emit();
            }
        }
    } else {
        None
    };

    let route = transmit::Route {
        decision: &decision,
        mode: Mode::Layer3,
        lookup_destination: Some(LOOPBACK),
    };
    let outbound = transmit::Outbound::try_new(&bytes, route).expect("Layer 3 frame");
    let report = transmit::SystemProvider
        .send(outbound)
        .expect("loopback Layer 3 send");
    report.validate_exact(&bytes).expect("submission validated");

    let mut buffer = [0u8; 2048];
    let (length, peer) = receiver.recv_from(&mut buffer).expect("loopback receive");
    assert_eq!(&buffer[..length], PAYLOAD, "exact payload delivered");
    assert_eq!(peer.port(), source_port, "the source port is preserved");
    assert_eq!(peer.ip(), LOOPBACK);

    if let Some(session) = session.as_mut() {
        let frame = session
            .next_captured_frame(&deadline(MAX_WAIT))
            .expect("capture frame")
            .expect("the loopback send is captured");
        assert!(
            frame_contains(&frame.frame, PAYLOAD),
            "the captured wire bytes contain the payload"
        );
        assert!(frame.frame.timestamp.is_some(), "the frame has a timestamp");
        assert_eq!(
            session.metadata().interface,
            loopback.id,
            "the capture ran on the loopback interface"
        );
        session.shutdown().expect("capture shutdown");
    }
    drop(session);
    await_release(baseline);
}

#[test]
#[ignore = "native host loopback evidence runs only via scripts/test-native-platform.py"]
fn readiness_and_repeated_cleanup() {
    gate();
    if !cfg!(native_layer2) {
        return Unavailable::unsupported("Layer 2 capture is not enabled in this build profile")
            .emit();
    }
    let baseline = warm_baseline();
    let loopback = match loopback() {
        Ok(loopback) => loopback,
        Err(unavailable) => {
            await_release(baseline);
            return unavailable.emit();
        }
    };
    let (_receiver, receiver_port) = bound_udp();
    let (sender, _source_port) = bound_udp();

    for repetition in 0..4 {
        let request = capture_request(
            &loopback,
            receiver_port,
            bounded_limits(),
            NativeSettings::default(),
        );
        let mut session = match arm_or_unavailable(&request, &deadline(MAX_WAIT)) {
            Ok(session) => session,
            Err(unavailable) => {
                await_release(baseline);
                return unavailable.emit();
            }
        };
        session
            .wait_ready(&deadline(MAX_WAIT))
            .expect("capture readiness");
        assert!(
            native_snapshot().active > baseline.active,
            "the armed capture holds a worker reservation"
        );
        sender
            .send_to(PAYLOAD, SocketAddr::new(LOOPBACK, receiver_port))
            .expect("kernel UDP loopback send");
        let frame = session
            .next_captured_frame(&deadline(MAX_WAIT))
            .expect("capture frame")
            .unwrap_or_else(|| panic!("repetition {repetition}: payload frame missing"));
        assert!(
            frame_contains(&frame.frame, PAYLOAD),
            "repetition {repetition}: the frame carries the exact payload"
        );
        session.shutdown().expect("capture shutdown");
        session.shutdown().expect("repeated shutdown is harmless");
        drop(session);
        await_release(baseline);
    }
}

#[test]
#[ignore = "native host loopback evidence runs only via scripts/test-native-platform.py"]
fn idle_deadline_and_cancellation() {
    gate();
    if !cfg!(native_layer2) {
        return Unavailable::unsupported("Layer 2 capture is not enabled in this build profile")
            .emit();
    }
    let baseline = warm_baseline();
    let loopback = match loopback() {
        Ok(loopback) => loopback,
        Err(unavailable) => {
            await_release(baseline);
            return unavailable.emit();
        }
    };
    let (_idle_socket, idle_port) = bound_udp();
    let request = capture_request(
        &loopback,
        idle_port,
        bounded_limits(),
        NativeSettings::default(),
    );
    let mut session = match arm_or_unavailable(&request, &deadline(MAX_WAIT)) {
        Ok(session) => session,
        Err(unavailable) => {
            await_release(baseline);
            return unavailable.emit();
        }
    };
    session
        .wait_ready(&deadline(MAX_WAIT))
        .expect("capture readiness");

    let started = Instant::now();
    let frame = session
        .next_captured_frame(&deadline(Duration::from_millis(50)))
        .expect("idle poll returns, not errors");
    assert!(frame.is_none(), "no traffic matches the idle filter");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(40),
        "the idle deadline was honored too early: {elapsed:?}"
    );
    assert!(
        elapsed < MAX_WAIT,
        "the idle deadline was not honored: {elapsed:?}"
    );

    let cancellation = Cancellation::default();
    let signal = cancellation.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        signal.cancel();
    });
    let started = Instant::now();
    let error = session
        .next_captured_frame(
            &deadline(Duration::from_secs(5)).with_cancellation(Some(cancellation)),
        )
        .expect_err("the cancelled wait fails");
    assert!(
        matches!(error, Error::Cancelled(_)),
        "cancellation surfaces as typed Cancelled, not {error}"
    );
    assert!(
        started.elapsed() < MAX_WAIT,
        "cancellation did not interrupt the wait promptly"
    );
    session.shutdown().expect("capture shutdown");
    drop(session);
    await_release(baseline);
}

#[test]
#[ignore = "native host loopback evidence runs only via scripts/test-native-platform.py"]
fn bounded_queue_reports_real_capture_loss() {
    gate();
    if !cfg!(native_layer2) {
        return Unavailable::unsupported("Layer 2 capture is not enabled in this build profile")
            .emit();
    }
    let baseline = warm_baseline();
    let loopback = match loopback() {
        Ok(loopback) => loopback,
        Err(unavailable) => {
            await_release(baseline);
            return unavailable.emit();
        }
    };
    let (_receiver, receiver_port) = bound_udp();
    let (sender, _source_port) = bound_udp();
    let mut limits = bounded_limits();
    limits.max_frames = 1;
    let request = capture_request(&loopback, receiver_port, limits, NativeSettings::default());
    let mut session = match arm_or_unavailable(&request, &deadline(MAX_WAIT)) {
        Ok(session) => session,
        Err(unavailable) => {
            await_release(baseline);
            return unavailable.emit();
        }
    };
    session
        .wait_ready(&deadline(MAX_WAIT))
        .expect("capture readiness");
    for _ in 0..64 {
        sender
            .send_to(PAYLOAD, SocketAddr::new(LOOPBACK, receiver_port))
            .expect("kernel UDP loopback send");
    }
    let started = Instant::now();
    let stats = loop {
        let stats = session.stats();
        if stats.overflow_events > 0 && stats.dropped_frames > 0 {
            break stats;
        }
        assert!(
            started.elapsed() < RELEASE_WAIT,
            "no real capture loss was reported: {stats:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        stats.evidence_loss_error().is_some(),
        "the loss counters must carry a typed evidence-loss error"
    );
    let mut overflowed = false;
    let drain_deadline = deadline(MAX_WAIT);
    for _ in 0..=request.limits.max_frames {
        match session.next_captured_frame(&drain_deadline) {
            Err(Error::CaptureQueueOverflow {
                dropped_frames,
                dropped_bytes,
                overflow_events,
            }) => {
                assert!(dropped_frames > 0 && dropped_bytes > 0 && overflow_events > 0);
                overflowed = true;
                break;
            }
            Err(error) => panic!("queue drain failed before the overflow error: {error}"),
            Ok(Some(_)) => {}
            Ok(None) => panic!("the queue overflow error was not delivered before the deadline"),
        }
    }
    assert!(
        overflowed,
        "the queued capture overflow error was delivered"
    );
    session.shutdown().expect("capture shutdown");
    drop(session);
    await_release(baseline);
}

#[test]
#[ignore = "native host loopback evidence runs only via scripts/test-native-platform.py"]
fn native_set_before_realized_values() {
    gate();
    if !cfg!(native_layer2) {
        return Unavailable::unsupported("Layer 2 capture is not enabled in this build profile")
            .emit();
    }
    let baseline = warm_baseline();
    let loopback = match loopback() {
        Ok(loopback) => loopback,
        Err(unavailable) => {
            await_release(baseline);
            return unavailable.emit();
        }
    };
    let (_receiver, receiver_port) = bound_udp();
    let (sender, _source_port) = bound_udp();

    let advertised =
        match capture::SystemProvider.timestamp_types(&loopback.id, &deadline(MAX_WAIT)) {
            Ok(types) => types,
            Err(error @ Error::MissingDependency { .. }) => {
                eprintln!("native loopback: timestamp enumeration backend error: {error}");
                await_release(baseline);
                return Unavailable::backend("capture backend dependency is absent").emit();
            }
            Err(error @ Error::Unsupported(_)) => {
                eprintln!("native loopback: timestamp enumeration unsupported: {error}");
                await_release(baseline);
                return Unavailable::unsupported(
                    "timestamp type enumeration is unsupported on this platform",
                )
                .emit();
            }
            Err(error) => panic!("timestamp type enumeration failed: {error}"),
        };

    let timestamp_source = advertised
        .iter()
        .any(|kind| kind.source == Some(TimestampSource::Host))
        .then_some(TimestampSource::Host);
    let timestamp_precision = TimestampPrecision::Nano;
    let native = NativeSettings {
        buffer_size: Some(1024 * 1024),
        timestamp_source,
        timestamp_precision: Some(timestamp_precision),
    };
    let request = capture_request(&loopback, receiver_port, bounded_limits(), native.clone());
    let mut session = match arm_or_unavailable(&request, &deadline(MAX_WAIT)) {
        Ok(session) => session,
        Err(unavailable) => {
            await_release(baseline);
            return unavailable.emit();
        }
    };
    let realized = &session.metadata().native;
    assert_eq!(
        realized.buffer_size.requested,
        Some(1024 * 1024),
        "buffer size requested as configured"
    );
    assert_eq!(realized.timestamp_source.requested, timestamp_source);
    assert_eq!(
        realized.timestamp_precision.requested,
        Some(timestamp_precision),
        "timestamp precision requested as configured"
    );
    assert_eq!(
        realized.buffer_size.applied,
        Some(1024 * 1024),
        "buffer size applied as requested"
    );
    if let Some(source) = timestamp_source {
        assert_eq!(realized.timestamp_source.applied, Some(source));
    }
    assert_eq!(
        realized.timestamp_precision.applied,
        Some(timestamp_precision),
        "timestamp precision applied as requested"
    );
    session
        .wait_ready(&deadline(MAX_WAIT))
        .expect("capture readiness");
    sender
        .send_to(PAYLOAD, SocketAddr::new(LOOPBACK, receiver_port))
        .expect("kernel UDP loopback send");
    let frame = session
        .next_captured_frame(&deadline(MAX_WAIT))
        .expect("capture frame")
        .expect("payload frame captured under realized settings");
    assert!(frame_contains(&frame.frame, PAYLOAD));
    assert!(frame.frame.timestamp.is_some());
    session.shutdown().expect("capture shutdown");
    drop(session);
    await_release(baseline);
}

#[test]
#[ignore = "native host loopback evidence runs only via scripts/test-native-platform.py"]
fn native_filter_error_releases_admission() {
    gate();
    if !cfg!(native_layer2) {
        return Unavailable::unsupported("Layer 2 capture is not enabled in this build profile")
            .emit();
    }
    let baseline = warm_baseline();
    let loopback = match loopback() {
        Ok(loopback) => loopback,
        Err(unavailable) => {
            await_release(baseline);
            return unavailable.emit();
        }
    };
    let mut request = capture_request(&loopback, 1, bounded_limits(), NativeSettings::default());
    request.filter = Some("udp and (".to_owned());
    match capture::SystemProvider.arm_capture(&request, &deadline(MAX_WAIT)) {
        Err(Error::InvalidCaptureFilter { message, .. }) => {
            assert!(!message.is_empty(), "the filter error names the problem");
        }
        Err(error @ Error::MissingDependency { .. }) => {
            eprintln!("native loopback: capture backend error: {error}");
            await_release(baseline);
            return Unavailable::backend("capture backend dependency is absent").emit();
        }
        Err(error @ Error::Unsupported(_)) => {
            eprintln!("native loopback: capture capability unsupported: {error}");
            await_release(baseline);
            return Unavailable::unsupported("capture capability is unsupported on this platform")
                .emit();
        }
        Err(error) => panic!("an invalid filter must fail with InvalidCaptureFilter, not {error}"),
        Ok(_) => panic!("an invalid filter must not arm a capture"),
    }
    await_release(baseline);
}

#[test]
#[ignore = "native host loopback evidence runs only via scripts/test-native-platform.py"]
fn iface_disappearance_driver_fail_cleans_up() {
    gate();
    Unavailable {
        reason_code: "isolation_unavailable",
        reason: "host loopback isolation forbids interface mutation or disappearance",
    }
    .emit();
}

fn scoped_cli(targets: &[String], options: &[&str]) -> (bool, serde_json::Value) {
    let binary =
        std::env::var_os("PACKETCRAFTR_NATIVE_CLI").expect("the launcher supplies the built CLI");
    let output = std::process::Command::new(binary)
        .args([
            "scan",
            "--output",
            "json",
            "--attempts",
            "1",
            "--timeout-ms",
            "1000",
            "--max-probes",
            "1",
            "--max-duration-ms",
            "5000",
        ])
        .args(targets)
        .args(options)
        .output()
        .expect("run the scoped target CLI");
    assert!(
        output.stdout.len() + output.stderr.len() <= 65_536,
        "bounded CLI output"
    );
    let json = serde_json::from_slice(&output.stdout).expect("scoped CLI JSON");
    println!("scoped CLI: {}", String::from_utf8_lossy(&output.stdout));
    (output.status.success(), json)
}

/// Every address used below is assigned to this host. No interface is mutated
/// and no off-host destination or neighbor discovery is requested.
#[test]
#[ignore = "native host scoped evidence runs only via scripts/test-native-platform.py"]
fn scoped_ipv6_targets() {
    use packetcraftr_core::error::Classified;
    use packetcraftr_core::protocol::network::Ipv6;
    use std::net::{SocketAddrV6, TcpListener};

    gate();
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/scanner-corpus.v1.json"))
            .expect("independent scanner corpus");
    let expected = &corpus["target_planning_scenarios"]
        .as_array()
        .expect("target scenarios")
        .iter()
        .find(|case| case["id"] == "scoped-host-local")
        .expect("host-local scoped fixture")["expected"];
    if !cfg!(native_route) {
        for options in [
            &["--list"][..],
            &["--connect", "--ports", "1"][..],
            &["--ports", "1"][..],
        ] {
            let (success, json) = scoped_cli(&["fe80::1%1".to_owned()], options);
            assert!(
                !success,
                "unsupported scoped operation must fail: {options:?}"
            );
            assert_eq!(json["error"]["code"], expected["portable"], "{options:?}");
        }
        println!(
            "PACKETCRAFTR_NATIVE_SCOPED={{\"selection\":\"unsupported_capability\",\"connect\":\"unsupported_capability\",\"raw\":\"unsupported_capability\"}}"
        );
        return;
    }
    let baseline = warm_baseline();
    let interfaces = interface::SystemProvider
        .ipv6_interfaces(&deadline(MAX_WAIT))
        .expect("enumerate real IPv6 interface identities without a capture backend");
    // Prefer the loopback link-local address where it exists (macOS lo0).
    // Windows uses an adapter's own link-local address and IPv6 interface index.
    let fixture = interfaces
        .iter()
        .filter(|info| info.flags.up)
        .flat_map(|info| {
            info.addresses
                .iter()
                .filter_map(move |assigned| match assigned.address {
                    IpAddr::V6(address) if address.is_unicast_link_local() => Some((info, address)),
                    _ => None,
                })
        })
        .min_by_key(|(info, _)| !info.flags.loopback);
    let Some((info, address)) = fixture else {
        await_release(baseline);
        return Unavailable {
            reason_code: "isolation_unavailable",
            reason: "this host has no assigned link-local IPv6 address for a host-local scoped fixture",
        }.emit();
    };
    let index = info.id.index;
    assert_ne!(index, 0);
    // Windows friendly names may contain spaces or non-ASCII text. The
    // target grammar intentionally accepts token-sized names; those adapters
    // remain reachable by their real IPv6 index, not their IPv4 index.
    let token_name = !info.id.name.is_empty()
        && info.id.name.len() <= 128
        && !info.id.name.starts_with('-')
        && !info.id.name.bytes().all(|byte| byte.is_ascii_digit())
        && info
            .id
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    let zone = if token_name {
        info.id.name.clone()
    } else {
        index.to_string()
    };
    let named = format!("{address}%{zone}");
    let indexed = if token_name {
        format!("{address}%{index}")
    } else {
        format!("{address}%0{index}")
    };
    let targets = [named.clone(), indexed];
    let (success, json) = scoped_cli(&targets, &["--list"]);
    assert!(success, "scoped list failed: {json}");
    let listed = json["result"]["targets"]
        .as_array()
        .expect("listed targets");
    assert_eq!(
        listed.len() as u64,
        expected["selected_targets"].as_u64().unwrap(),
        "name/index aliases coalesce"
    );
    assert_eq!(listed[0]["address"], address.to_string());
    assert_eq!(listed[0]["scope"]["zone"], zone);
    assert_eq!(listed[0]["scope"]["interface"]["name"], info.id.name);
    assert_eq!(listed[0]["scope"]["interface"]["index"], index);
    assert_eq!(
        listed[0]["origins"].as_array().unwrap().len() as u64,
        expected["origins"].as_u64().unwrap()
    );
    assert_eq!(json["result"]["resolution_performed"], false);

    let listener = TcpListener::bind(SocketAddrV6::new(address, 0, 0, index))
        .expect("bind a TCP listener on this host's scoped address");
    listener.set_nonblocking(true).expect("bounded TCP accept");
    let port = listener
        .local_addr()
        .expect("listener address")
        .port()
        .to_string();
    let (success, json) = scoped_cli(&targets, &["--connect", "--ports", &port]);
    assert!(success, "scoped connect failed: {json}");
    let endpoints = json["result"]["endpoints"]
        .as_array()
        .expect("connect endpoints");
    assert_eq!(endpoints.len(), 1);
    let probe = &endpoints[0]["probes"][0];
    assert_eq!(probe["outcome"], expected["connect_outcome"], "{json}");
    assert_eq!(probe["classification"], expected["connect_classification"]);
    assert_eq!(probe["scope"]["interface"]["index"], index);
    let local: SocketAddr = probe["local"]
        .as_str()
        .expect("client socket local address")
        .parse()
        .unwrap();
    let started = Instant::now();
    let peer = loop {
        match listener.accept() {
            Ok((_, peer)) => break peer,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && started.elapsed() < MAX_WAIT =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("scoped native listener did not receive the connection: {error}"),
        }
    };
    assert_eq!(
        peer, local,
        "independent listener matches the published client socket"
    );
    let SocketAddr::V6(peer) = peer else {
        panic!("scoped socket peer must be IPv6")
    };
    assert_eq!(*peer.ip(), address);
    assert_eq!(
        peer.scope_id(),
        index,
        "native socket keeps its selected IPv6 zone"
    );
    assert_eq!(json["result"]["socket_stats"]["connections_scheduled"], 1);
    drop(listener);

    // A real raw route is pinned to the same resolved identity; a UDP socket
    // supplies independent delivery ground truth, without requiring Npcap.
    let decision = route::SystemProvider
        .lookup_with_preferences(
            IpAddr::V6(address),
            Some(&info.id),
            Some(IpAddr::V6(address)),
            &deadline(MAX_WAIT),
        )
        .expect("route to the host's scoped address on the selected interface");
    assert_eq!(
        decision.interface, info.id,
        "raw route retains the resolved zone"
    );
    assert_eq!(decision.selected_source, Some(IpAddr::V6(address)));
    let receiver =
        UdpSocket::bind(SocketAddrV6::new(address, 0, 0, index)).expect("scoped UDP receiver");
    receiver
        .set_read_timeout(Some(MAX_WAIT))
        .expect("finite UDP receive");
    let source = UdpSocket::bind(SocketAddrV6::new(address, 0, 0, index))
        .expect("reserve scoped source port");
    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source: address,
        destination: address,
        ..Ipv6::default()
    });
    packet.push(Udp {
        source_port: source.local_addr().unwrap().port(),
        destination_port: receiver.local_addr().unwrap().port(),
        ..Udp::default()
    });
    packet.push(Raw::new(PAYLOAD));
    let bytes = packetcraftr_core::build::Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .expect("scoped UDP packet")
        .bytes;
    let outbound = transmit::Outbound::try_new(
        &bytes,
        transmit::Route {
            decision: &decision,
            mode: Mode::Layer3,
            lookup_destination: Some(IpAddr::V6(address)),
        },
    )
    .expect("scoped raw outbound");
    let raw = match transmit::SystemProvider.send(outbound) {
        Ok(report) => {
            report
                .validate_exact(&bytes)
                .expect("raw submission evidence");
            let mut buffer = [0u8; 2048];
            let (length, peer) = receiver
                .recv_from(&mut buffer)
                .expect("scoped raw UDP delivery");
            assert_eq!(&buffer[..length], PAYLOAD);
            assert_eq!(peer.ip(), IpAddr::V6(address));
            assert_eq!(peer.port(), source.local_addr().unwrap().port());
            "exercised"
        }
        Err(error @ Error::Unsupported(_)) => {
            assert_eq!(error.classification().code, "capability.unsupported");
            println!("scoped raw capability: {error}");
            "unsupported_capability"
        }
        Err(error) => panic!("scoped raw send failed: {error}"),
    };
    await_release(baseline);
    println!(
        "PACKETCRAFTR_NATIVE_SCOPED={{\"selection\":\"exercised\",\"connect\":\"exercised\",\"raw\":\"{raw}\"}}"
    );
}
