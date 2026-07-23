// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
#[test]
fn hostname_policy_precedes_resolution_and_resolved_policy_precedes_routes() {
    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let route_calls = Arc::new(AtomicUsize::new(0));
    let resolver = RecordingHostnameResolver {
        calls: Arc::clone(&resolver_calls),
        results: Arc::new(Mutex::new(VecDeque::from([vec![IpAddr::V4(
            Ipv4Addr::new(10, 0, 0, 2),
        )]]))),
    };
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: route(LinkCapability::Layer3),
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy::default(),
    );
    let target = "private.example".parse::<LiveTarget>().unwrap();
    let request = packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::UNSPECIFIED, 12_345, 9);

    let error = client
        .plan_target(
            &request,
            &target,
            &resolver,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                ..PlanOptions::default()
            },
        )
        .unwrap_err();

    assert!(matches!(
        error,
        ClientError::Target(TargetResolutionError::Policy(
            TrafficPolicyError::HostnameResolution { .. }
        ))
    ));
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn resolved_target_selects_addresses_by_typed_ip_version() {
    let ipv4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let ipv6 = "fd00::2".parse().unwrap();
    let resolved = ResolvedTarget {
        declared: LiveTarget::Address(ipv4),
        addresses: vec![ipv6, ipv4],
    };

    assert_eq!(resolved.address_for_version(IpVersion::V4), Some(ipv4));
    assert_eq!(resolved.address_for_version(IpVersion::V6), Some(ipv6));
}

#[test]
fn every_resolution_reauthorizes_all_addresses_before_route_use() {
    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let route_calls = Arc::new(AtomicUsize::new(0));
    let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let resolver = RecordingHostnameResolver {
        calls: Arc::clone(&resolver_calls),
        results: Arc::new(Mutex::new(VecDeque::from([
            vec![private],
            vec![private, public],
        ]))),
    };
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: route(LinkCapability::Layer3),
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy {
            allow_hostname_resolution: true,
            ..TrafficPolicy::default()
        },
    );
    let target = "changing.example".parse::<LiveTarget>().unwrap();
    let request = packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::UNSPECIFIED, 12_345, 9);
    let options = PlanOptions {
        link_mode: LinkMode::Layer3,
        ..PlanOptions::default()
    };

    let (first, _) = client
        .plan_target(&request, &target, &resolver, &options)
        .unwrap();
    assert_eq!(first.addresses(), &[private]);
    let error = client
        .plan_target(&request, &target, &resolver, &options)
        .unwrap_err();

    assert!(matches!(
        error,
        ClientError::Target(TargetResolutionError::Policy(
            TrafficPolicyError::PublicDestination { destination }
        )) if destination == public
    ));
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 2);
    assert_eq!(route_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn hostname_and_live_error_classifications_are_stable() {
    assert!("EXAMPLE.test.".parse::<Hostname>().is_ok());
    for invalid in ["", "bad label.example", "-bad.example", "bad-.example"] {
        assert!(matches!(
            invalid.parse::<Hostname>(),
            Err(TargetResolutionError::InvalidHostname { .. })
        ));
    }
    assert_eq!(
        LiveIoError::Privilege {
            message: "denied".to_owned(),
        }
        .classification()
        .kind,
        Kind::Capability
    );
    assert_eq!(
        LiveIoError::PartialSend {
            expected: 10,
            actual: 9,
        }
        .classification()
        .code,
        "io.partial_send"
    );
    assert_eq!(
        LiveIoError::InvalidSendReport {
            bytes_sent: 1,
            wire_bytes: 2,
        }
        .classification()
        .kind,
        Kind::Internal
    );
    assert_eq!(
        NativeRouteError::Unsupported {
            message: "disabled".to_owned(),
        }
        .classification()
        .code,
        "capability.route"
    );
    assert_eq!(
        NeighborError::Io {
            interface: "test0".to_owned(),
            target: IpAddr::V4(Ipv4Addr::LOCALHOST),
            operation: "opening capture",
            source: LiveIoError::MissingDependency {
                dependency: "test backend",
                message: "missing".to_owned(),
            },
        }
        .classification()
        .kind,
        Kind::Capability
    );
}

#[test]
fn aggregate_capture_retention_uses_one_frame_ceiling() {
    let mut frames = 0;
    let mut bytes = 0;
    let mut diagnostics = Vec::new();
    assert!(reserve_capture_evidence(
        &mut frames,
        &mut bytes,
        10,
        1,
        100,
        &mut diagnostics,
    ));
    assert!(!reserve_capture_evidence(
        &mut frames,
        &mut bytes,
        10,
        1,
        100,
        &mut diagnostics,
    ));
    assert_eq!((frames, bytes), (1, 10));
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.capture_frame_limit")
    );
}

#[test]
fn capture_queue_limits_fail_closed_at_zero_and_stable_maxima() {
    assert_eq!(
        CaptureQueueLimits::default().validate().unwrap(),
        CaptureQueueLimits::default()
    );

    for (field, limits) in [
        (
            "max_frames",
            CaptureQueueLimits {
                max_frames: 0,
                ..CaptureQueueLimits::default()
            },
        ),
        (
            "max_bytes",
            CaptureQueueLimits {
                max_bytes: 0,
                ..CaptureQueueLimits::default()
            },
        ),
        (
            "snap_length",
            CaptureQueueLimits {
                snap_length: 0,
                ..CaptureQueueLimits::default()
            },
        ),
    ] {
        assert!(matches!(
            limits.validate(),
            Err(LiveIoError::InvalidCaptureQueueLimit {
                field: actual,
                ..
            }) if actual == field
        ));
    }

    for (field, limits) in [
        (
            "max_frames",
            CaptureQueueLimits {
                max_frames: DEFAULT_CAPTURE_QUEUE_FRAMES + 1,
                ..CaptureQueueLimits::default()
            },
        ),
        (
            "max_bytes",
            CaptureQueueLimits {
                max_bytes: DEFAULT_CAPTURE_QUEUE_BYTES + 1,
                ..CaptureQueueLimits::default()
            },
        ),
        (
            "snap_length",
            CaptureQueueLimits {
                snap_length: crate::capture::DEFAULT_SIZE_LIMIT + 1,
                ..CaptureQueueLimits::default()
            },
        ),
    ] {
        assert!(matches!(
            limits.validate(),
            Err(LiveIoError::InvalidCaptureQueueLimit {
                field: actual,
                ..
            }) if actual == field
        ));
    }

    assert!(matches!(
        CaptureQueueLimits {
            max_frames: usize::MAX,
            max_bytes: usize::MAX,
            snap_length: 2,
            overflow_policy: CaptureOverflowPolicy::Fail,
        }
        .validate(),
        Err(LiveIoError::InvalidCaptureQueueLimit {
            field: "max_frames",
            ..
        })
    ));
    assert!(matches!(
        CaptureQueueLimits {
            max_bytes: 1,
            snap_length: 2,
            ..CaptureQueueLimits::default()
        }
        .validate(),
        Err(LiveIoError::InvalidCaptureQueueLimit {
            field: "snap_length",
            ..
        })
    ));
}

#[test]
fn invalid_exchange_limits_fail_before_route_or_live_side_effects() {
    let route_calls = Arc::new(AtomicUsize::new(0));
    let neighbors = CountingNeighbors::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let io = ScriptedExchangeIo {
        events: Arc::clone(&events),
        response: Arc::new(Mutex::new(None)),
        deliver_before_send: false,
        limits: Arc::new(Mutex::new(Vec::new())),
        capture_statistics: CaptureStatistics::default(),
    };
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: route(LinkCapability::Layer3),
            calls: Arc::clone(&route_calls),
        },
        neighbors.clone(),
        io,
        TrafficPolicy::default(),
    );
    let template = PacketTemplate::new(packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12_345,
        9,
    ));

    for options in [
        ExchangeOptions {
            max_capture_queue_frames: 1,
            max_responses: 2,
            ..ExchangeOptions::default()
        },
        ExchangeOptions {
            timeout: MAX_EXCHANGE_TIMEOUT + Duration::from_nanos(1),
            ..ExchangeOptions::default()
        },
    ] {
        assert!(matches!(
            client.exchange(&template, options),
            Err(ClientError::InvalidExchangeOption { .. })
        ));
    }
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
    assert!(events.lock().unwrap().is_empty());
}
