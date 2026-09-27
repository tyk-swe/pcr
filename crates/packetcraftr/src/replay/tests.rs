// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::capture_file::{Reader, Writer};
use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::{
    Error as LiveIoError,
    interface::Id as InterfaceId,
    link::{Capability as LinkCapability, Mode as LinkMode},
    route::{Decision, Error as RouteError, Scope, SelectionReason},
    transmit::Submission,
};

use super::admission::FinalWire;
use super::engine::run;
use super::error::Error;
use super::evidence::{FrameEvidence, Transmission, network_envelope, validate_transmission};
use super::executor::{Executor, map_route_error};
use super::plan::link_mode;
use super::report::Report;
use super::request::{Limits, Options, Parts, Request, Selector, Source, Timing};
use crate::clock::Clock;
use crate::policy::{Authorizer, Operation};
use crate::route::{Interface, Materialized as MaterializedRoute, Plan as RoutePlan};
use crate::test_support::RecordingClock;
use packetcraftr_core::error::BoundaryError;

#[derive(Default)]
struct RecordingAuthorizer {
    calls: usize,
    final_wire_calls: usize,
    limits: Vec<(u64, u64)>,
    deny: bool,
    deny_final_wire: bool,
}

impl Authorizer for RecordingAuthorizer {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        self.calls += 1;
        let limits = operation.limits();
        self.limits.push((limits.packets(), limits.wire_bytes()));
        assert!(
            matches!(operation, Operation::Replay(_)),
            "replay must submit an exact frame, got {operation:?}"
        );
        if self.deny {
            Err(BoundaryError::new(
                "denied by test policy",
                Classification::new("policy.test", Kind::Policy, None),
                Vec::new(),
            ))
        } else {
            Ok(())
        }
    }
}

impl FinalWire for RecordingAuthorizer {
    fn authorize_final_wire(
        &mut self,
        _frame: &Frame,
        _route: &RoutePlan,
    ) -> Result<(), BoundaryError> {
        self.final_wire_calls += 1;
        if self.deny_final_wire {
            Err(BoundaryError::new(
                "final wire route denied by test policy",
                Classification::new("policy.source_ownership", Kind::Policy, None),
                Vec::new(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct RecordingTransmitter {
    validation_calls: usize,
    transmission_calls: usize,
    partial: bool,
    different_interface: bool,
    /// Resolves every request to this complete identity, the way the system
    /// transmitter resolves a name-only or index-only selector.
    resolves_to: Option<InterfaceId>,
}

impl Executor for RecordingTransmitter {
    fn plan_frame(
        &mut self,
        interface: &Interface,
        mode: LinkMode,
        frame: &Frame,
        _deadline: &Deadline,
    ) -> Result<MaterializedRoute, LiveIoError> {
        self.validation_calls += 1;
        let interface = match (&self.resolves_to, interface) {
            (Some(resolved), _) | (None, Interface::Id(resolved)) => resolved,
            (None, unresolved) => panic!("{unresolved:?} needs a resolved identity"),
        };
        Ok(MaterializedRoute {
            plan: test_route(interface, mode, frame.link_type),
            neighbor_resolution: None,
        })
    }

    fn transmit(
        &mut self,
        route: &MaterializedRoute,
        frame: &Frame,
    ) -> Result<Transmission, LiveIoError> {
        self.transmission_calls += 1;
        let interface = &route.plan.decision.interface;
        let reported_interface = if self.different_interface {
            InterfaceId {
                name: "other0".to_owned(),
                index: interface.index + 1,
            }
        } else {
            interface.clone()
        };
        Ok(Transmission {
            interface: reported_interface,
            report: Submission::start().complete(
                if self.partial {
                    frame.bytes().len().saturating_sub(1)
                } else {
                    frame.bytes().len()
                },
                frame.bytes().clone(),
            ),
        })
    }
}

/// Selects every frame and routes it through [`test_interface`].
struct AllFrames;

impl Selector for AllFrames {
    fn select(&mut self, _source_index: u64, _frame: &Frame) -> Result<bool, Error> {
        Ok(true)
    }

    fn interface(&mut self, _source_index: u64, _frame: &Frame) -> Result<Interface, Error> {
        Ok(Interface::Id(test_interface()))
    }
}

/// Selects every frame and routes it through one interface selector.
struct Through(Interface);

impl Selector for Through {
    fn select(&mut self, _source_index: u64, _frame: &Frame) -> Result<bool, Error> {
        Ok(true)
    }

    fn interface(&mut self, _source_index: u64, _frame: &Frame) -> Result<Interface, Error> {
        Ok(self.0.clone())
    }
}

/// Records the one-based frame numbers it is asked about.
struct RecordingSelector {
    numbers: Vec<u64>,
    skip: Option<u64>,
    keep: bool,
}

impl Selector for RecordingSelector {
    fn select(&mut self, source_index: u64, _frame: &Frame) -> Result<bool, Error> {
        let number = source_index + 1;
        self.numbers.push(number);
        Ok(self.keep && self.skip != Some(number))
    }

    fn interface(&mut self, _source_index: u64, _frame: &Frame) -> Result<Interface, Error> {
        Ok(Interface::Id(test_interface()))
    }
}

fn test_interface() -> InterfaceId {
    InterfaceId {
        name: "test0".to_owned(),
        index: 7,
    }
}

fn test_route(interface: &InterfaceId, mode: LinkMode, link_type: LinkType) -> RoutePlan {
    let selected_source = "192.0.2.1".parse().expect("fixture source");
    let source_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
    RoutePlan {
        decision: Decision {
            interface: interface.clone(),
            source_mac: Some(source_mac),
            selected_source: Some(selected_source),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::InterfaceOnly,
            destination_scope: Scope::Link,
            mtu: 1_500,
            capability: LinkCapability::Layer2AndLayer3,
            link_type,
        },
        mode,
        lookup_destination: None,
        final_destination: None,
        visited_destinations: Vec::new(),
        packet_source: Some(selected_source),
        neighbor_source: None,
        neighbor_target: None,
        destination_mac: None,
        source_mac: Some(source_mac),
        neighbor_vlan_tags: Vec::new(),
        synthesized_ethernet: false,
    }
}

fn capture_reader(link_type: LinkType, frames: &[(Duration, &[u8])]) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), link_type).expect("pcap writer");
    for (offset, bytes) in frames {
        writer
            .write_frame(
                &Frame::new(UNIX_EPOCH + *offset, link_type, bytes.to_vec())
                    .expect("capture frame"),
            )
            .expect("write capture frame");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("capture reader")
}

fn replay_options(timing: Timing) -> Options {
    Options {
        repeat: 1,
        inter_pass_delay: Duration::ZERO,
        link_mode: LinkMode::Auto,
        timing,
        limits: Limits::default(),
        allow_permissive_live: false,
    }
}

/// Replays `source` under `options` through the engine's seams.
fn replay_source<R: std::io::Read, S: Selector, C: Clock>(
    source: Source<R>,
    options: &Options,
    selector: S,
    authorizer: &mut RecordingAuthorizer,
    transmitter: &mut RecordingTransmitter,
    clock: &mut C,
    emit: impl FnMut(FrameEvidence, &Deadline) -> Result<(), Error>,
) -> Result<Report, Error> {
    run(
        Parts {
            source,
            selector,
            options: options.clone(),
        },
        authorizer,
        transmitter,
        clock,
        Deadline::new(options.limits.max_duration),
        emit,
    )
}

/// Replays one seekable capture, rewound before every pass.
fn replay_seekable<S: Selector, C: Clock>(
    reader: Reader<Cursor<Vec<u8>>>,
    options: &Options,
    selector: S,
    authorizer: &mut RecordingAuthorizer,
    transmitter: &mut RecordingTransmitter,
    clock: &mut C,
    emit: impl FnMut(FrameEvidence, &Deadline) -> Result<(), Error>,
) -> Result<Report, Error> {
    replay_source(
        Source::seekable(reader),
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        emit,
    )
}

/// Replays one streaming capture.
fn replay<S: Selector, C: Clock>(
    reader: Reader<Cursor<Vec<u8>>>,
    options: &Options,
    selector: S,
    authorizer: &mut RecordingAuthorizer,
    transmitter: &mut RecordingTransmitter,
    clock: &mut C,
    emit: impl FnMut(FrameEvidence, &Deadline) -> Result<(), Error>,
) -> Result<Report, Error> {
    replay_source(
        Source::stream(reader),
        options,
        selector,
        authorizer,
        transmitter,
        clock,
        emit,
    )
}

#[test]
fn a_partial_interface_selector_accepts_the_interface_it_resolves_to() {
    let resolved = test_interface();
    for (requested, accepted) in [
        (Interface::Name(resolved.name.clone()), true),
        (
            Interface::Index(std::num::NonZeroU32::new(resolved.index).expect("fixture index")),
            true,
        ),
        (Interface::Id(resolved.clone()), true),
        (Interface::Name("other0".to_owned()), false),
        (
            Interface::Id(InterfaceId {
                name: resolved.name.clone(),
                index: resolved.index + 1,
            }),
            false,
        ),
    ] {
        let reader = capture_reader(LinkType::ETHERNET, &[(Duration::ZERO, &[0; 60])]);
        let mut authorizer = RecordingAuthorizer::default();
        let mut transmitter = RecordingTransmitter {
            resolves_to: Some(resolved.clone()),
            ..RecordingTransmitter::default()
        };
        let mut clock = RecordingClock::default();
        let result = replay(
            reader,
            &replay_options(Timing::Immediate),
            Through(requested.clone()),
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_, _| Ok(()),
        );
        if accepted {
            let summary = result.unwrap_or_else(|error| panic!("{requested:?}: {error:?}"));
            assert_eq!(
                summary.interfaces_used,
                std::slice::from_ref(&resolved),
                "{requested:?}"
            );
            assert_eq!(transmitter.transmission_calls, 1, "{requested:?}");
        } else {
            assert!(
                matches!(result, Err(Error::InvalidEvidence { .. })),
                "{requested:?}: {result:?}"
            );
            assert_eq!(transmitter.transmission_calls, 0, "{requested:?}");
        }
    }
}

#[test]
fn replay_timing_validation_rejects_non_finite_and_non_positive_values() {
    for timing in [
        Timing::Scaled(f64::NAN),
        Timing::Scaled(f64::INFINITY),
        Timing::Scaled(-1.0),
        Timing::FixedRate(f64::NAN),
        Timing::FixedRate(f64::INFINITY),
        Timing::FixedRate(0.0),
        Timing::BitRate(0),
    ] {
        assert!(matches!(
            timing.validate(),
            Err(Error::InvalidTiming { .. })
        ));
    }
}

#[test]
fn replay_timing_requires_capture_time_only_for_source_interval_modes() {
    assert_eq!(
        Timing::Immediate
            .delay_between(None, None, 2, 0, Duration::ZERO)
            .expect("immediate timing is independent of capture time"),
        Duration::ZERO
    );
    assert_eq!(
        Timing::FixedRate(2.0)
            .delay_between(None, None, 2, 0, Duration::ZERO)
            .expect("fixed timing is independent of capture time"),
        Duration::from_millis(500)
    );
    assert!(matches!(
        Timing::Original.delay_between(None, Some(UNIX_EPOCH), 2, 0, Duration::ZERO),
        Err(Error::TimestampUnavailable {
            source_index: 2,
            mode: "original"
        })
    ));
    assert!(matches!(
        Timing::Scaled(2.0).delay_between(Some(UNIX_EPOCH), None, 3, 0, Duration::ZERO),
        Err(Error::TimestampUnavailable {
            source_index: 3,
            mode: "scaled"
        })
    ));
}

#[test]
fn replay_network_envelope_rejects_malformed_ip_envelopes() {
    for (bytes, expected) in [
        (Vec::new(), "empty"),
        (vec![0x45; 19], "truncated IPv4"),
        (vec![0x60; 39], "truncated IPv6"),
        (vec![0x70], "unsupported IP version 7"),
    ] {
        let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).expect("capture frame");
        let error = network_envelope(&frame).expect_err("malformed envelope accepted");
        assert!(error.to_string().contains(expected), "{error}");
    }

    let mut ipv4 = vec![0_u8; 20];
    ipv4[0] = 0x45;
    ipv4[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ipv4[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let envelope =
        network_envelope(&Frame::new(UNIX_EPOCH, LinkType::RAW, ipv4).expect("IPv4 frame"))
            .expect("valid IPv4 envelope rejected");
    assert_eq!(envelope.source, "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(envelope.destination, "10.0.0.2".parse::<IpAddr>().unwrap());

    let source: Ipv6Addr = "fd00::1".parse().unwrap();
    let destination: Ipv6Addr = "fd00::2".parse().unwrap();
    let mut ipv6 = vec![0_u8; 40];
    ipv6[0] = 0x60;
    ipv6[8..24].copy_from_slice(&source.octets());
    ipv6[24..40].copy_from_slice(&destination.octets());
    let envelope =
        network_envelope(&Frame::new(UNIX_EPOCH, LinkType::RAW, ipv6).expect("IPv6 frame"))
            .expect("valid IPv6 envelope rejected");
    assert_eq!(envelope.source, IpAddr::V6(source));
    assert_eq!(envelope.destination, IpAddr::V6(destination));
}

#[test]
fn replay_link_mode_errors_preserve_source_index_and_requested_mode() {
    let error = link_mode(7, LinkType(999), LinkMode::Auto).unwrap_err();
    assert!(matches!(
        error,
        Error::UnsupportedLinkType {
            source_index: 7,
            link_type: 999
        }
    ));

    let error = link_mode(8, LinkType::ETHERNET, LinkMode::Layer3).unwrap_err();
    assert!(matches!(
        error,
        Error::LinkModeMismatch {
            source_index: 8,
            link_type,
            requested: LinkMode::Layer3
        } if link_type == LinkType::ETHERNET.0
    ));
}

#[test]
fn replay_transmission_evidence_requires_exact_wire_length_and_bytes() {
    let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0x45, 1, 2]).unwrap();
    validate_transmission(
        1,
        &frame,
        &Submission::start().complete(3, frame.bytes().clone()),
    )
    .unwrap();

    let partial = validate_transmission(
        2,
        &frame,
        &Submission::start().complete(2, frame.bytes().clone()),
    )
    .unwrap_err();
    assert!(matches!(
        partial,
        Error::Transmission {
            source_index: 2,
            ..
        }
    ));

    let mismatch = validate_transmission(
        3,
        &frame,
        &Submission::start().complete(3, Bytes::from_static(&[0x45, 1, 3])),
    )
    .unwrap_err();
    assert!(matches!(
        mismatch,
        Error::Transmission {
            source_index: 3,
            ..
        }
    ));
}

#[test]
fn replay_authorization_denial_has_no_later_io_side_effects() {
    let reader = capture_reader(LinkType::ETHERNET, &[(Duration::ZERO, &[1])]);
    let mut authorizer = RecordingAuthorizer {
        deny: true,
        ..RecordingAuthorizer::default()
    };
    let mut transmitter = RecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let error = replay(
        reader,
        &replay_options(Timing::Immediate),
        AllFrames,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_, _| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        Error::Authorization {
            source_index: 0,
            ..
        }
    ));
    assert_eq!(authorizer.calls, 1);
    assert_eq!(authorizer.final_wire_calls, 0);
    assert_eq!(transmitter.validation_calls, 0);
    assert_eq!(transmitter.transmission_calls, 0);
    assert!(clock.delays().is_empty());
}

#[test]
fn replay_final_wire_denial_happens_after_passive_route_selection_and_before_send() {
    let reader = capture_reader(LinkType::ETHERNET, &[(Duration::ZERO, &[1])]);
    let mut authorizer = RecordingAuthorizer {
        deny_final_wire: true,
        ..RecordingAuthorizer::default()
    };
    let mut transmitter = RecordingTransmitter::default();
    let mut clock = RecordingClock::default();

    let error = replay(
        reader,
        &replay_options(Timing::Immediate),
        AllFrames,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_, _| Ok(()),
    )
    .expect_err("final wire authorization must reject the selected route");

    assert!(matches!(
        error,
        Error::Authorization {
            source_index: 0,
            ..
        }
    ));
    assert_eq!(authorizer.calls, 1);
    assert_eq!(authorizer.final_wire_calls, 1);
    assert_eq!(transmitter.validation_calls, 1);
    assert_eq!(transmitter.transmission_calls, 0);
    assert!(clock.delays().is_empty());
}

#[test]
fn replay_selector_skips_authorization_and_preserves_transmitted_spacing() {
    let reader = capture_reader(
        LinkType::ETHERNET,
        &[
            (Duration::from_secs(1), &[1, 2]),
            (Duration::from_secs(2), &[3, 4, 5]),
            (Duration::from_secs(3), &[6, 7, 8, 9]),
        ],
    );
    let mut selector = RecordingSelector {
        numbers: Vec::new(),
        skip: Some(2),
        keep: true,
    };
    let mut authorizer = RecordingAuthorizer::default();
    let mut transmitter = RecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let mut emitted = Vec::new();
    let summary = replay(
        reader,
        &replay_options(Timing::Original),
        &mut selector,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |evidence, _| {
            emitted.push(evidence);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(selector.numbers, [1, 2, 3]);
    assert_eq!(authorizer.limits, [(1, 2), (2, 6)]);
    assert_eq!(transmitter.transmission_calls, 2);
    assert_eq!(clock.delays(), [Duration::ZERO, Duration::from_secs(2)]);
    assert_eq!(summary.frames_read, 3);
    assert_eq!(summary.frames_transmitted, 2);
    assert_eq!(summary.bytes_transmitted, 6);
    assert_eq!(
        emitted
            .iter()
            .map(|evidence| evidence.source_index)
            .collect::<Vec<_>>(),
        [0, 2]
    );
}

#[test]
fn replay_selector_skipped_frames_still_consume_the_frame_budget() {
    let reader = capture_reader(
        LinkType::ETHERNET,
        &[
            (Duration::ZERO, &[1]),
            (Duration::ZERO, &[2]),
            (Duration::ZERO, &[3]),
        ],
    );
    let mut selector = RecordingSelector {
        numbers: Vec::new(),
        skip: None,
        keep: false,
    };
    let mut options = replay_options(Timing::Immediate);
    options.limits.max_source_frames = 2;
    let mut authorizer = RecordingAuthorizer::default();
    let mut transmitter = RecordingTransmitter::default();
    let error = replay(
        reader,
        &options,
        &mut selector,
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |_, _| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(
        error,
        Error::SourceFrameLimit {
            source_index: 2,
            actual: 3,
            limit: 2,
        }
    ));
    assert_eq!(selector.numbers, [1, 2]);
    assert_eq!(authorizer.calls, 0);
    assert_eq!(transmitter.transmission_calls, 0);
}

#[test]
fn byte_rate_uses_selected_bytes_and_cumulative_rounding() {
    let reader = capture_reader(
        LinkType::ETHERNET,
        &[
            (Duration::ZERO, &[1, 2]),
            (Duration::from_secs(100), &[3, 4, 5]),
            (Duration::ZERO, &[6, 7, 8, 9]),
            (Duration::ZERO, &[10]),
        ],
    );
    let mut selector = RecordingSelector {
        numbers: Vec::new(),
        skip: Some(2),
        keep: true,
    };
    let mut clock = RecordingClock::default();
    let mut authorizer = RecordingAuthorizer::default();
    let mut transmitter = RecordingTransmitter::default();
    let summary = replay(
        reader,
        &replay_options(Timing::BitRate(3_000_000_000)),
        &mut selector,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |_, _| Ok(()),
    )
    .unwrap();
    assert_eq!(
        clock.delays(),
        [
            Duration::ZERO,
            Duration::from_nanos(6),
            Duration::from_nanos(10)
        ]
    );
    assert_eq!(summary.scheduled_duration, Duration::from_nanos(16));
    assert_eq!(summary.bytes_transmitted, 7);
    assert_eq!(authorizer.limits, [(1, 2), (2, 6), (3, 7)]);
    assert_eq!(authorizer.final_wire_calls, 3);
}

#[test]
fn byte_rate_duration_and_policy_failures_stop_before_later_transmission() {
    let frames = [(Duration::ZERO, &[1_u8][..]), (Duration::ZERO, &[2_u8][..])];
    let mut options = replay_options(Timing::BitRate(1));
    options.limits.max_duration = Duration::from_secs(1);
    let mut transmitter = RecordingTransmitter::default();
    let error = replay(
        capture_reader(LinkType::ETHERNET, &frames),
        &options,
        AllFrames,
        &mut RecordingAuthorizer::default(),
        &mut transmitter,
        &mut RecordingClock::default(),
        |_, _| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        Error::DurationLimit {
            source_index: 1,
            ..
        }
    ));
    assert_eq!(transmitter.transmission_calls, 1);

    let mut transmitter = RecordingTransmitter::default();
    let mut authorizer = RecordingAuthorizer {
        deny_final_wire: true,
        ..RecordingAuthorizer::default()
    };
    assert!(
        replay(
            capture_reader(LinkType::ETHERNET, &frames),
            &options,
            AllFrames,
            &mut authorizer,
            &mut transmitter,
            &mut RecordingClock::default(),
            |_, _| Ok(()),
        )
        .is_err()
    );
    assert_eq!(transmitter.transmission_calls, 0);
}

/// Both arms of the replay route-selection mapping retain the route adapter's
/// own refusal as a source, so the platform diagnostic reaches `causes()`
/// instead of being dropped when it stops being restated in `message`.
#[test]
fn replay_route_selection_failures_retain_the_route_adapter_refusal() {
    let destination = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let unreachable = map_route_error(RouteError::RouteNotFound { destination });

    assert_eq!(
        unreachable.to_string(),
        "packet transmission failed: replay route selection failed"
    );
    assert_eq!(unreachable.classification().code, "io.send");
    assert_eq!(unreachable.causes(), ["no route to 203.0.113.9 was found"]);

    // The refusal keeps reaching a consumer through the replay wrapper the
    // engine publishes it in.
    let published = Error::Transmission {
        source_index: 0,
        source: unreachable,
    };
    assert_eq!(
        published.causes(),
        [
            "packet transmission failed: replay route selection failed",
            "no route to 203.0.113.9 was found",
        ]
    );

    // An operating-system refusal keeps its own nested diagnostic too.
    let refused = map_route_error(RouteError::OperatingSystem {
        operation: "RTM_GETROUTE",
        message: "the operating system refused the request".to_owned(),
        source: Some(packetcraftr_core::error::Source::new(
            std::io::Error::other("operation not permitted"),
        )),
    });
    assert_eq!(
        refused.causes(),
        [
            "native operation RTM_GETROUTE failed: the operating system refused the request",
            "operation not permitted",
        ]
    );

    // The capability arm keeps naming the replay boundary and publishes the
    // adapter's text once, in `causes`.
    let unsupported = map_route_error(RouteError::Unsupported(
        packetcraftr_netio::Unsupported::new(
            packetcraftr_netio::NativeCapability::Route,
            "native route selection is off",
        ),
    ));
    assert_eq!(
        unsupported.to_string(),
        "live packet I/O is unavailable: the native route adapter cannot select a replay route"
    );
    assert_eq!(unsupported.classification().kind, Kind::Capability);
    assert_eq!(
        unsupported.causes(),
        ["native route selection is unavailable: native route selection is off"]
    );
}

#[test]
fn replay_processing_cost_reduces_waits_and_overruns_keep_the_anchor() {
    use crate::clock::Clock;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    #[derive(Clone)]
    struct VirtualClock {
        now: Arc<Mutex<Instant>>,
        waits: Arc<Mutex<Vec<Duration>>>,
    }
    impl Clock for VirtualClock {
        type Error = std::convert::Infallible;
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
        fn sleep(
            &self,
            delay: Duration,
            _deadline: &packetcraftr_core::budget::Deadline,
        ) -> Result<(), Self::Error> {
            self.waits.lock().unwrap().push(delay);
            *self.now.lock().unwrap() += delay;
            Ok(())
        }
    }
    let now = Arc::new(Mutex::new(Instant::now()));
    let mut clock = VirtualClock {
        now: Arc::clone(&now),
        waits: Arc::default(),
    };
    let reader = capture_reader(
        LinkType::ETHERNET,
        &[
            (Duration::from_secs(1), &[1]),
            (Duration::from_secs(2), &[2]),
            (Duration::from_secs(3), &[3]),
            (Duration::from_secs(4), &[4]),
        ],
    );
    let mut overhead = [700, 2500, 0, 0].into_iter();
    let summary = replay(
        reader,
        &replay_options(Timing::Original),
        AllFrames,
        &mut RecordingAuthorizer::default(),
        &mut RecordingTransmitter::default(),
        &mut clock,
        |_, _| {
            *now.lock().unwrap() += Duration::from_millis(overhead.next().unwrap());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(summary.frames_transmitted, 4);
    assert_eq!(summary.scheduled_duration, Duration::from_secs(3));
    assert_eq!(
        *clock.waits.lock().unwrap(),
        [
            Duration::ZERO,
            Duration::from_millis(300),
            Duration::ZERO,
            Duration::ZERO
        ]
    );
}

/// Routes the frame at source index `i` through `test{i + 1}`.
struct MappedInterfaces;
impl Selector for MappedInterfaces {
    fn select(&mut self, _: u64, _: &Frame) -> Result<bool, Error> {
        Ok(true)
    }
    fn interface(&mut self, source_index: u64, _: &Frame) -> Result<Interface, Error> {
        let number = source_index + 1;
        Ok(Interface::Id(InterfaceId {
            name: format!("test{number}"),
            index: 6 + u32::try_from(number).expect("fixture index"),
        }))
    }
}

#[test]
fn repeated_replay_keeps_source_positions_and_uses_one_budget_and_interface_schedule() {
    let capture = || {
        capture_reader(
            LinkType::ETHERNET,
            &[(Duration::ZERO, b"ab"), (Duration::from_millis(10), b"cd")],
        )
    };
    let mut options = replay_options(Timing::Original);
    options.repeat = 2;
    options.inter_pass_delay = Duration::from_millis(3);
    let mut authorizer = RecordingAuthorizer::default();
    let mut transmitter = RecordingTransmitter::default();
    let mut clock = RecordingClock::default();
    let mut evidence = Vec::new();
    let summary = replay_seekable(
        capture(),
        &options,
        MappedInterfaces,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |frame, _| {
            evidence.push(frame);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(summary.passes_completed, 2);
    assert_eq!(summary.frames_read, 4);
    assert_eq!(summary.frames_transmitted, 4);
    assert_eq!(summary.interfaces_used.len(), 2);
    assert_eq!(summary.scheduled_duration, Duration::from_millis(23));
    assert_eq!(
        evidence
            .iter()
            .map(|frame| (
                frame.pass,
                frame.source_index,
                frame.transmission().interface.index
            ))
            .collect::<Vec<_>>(),
        [(1, 0, 7), (1, 1, 8), (2, 0, 7), (2, 1, 8)]
    );
    assert_eq!(authorizer.final_wire_calls, 4);
    assert_eq!(authorizer.limits, [(1, 2), (2, 4), (3, 6), (4, 8)]);
    options.limits.max_source_frames = 3;
    let mut transmitter = RecordingTransmitter::default();
    assert!(matches!(
        replay_seekable(
            capture(),
            &options,
            MappedInterfaces,
            &mut authorizer,
            &mut transmitter,
            &mut RecordingClock::default(),
            |_, _| Ok(())
        ),
        Err(Error::SourceFrameLimit {
            actual: 4,
            limit: 3,
            ..
        })
    ));
    assert_eq!(transmitter.transmission_calls, 3);

    let mut transmitter = RecordingTransmitter::default();
    let error = replay(
        capture(),
        &options,
        MappedInterfaces,
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |_, _| Ok(()),
    )
    .expect_err("a streaming capture cannot be read twice");
    assert!(
        matches!(
            error,
            Error::InvalidLimit {
                field: "repeat",
                value: 2,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(transmitter.validation_calls, 0);
}

#[test]
fn generated_capture_replays_verbatim_through_fake_providers() {
    // `build --output pcap --link-type raw` emits exactly this: packets built
    // by the codec builder framed under an explicit link type with
    // deterministic timestamps.
    let registry = packetcraftr_core::protocol::builtin::registry();
    let builder = packetcraftr_core::build::Builder::new(std::sync::Arc::clone(&registry));
    let mut bytes = Vec::new();
    let mut writer = Writer::pcap(Vec::new(), LinkType::RAW).expect("pcap writer");
    for ttl in [1_u8, 64] {
        let packet = packetcraftr_core::expression::parse(
            &format!("ipv4(src=192.0.2.1,dst=192.0.2.2,ttl={ttl})/udp(dport=9000)"),
            &registry,
            Default::default(),
        )
        .expect("recipe parses");
        let built = builder
            .build(
                packet,
                packetcraftr_core::codec::Context::default(),
                packetcraftr_core::build::Options::default(),
            )
            .expect("packet builds");
        bytes.push(built.bytes.clone());
        writer
            .write_frame(&Frame::new(UNIX_EPOCH, LinkType::RAW, built.bytes).expect("frame"))
            .expect("capture frame writes");
    }
    let reader = Reader::new(Cursor::new(writer.into_inner())).expect("generated capture opens");

    let mut transmitter = RecordingTransmitter::default();
    let mut authorizer = RecordingAuthorizer::default();
    let mut evidence = Vec::new();
    let summary = replay(
        reader,
        &replay_options(Timing::Immediate),
        AllFrames,
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |frame, _| {
            evidence.push(frame);
            Ok(())
        },
    )
    .expect("generated capture replays");

    assert_eq!(summary.frames_transmitted, 2);
    assert_eq!(
        evidence
            .iter()
            .map(|frame| frame.frame.bytes().clone())
            .collect::<Vec<_>>(),
        bytes,
        "transmitted frames are the exact built bytes"
    );
    assert_eq!(transmitter.transmission_calls, 2);
    assert_eq!(authorizer.final_wire_calls, 2);
}

/// `Client::replay` over fake providers: the client's policy admits each
/// frame, its interface and transmit providers carry it, and its sink
/// receives the evidence.
mod client {
    use std::sync::{Arc, Mutex};

    use packetcraftr_core::budget::Cancelled;
    use packetcraftr_core::build::Builder;
    use packetcraftr_core::packet::Packet;
    use packetcraftr_core::protocol::{
        link::Ethernet,
        network::{Icmpv4, Ipv4},
    };
    use packetcraftr_netio::interface::{self, Address, Flags};

    use super::*;
    use crate::policy::Policy;
    use packetcraftr_core::filter::{Filter, FrameSelector, Options as FilterOptions};

    use crate::replay::{
        Collector,
        routing::{Condition, Routing, Rule},
    };
    use crate::test_support::{Call, FakeProviders};
    use crate::{Client, ProviderSet};

    const INTERFACE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);

    type Providers = ProviderSet<
        FakeProviders,
        Interfaces,
        FakeProviders,
        FakeProviders,
        FakeProviders,
        FakeProviders,
    >;

    /// Two up Ethernet interfaces that own 192.0.2.1, enumerated into the
    /// same call log as the other fake providers.
    #[derive(Clone)]
    struct Interfaces(Arc<Mutex<Vec<Call>>>);

    impl interface::Provider for Interfaces {
        fn interfaces(
            &self,
            _deadline: &Deadline,
        ) -> Result<Vec<interface::Info>, interface::Error> {
            self.0
                .lock()
                .expect("fake provider calls")
                .push(Call::Interfaces);
            let info = |id| interface::Info {
                id,
                description: None,
                mac_address: Some(INTERFACE_MAC),
                addresses: vec![Address {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    prefix_length: 24,
                }],
                flags: Flags {
                    up: true,
                    ..Flags::default()
                },
                mtu: Some(1_500),
                capability: LinkCapability::Layer2AndLayer3,
                link_type: LinkType::ETHERNET,
            };
            Ok(vec![info(test_interface()), info(second_interface())])
        }
    }

    /// The other interface [`Interfaces`] enumerates.
    fn second_interface() -> InterfaceId {
        InterfaceId {
            name: "test1".to_owned(),
            index: 8,
        }
    }

    /// A client whose policy permits the permissive rebuild every replayed
    /// frame needs, over fake providers sharing one call log.
    fn client(policy: Policy) -> (Client<Providers>, FakeProviders) {
        let fake = FakeProviders::default();
        let providers = ProviderSet {
            route: fake.clone(),
            interface: Interfaces(Arc::clone(&fake.calls)),
            capture: fake.clone(),
            transmit: fake.clone(),
            tcp: fake.clone(),
            resolver: fake.clone(),
        };
        let client = Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            policy,
            providers,
        );
        (client, fake)
    }

    fn permissive() -> Policy {
        Policy {
            allow_permissive_packets: true,
            ..Policy::default()
        }
    }

    /// An ICMP echo from the interface's own addresses to a documentation
    /// neighbor, identified by `ttl`.
    fn owned_frame(ttl: u8) -> Vec<u8> {
        let mut packet = Packet::new();
        packet
            .push(Ethernet {
                source: INTERFACE_MAC.0,
                destination: [0x02, 0, 0, 0, 0, 2],
                ..Ethernet::default()
            })
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(192, 0, 2, 2),
                ttl,
                ..Ipv4::default()
            })
            .push(Icmpv4::default());
        Builder::new(packetcraftr_core::protocol::builtin::registry())
            .build(
                packet,
                packetcraftr_core::codec::Context::default(),
                packetcraftr_core::build::Options::default(),
            )
            .expect("replay fixture builds")
            .bytes
            .to_vec()
    }

    fn request(frames: &[Vec<u8>]) -> Request<Cursor<Vec<u8>>> {
        routed_request(frames, Routing::from(Interface::Id(test_interface())))
    }

    fn routed_request(frames: &[Vec<u8>], routing: Routing) -> Request<Cursor<Vec<u8>>> {
        let frames = frames
            .iter()
            .map(|bytes| (Duration::ZERO, bytes.as_slice()))
            .collect::<Vec<_>>();
        let mut options = replay_options(Timing::Immediate);
        options.allow_permissive_live = true;
        Request::new(
            Source::stream(capture_reader(LinkType::ETHERNET, &frames)),
            routing,
            options,
        )
    }

    /// Routing by filter rules, each `(filter, interface)`.
    fn filter_routing(rules: &[(&str, Interface)]) -> Routing {
        let registry = packetcraftr_core::protocol::builtin::registry();
        let rules = rules
            .iter()
            .map(|(filter, interface)| Rule {
                condition: Condition::Filter(
                    FrameSelector::new(
                        Arc::clone(&registry),
                        Filter::compile(filter, &registry, FilterOptions::default())
                            .expect("fixture filter compiles"),
                        1_500,
                    )
                    .expect("frame filter"),
                ),
                interface: interface.clone(),
            })
            .collect();
        Routing::new(rules, None).expect("bounded rules")
    }

    #[test]
    fn routing_sends_each_frame_through_the_interface_its_rule_names() {
        let frames = [owned_frame(1), owned_frame(64)];
        let (client, fake) = client(permissive());
        let collector = Collector::default();
        let routing = filter_routing(&[
            ("ipv4.ttl == 1", Interface::Name("test0".to_owned())),
            (
                "ipv4.ttl == 64",
                Interface::Index(std::num::NonZeroU32::new(8).expect("fixture index")),
            ),
        ]);

        let report = client
            .replay(routed_request(&frames, routing), collector.clone())
            .expect("both frames are routed");
        let aggregate = collector.finish(report).expect("collected frames agree");

        assert_eq!(
            aggregate.report.interfaces_used,
            [test_interface(), second_interface()]
        );
        assert_eq!(
            aggregate
                .frames
                .iter()
                .map(|evidence| evidence.transmission().interface.clone())
                .collect::<Vec<_>>(),
            [test_interface(), second_interface()]
        );
        // Each name or index selector resolves through the interface provider.
        assert_eq!(
            fake.calls(),
            [
                Call::Interfaces,
                Call::Transmit(frames[0].clone()),
                Call::Interfaces,
                Call::Transmit(frames[1].clone()),
            ]
        );
    }

    #[test]
    fn a_frame_its_rules_route_two_ways_stops_before_any_provider() {
        let (client, fake) = client(permissive());
        let routing = filter_routing(&[
            ("ipv4", Interface::Name("test0".to_owned())),
            ("icmp", Interface::Name("test1".to_owned())),
        ]);

        let error = client
            .replay(
                routed_request(&[owned_frame(64)], routing),
                Collector::default(),
            )
            .expect_err("the frame's rules disagree");

        assert!(
            matches!(error, Error::ConflictingInterfaces { source_index: 0 }),
            "{error:?}"
        );
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
    }

    #[test]
    fn replay_admits_routes_and_transmits_each_captured_frame_exactly() {
        let frames = [owned_frame(1), owned_frame(64)];
        let (client, fake) = client(permissive());
        let collector = Collector::default();

        let report = client
            .replay(request(&frames), collector.clone())
            .expect("owned documentation frames replay");
        let aggregate = collector.finish(report).expect("collected frames agree");

        assert_eq!(aggregate.report.frames_transmitted, 2);
        assert_eq!(aggregate.report.interfaces_used, [test_interface()]);
        assert_eq!(
            aggregate
                .frames
                .iter()
                .map(|evidence| evidence.frame.bytes().to_vec())
                .collect::<Vec<_>>(),
            frames
        );
        // The validated interface is enumerated once and reused.
        assert_eq!(
            fake.calls(),
            [
                Call::Interfaces,
                Call::Transmit(frames[0].clone()),
                Call::Transmit(frames[1].clone()),
            ]
        );
    }

    #[test]
    fn a_frame_the_policy_denies_consults_no_provider() {
        let (client, fake) = client(Policy::default());

        let error = client
            .replay(request(&[owned_frame(64)]), Collector::default())
            .expect_err("the default policy refuses permissive rebuilds");

        assert_eq!(error.classification().code, "policy.permissive_packet");
        assert!(fake.calls().is_empty(), "{:?}", fake.calls());
    }

    #[test]
    fn a_failing_sink_stops_the_replay_with_its_failure_as_the_source() {
        let frames = [owned_frame(1), owned_frame(64)];
        let (client, fake) = client(permissive());

        let error = client
            .replay(request(&frames), |_: crate::replay::Event| {
                Err(BoundaryError::new(
                    "fixture sink closed",
                    Classification::new("io.fixture", Kind::Io, None),
                    vec!["fixture cause".to_owned()],
                ))
            })
            .expect_err("the sink refuses the first frame");

        assert!(
            matches!(
                error,
                Error::Output {
                    source_index: 0,
                    ..
                }
            ),
            "{error:?}"
        );
        assert_eq!(error.classification().code, "io.replay");
        assert_eq!(
            std::error::Error::source(&error).map(ToString::to_string),
            Some("fixture sink closed".to_owned())
        );
        assert_eq!(error.causes(), ["fixture sink closed", "fixture cause"]);
        assert_eq!(fake.calls().len(), 2, "one frame was sent before the sink");
    }

    #[test]
    fn a_sink_interrupted_by_cancellation_stops_the_replay_as_cancelled() {
        let (client, _) = client(permissive());

        let error = client
            .replay(request(&[owned_frame(64)]), |_: crate::replay::Event| {
                Err(BoundaryError::from_error(Cancelled))
            })
            .expect_err("the sink was interrupted");

        assert!(matches!(error, Error::Cancelled(_)), "{error:?}");
    }
}
