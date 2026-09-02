// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use crate::progress::Runtime;
use bytes::Bytes;
use packetcraftr_core::build::Builder;
use packetcraftr_core::error::Classified;
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr_core::{Packet, layer::Raw};
use packetcraftr_netio::{capture::Statistics as CaptureStatistics, transmit::Submission};

use crate::test_fixtures::NoopClock;
use crate::{BoundaryError, Stats as ExecutionStats};

use super::evidence::add_execution_stats;
use crate::authorization::{Authorizer, Operation};

use super::{
    Execution, ExecutionCase, Executor, LiveLimits, LiveOptions, RunInput, Stats, run,
    run_with_events,
};

#[test]
fn live_evidence_limits_are_validated_outside_the_offline_campaign() {
    LiveOptions::default()
        .validate()
        .expect("default live limits");

    for limits in [
        LiveLimits {
            max_evidence_frames: 0,
            ..LiveLimits::default()
        },
        LiveLimits {
            max_evidence_bytes: 0,
            ..LiveLimits::default()
        },
    ] {
        let error = LiveOptions {
            limits,
            ..LiveOptions::default()
        }
        .validate()
        .expect_err("zero live evidence limit must fail");
        assert!(matches!(error, super::Error::InvalidLimit { .. }));
    }
}

#[test]
fn aggregate_live_fuzz_validates_case_count_before_collecting() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        cases: usize::MAX,
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = AllowAll;
    let mut executor = CountingExecutor::default();

    let error = run(
        RunInput {
            request: &request,
            live: LiveOptions::default(),
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("an oversized live aggregate campaign must fail validation");

    assert!(matches!(
        error,
        super::Error::Campaign(packet_fuzz::Error::InvalidLimit { field: "cases", .. })
    ));
    assert_eq!(executor.executions, 0);
}

#[test]
fn execution_statistics_aggregation_is_complete_and_atomic() {
    let mut total = Stats {
        cases_generated: 7,
        cases_built: 5,
        packets_attempted: 1,
        packets_completed: 2,
        bytes: 3,
        elapsed: Duration::from_secs(4),
        capture: CaptureStatistics {
            received_frames: 5,
            dropped_frames: 6,
            receiver_dropped_frames: 4,
            ..CaptureStatistics::default()
        },
    };
    add_execution_stats(
        &mut total,
        &ExecutionStats {
            packets_attempted: 10,
            packets_completed: 20,
            bytes: 30,
            elapsed: Duration::from_secs(40),
            capture: CaptureStatistics {
                received_frames: 50,
                dropped_frames: 60,
                receiver_dropped_frames: 40,
                ..CaptureStatistics::default()
            },
        },
        11,
    )
    .expect("bounded statistics");
    assert_eq!(
        total,
        Stats {
            cases_generated: 7,
            cases_built: 5,
            packets_attempted: 11,
            packets_completed: 22,
            bytes: 33,
            elapsed: Duration::from_secs(44),
            capture: CaptureStatistics {
                received_frames: 55,
                dropped_frames: 66,
                receiver_dropped_frames: 44,
                ..CaptureStatistics::default()
            },
        }
    );

    let before = total.clone();
    let error = add_execution_stats(
        &mut total,
        &ExecutionStats {
            packets_attempted: 1,
            capture: CaptureStatistics {
                receiver_dropped_frames: u64::MAX,
                ..CaptureStatistics::default()
            },
            ..ExecutionStats::default()
        },
        12,
    )
    .expect_err("capture counter must overflow");
    assert!(matches!(
        error,
        super::Error::StatisticsOverflow { case_index: 12 }
    ));
    assert_eq!(total, before);
}

struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        // The fuzz workflow always states its packets, its chosen destination,
        // and its permissive-live position; a budget-only request would skip
        // the destination gate.
        assert!(
            matches!(operation, Operation::Declared(_)),
            "fuzz submits a declared-packet request, got {operation:?}"
        );
        Ok(())
    }
}

struct RebuildingExecutor;

impl Executor for RebuildingExecutor {
    fn execute(
        &mut self,
        case: &ExecutionCase,
        _timeout: Duration,
    ) -> Result<Execution, BoundaryError> {
        let sent = crate::evidence::test_sent_packet(case.packet.clone());
        Ok(Execution {
            permit: case.permit,
            stats: ExecutionStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(sent.bytes_sent()).unwrap(),
                ..ExecutionStats::default()
            },
            sent,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        })
    }
}

#[derive(Default)]
struct CountingExecutor {
    executions: usize,
}

impl Executor for CountingExecutor {
    fn execute(
        &mut self,
        case: &ExecutionCase,
        _timeout: Duration,
    ) -> Result<Execution, BoundaryError> {
        self.executions += 1;
        let mut executor = RebuildingExecutor;
        executor.execute(case, Duration::ZERO)
    }
}

struct RouteMaterializingExecutor {
    registry: Arc<packetcraftr_core::registry::Registry>,
}

impl Executor for RouteMaterializingExecutor {
    fn execute(
        &mut self,
        case: &ExecutionCase,
        _timeout: Duration,
    ) -> Result<Execution, BoundaryError> {
        let sent = route_materialized_sent_packet(&self.registry, case.packet.clone());
        Ok(Execution {
            permit: case.permit,
            stats: ExecutionStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(sent.bytes_sent()).unwrap(),
                ..ExecutionStats::default()
            },
            sent,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        })
    }
}

struct SubstitutingFuzzExecutor;

impl Executor for SubstitutingFuzzExecutor {
    fn execute(
        &mut self,
        _case: &ExecutionCase,
        _timeout: Duration,
    ) -> Result<Execution, BoundaryError> {
        let sent = crate::evidence::test_sent_packet(packet());
        Ok(Execution {
            permit: _case.permit,
            stats: ExecutionStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(sent.bytes_sent()).unwrap(),
                ..ExecutionStats::default()
            },
            sent,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        })
    }
}

fn packet() -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        })
        .push(Udp {
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"campaign")));
    packet
}

fn route_materialized_packet() -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"campaign")));
    packet
}

fn route_materialized_sent_packet(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    mut packet: Packet,
) -> crate::SentPacket {
    let route = route_materializing_route();
    crate::materialize::materialize_network_fields(&mut packet, &route.plan)
        .expect("route source should materialize");
    crate::materialize::materialize_link_structure(&mut packet, &route.plan)
        .expect("link structure should materialize");
    let built = Builder::new(Arc::clone(registry))
        .build(
            packet,
            crate::materialize::build_context(&route.plan),
            packetcraftr_core::build::Options::default(),
        )
        .expect("materialized sent packet should build");
    let report = Submission::start().complete(built.bytes.len(), built.bytes.clone());
    crate::SentPacket::try_new(built, route, report).expect("trusted materialized sent packet")
}

fn route_materializing_route() -> packetcraftr_netio::route::Materialized {
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_netio::{
        interface::Id as InterfaceId,
        link::{Capability, Mode},
        route::{Decision, Materialized, Plan},
    };

    let source = Ipv4Addr::new(192, 0, 2, 10);
    let destination = Ipv4Addr::new(198, 51, 100, 2);
    Materialized {
        plan: Plan {
            decision: Decision {
                interface: InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 1,
                },
                source_mac: None,
                selected_source: Some(IpAddr::V4(source)),
                preferred_source: None,
                next_hop: None,
                selection_reason: packetcraftr_netio::route::SelectionReason::Gateway,
                destination_scope: packetcraftr_netio::route::Scope::Global,
                mtu: u32::MAX,
                capability: Capability::Layer3,
                link_type: LinkType::RAW,
            },
            mode: Mode::Layer3,
            lookup_destination: Some(IpAddr::V4(destination)),
            final_destination: Some(IpAddr::V4(destination)),
            visited_destinations: vec![IpAddr::V4(destination)],
            packet_source: Some(IpAddr::V4(source)),
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: None,
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        },
        neighbor_resolution: None,
    }
}

#[test]
fn live_execution_uses_the_identical_packet_campaign() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        seed: 0x5eed,
        cases: 8,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let offline =
        packet_fuzz::run(&request, packet(), Arc::clone(&registry)).expect("offline campaign");
    let mut authorizer = AllowAll;
    let mut executor = RebuildingExecutor;
    let live = run(
        RunInput {
            request: &request,
            live: LiveOptions {
                timeout: Duration::from_millis(1),
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect("live campaign");

    assert_eq!(offline.cases.len(), live.cases.len());
    for (offline, live) in offline.cases.iter().zip(&live.cases) {
        assert_eq!(offline.index, live.prepared.index);
        assert_eq!(offline.seed, live.prepared.seed);
        assert_eq!(offline.mutation, live.prepared.mutation);
        assert_eq!(offline.shrink_values, live.prepared.shrink_values);
        assert_eq!(
            offline.built.as_ref().map(|built| built.bytes.as_ref()),
            live.prepared
                .built
                .as_ref()
                .map(|built| built.bytes.as_ref())
        );
    }
}

#[test]
fn live_fuzz_sink_failure_prevents_later_case_execution() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        cases: 3,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = AllowAll;
    let mut executor = CountingExecutor::default();
    let emitted = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = Arc::clone(&emitted);

    let error = run_with_events(
        RunInput {
            request: &request,
            live: LiveOptions {
                timeout: Duration::from_millis(1),
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
        &Runtime::default(),
        move |case| {
            observed.lock().unwrap().push(case.prepared.index);
            Err(BoundaryError::new(
                "induced live fuzz sink failure",
                packetcraftr_core::error::Classification::new(
                    "io.test_output",
                    packetcraftr_core::error::Kind::Io,
                    None,
                ),
                Vec::new(),
            ))
        },
    )
    .expect_err("the first case event must stop the campaign");

    assert!(matches!(error, super::Error::Output { .. }));
    assert_eq!(executor.executions, 1);
    assert_eq!(*emitted.lock().unwrap(), [0]);
}

#[test]
fn live_fuzz_accepts_route_materialized_case() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        cases: 1,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = AllowAll;
    let mut executor = RouteMaterializingExecutor {
        registry: Arc::clone(&registry),
    };
    let live = run(
        RunInput {
            request: &request,
            live: LiveOptions {
                timeout: Duration::from_millis(1),
                ..LiveOptions::default()
            },
            packet: route_materialized_packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect("route-materialized live fuzz case should be accepted");

    let built = live
        .cases
        .iter()
        .find_map(|case| case.prepared.built.as_ref())
        .expect("one built live fuzz case");
    let ipv4 = built
        .packet
        .layer(0)
        .and_then(|layer| layer.as_any().downcast_ref::<Ipv4>())
        .expect("materialized IPv4 layer");
    assert_eq!(ipv4.source, Ipv4Addr::new(192, 0, 2, 10));
}

#[test]
fn live_fuzz_rejects_substituted_authorized_case() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        cases: 1,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = AllowAll;
    let mut executor = SubstitutingFuzzExecutor;
    let error = run(
        RunInput {
            request: &request,
            live: LiveOptions {
                timeout: Duration::from_millis(1),
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("substituted sent evidence must be rejected");

    assert_eq!(error.classification().code, "internal.fuzz_evidence");
    assert!(error.to_string().contains("substituted bytes"));
}

struct DenyingAuthorizer {
    invocations: usize,
}

impl Authorizer for DenyingAuthorizer {
    fn authorize_operation(&mut self, _operation: Operation<'_>) -> Result<(), BoundaryError> {
        self.invocations += 1;
        Err(BoundaryError::from_error(
            crate::policy::Error::PublicDestination {
                destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            },
        ))
    }
}

#[test]
fn live_fuzz_consults_the_authorizer_exactly_once_before_any_execution() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        seed: 0x5eed,
        cases: 4,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = DenyingAuthorizer { invocations: 0 };
    let mut executor = CountingExecutor::default();

    let error = run(
        RunInput {
            request: &request,
            live: LiveOptions {
                destination: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("a denied campaign must not run");

    assert_eq!(authorizer.invocations, 1);
    assert_eq!(executor.executions, 0);
    assert_eq!(error.classification().code, "policy.public_destination");
}

#[test]
fn live_fuzz_authorizes_a_campaign_where_no_case_built() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let request = packet_fuzz::Request {
        seed: 0x5eed,
        cases: 4,
        strategies: vec![packet_fuzz::Strategy::Malformed],
        targets: vec!["1.length".parse().expect("derived length target")],
        ..packet_fuzz::Request::default()
    };
    let offline =
        packet_fuzz::run(&request, packet(), Arc::clone(&registry)).expect("offline campaign");
    assert!(
        offline.cases.iter().all(|case| case.built.is_none()),
        "the fixture must reject every case so the campaign declares no packets"
    );
    let mut authorizer = DenyingAuthorizer { invocations: 0 };
    let mut executor = CountingExecutor::default();

    let error = run(
        RunInput {
            request: &request,
            live: LiveOptions {
                destination: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))),
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("a campaign with nothing to send is still authorized");

    assert_eq!(authorizer.invocations, 1);
    assert_eq!(executor.executions, 0);
    assert_eq!(error.classification().code, "policy.public_destination");
}

/// A campaign that would put permissively built bytes on the wire needs two
/// independent approvals — the per-operation opt-in and the policy's standing
/// allowance — and the authorizer, not the workflow, is where both are
/// applied. Nothing may be transmitted before both pass.
#[test]
fn a_permissive_live_campaign_is_denied_by_the_authorizer_before_any_transmission() {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let permissive_build = packetcraftr_core::build::Options {
        mode: packetcraftr_core::build::Mode::Permissive,
        ..packetcraftr_core::build::Options::default()
    };
    let malformed = packet_fuzz::Request {
        seed: 0x5eed,
        cases: 4,
        strategies: vec![packet_fuzz::Strategy::Malformed],
        targets: vec!["1.length".parse().expect("derived length target")],
        build: permissive_build.clone(),
        ..packet_fuzz::Request::default()
    };
    let offline = packet_fuzz::run(&malformed, packet(), Arc::clone(&registry))
        .expect("permissive offline campaign");
    assert!(
        offline.cases.iter().any(|case| {
            case.built
                .as_ref()
                .is_some_and(|built| built.requires_live_opt_in)
        }),
        "the fixture must build at least one case that needs the live opt-in"
    );

    let permissive_policy = crate::policy::Policy {
        allow_permissive_packets: true,
        ..crate::policy::Policy::default()
    };
    let strict_policy = crate::policy::Policy::default();
    for (policy, allow_malformed_live, expected_code) in [
        (&permissive_policy, false, "policy.permissive_live_opt_in"),
        (&strict_policy, true, "policy.permissive_packet"),
        (&strict_policy, false, "policy.permissive_live_opt_in"),
    ] {
        let mut authorizer = crate::authorization::PolicyAuthorizer::for_packets(policy);
        let mut executor = CountingExecutor::default();

        let error = run(
            RunInput {
                request: &malformed,
                live: LiveOptions {
                    destination: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
                    allow_malformed_live,
                    ..LiveOptions::default()
                },
                packet: packet(),
                registry: Arc::clone(&registry),
            },
            &mut authorizer,
            &mut executor,
            &mut NoopClock,
        )
        .expect_err("a permissive live campaign without both approvals must be refused");

        assert_eq!(error.classification().code, expected_code);
        assert_eq!(
            executor.executions, 0,
            "nothing may be transmitted before both approvals pass"
        );
    }

    // The same gate approves when both are present: a permissively built
    // campaign whose cases still encode exactly runs to completion.
    let encodable = packet_fuzz::Request {
        seed: 0x5eed,
        cases: 4,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        build: permissive_build,
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = crate::authorization::PolicyAuthorizer::for_packets(&permissive_policy);
    let mut executor = CountingExecutor::default();
    let report = run(
        RunInput {
            request: &encodable,
            live: LiveOptions {
                destination: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
                allow_malformed_live: true,
                ..LiveOptions::default()
            },
            packet: packet(),
            registry,
        },
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect("both approvals present");
    assert_eq!(executor.executions, 4);
    assert_eq!(report.cases.len(), 4);
}
