// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_core::build::Builder;
use packetcraftr_core::error::Classified;
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr_core::{Packet, layer::Raw};
use packetcraftr_netio::{capture::Statistics as CaptureStatistics, transmit::Submission};

use crate::clock::Clock;
use crate::{BoundaryError, Stats as ExecutionStats};

use super::execution::add_execution_stats;
use super::{Authorizer, Execution, ExecutionCase, Executor, LiveLimits, LiveOptions, Stats, run};

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
    fn authorize_operation(
        &mut self,
        _packets: &[Packet],
        _destination: Option<std::net::IpAddr>,
        _maximum_wire_bytes: u64,
        _requires_malformed_live: bool,
    ) -> Result<(), BoundaryError> {
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

#[derive(Default)]
struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
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
    let registry =
        Arc::new(packetcraftr_core::protocol::builtin::registry().expect("built-in registry"));
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
        &request,
        LiveOptions {
            timeout: Duration::from_millis(1),
            ..LiveOptions::default()
        },
        packet(),
        registry,
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect("live campaign");

    assert_eq!(offline.cases.len(), live.cases.len());
    for (offline, live) in offline.cases.iter().zip(&live.cases) {
        assert_eq!(offline.index, live.index);
        assert_eq!(offline.seed, live.seed);
        assert_eq!(offline.mutation, live.mutation);
        assert_eq!(offline.shrink_values, live.shrink_values);
        assert_eq!(
            offline.built.as_ref().map(|built| built.bytes.as_ref()),
            live.built.as_ref().map(|built| built.bytes.as_ref())
        );
    }
}

#[test]
fn live_fuzz_accepts_route_materialized_case() {
    let registry =
        Arc::new(packetcraftr_core::protocol::builtin::registry().expect("built-in registry"));
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
        &request,
        LiveOptions {
            timeout: Duration::from_millis(1),
            ..LiveOptions::default()
        },
        route_materialized_packet(),
        registry,
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect("route-materialized live fuzz case should be accepted");

    let built = live
        .cases
        .iter()
        .find_map(|case| case.built.as_ref())
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
    let registry =
        Arc::new(packetcraftr_core::protocol::builtin::registry().expect("built-in registry"));
    let request = packet_fuzz::Request {
        cases: 1,
        strategies: vec![packet_fuzz::Strategy::BitFlip],
        targets: vec!["2.bytes".parse().expect("raw field target")],
        ..packet_fuzz::Request::default()
    };
    let mut authorizer = AllowAll;
    let mut executor = SubstitutingFuzzExecutor;
    let error = run(
        &request,
        LiveOptions {
            timeout: Duration::from_millis(1),
            ..LiveOptions::default()
        },
        packet(),
        registry,
        &mut authorizer,
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("substituted sent evidence must be rejected");

    assert_eq!(error.classification().code, "internal.fuzz_evidence");
    assert!(error.to_string().contains("substituted bytes"));
}
