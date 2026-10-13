// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, UNIX_EPOCH},
};

use packetcraftr_core::{
    budget::Deadline,
    error::BoundaryError,
    packet::Packet,
    protocol::{
        network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
        transport::{Tcp, TcpOption},
    },
};

use super::{
    Collector, Error, Outcome, Probe, Request, engine,
    executor::{OsExecutor, Preparation},
    plan::PlannedProbe,
};
use crate::{
    Sink, Stats,
    execution::Executor,
    policy::{Authorizer, Operation},
    probe::{Batch, Evidence},
    target::{Authorized, ResolveTarget, ResolvedZone, SelectedAddress, Target},
    test_support::{NoopClock, RecordingClock, decoded_packet, sent_packet},
};

struct Approval {
    address: IpAddr,
    deny: bool,
}
impl Authorizer for Approval {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        assert!(operation.limits().packets() <= 32);
        if self.deny {
            Err(BoundaryError::execution_validation(
                "denied",
                "policy.test",
                "test",
            ))
        } else {
            Ok(())
        }
    }
}
impl ResolveTarget for Approval {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
        _: &Deadline,
    ) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.clone(),
            selected: vec![SelectedAddress {
                address: self.address,
                scope: if let Target::ScopedAddress(scoped) = target {
                    Some(ResolvedZone {
                        zone: scoped.zone().clone(),
                        interface: packetcraftr_netio::interface::Id {
                            name: scoped.zone().as_str().into(),
                            index: 1,
                        },
                    })
                } else {
                    None
                },
            }],
        })
    }
}

#[derive(Default)]
struct Fixture {
    executed: Vec<PlannedProbe>,
    prepared: bool,
    preparation: Preparation,
    preparation_clock: Option<RecordingClock>,
    silent: bool,
    conflict: bool,
    corrupt: bool,
    late: bool,
    timestamp_echo: Option<bool>,
    echo_payload: Option<bool>,
    closed_open: bool,
}
impl OsExecutor for Fixture {
    fn prepare(&mut self, _: &PlannedProbe, _: &Deadline) -> Result<Preparation, BoundaryError> {
        self.prepared = true;
        if let Some(clock) = &self.preparation_clock {
            clock.advance(self.preparation.stats.elapsed);
        }
        Ok(self.preparation.clone())
    }
}
impl Executor<Batch<PlannedProbe>> for Fixture {
    fn execute(&mut self, batch: &Batch<PlannedProbe>) -> Result<Evidence, BoundaryError> {
        let probe = batch.probes[0].clone();
        self.executed.push(probe.clone());
        let mut request = probe.packet();
        if let Some(ip) = request.get_mut::<Ipv4>() {
            ip.source = Ipv4Addr::new(192, 0, 2, 1);
        }
        if let Some(ip) = request.get_mut::<Ipv6>() {
            ip.source = "2001:db8::1".parse().unwrap();
        }
        let sent = sent_packet(request.clone());
        let bytes = sent.bytes_sent() as u64;
        let mut responses = Vec::new();
        if !self.silent && probe.kind.is_some() && probe.kind != Some(Probe::Echo) {
            let mut response = Packet::new();
            if let Some(ip) = request.get::<Ipv4>() {
                response.push(Ipv4 {
                    source: ip.destination,
                    destination: ip.source,
                    ..Ipv4::default()
                });
            }
            if let Some(ip) = request.get::<Ipv6>() {
                response.push(Ipv6 {
                    source: ip.destination,
                    destination: ip.source,
                    ..Ipv6::default()
                });
            }
            let mut tcp = Tcp {
                source_port: probe.port,
                destination_port: probe.source_port,
                sequence: 12345,
                acknowledgment: probe.identity.wrapping_add(1),
                flags: if probe.kind == Some(Probe::ClosedSyn) && !self.closed_open {
                    Tcp::RST | Tcp::ACK
                } else {
                    Tcp::SYN | Tcp::ACK
                },
                window: 4096,
                options: if probe.kind == Some(Probe::ClosedSyn) {
                    Vec::new()
                } else {
                    vec![TcpOption::Mss(1460)]
                },
                ..Tcp::default()
            };
            if probe.kind == Some(Probe::TimestampSyn)
                && let Some(corrupt) = self.timestamp_echo
            {
                tcp.options.extend([TcpOption::Nop, TcpOption::Nop]);
                tcp.options.push(TcpOption::Timestamps {
                    value: 56789,
                    echo_reply: probe.identity.wrapping_add(u32::from(corrupt)),
                });
            }
            if self.corrupt {
                tcp.acknowledgment = tcp.acknowledgment.wrapping_add(1);
            }
            response.push(tcp);
            let decoded = decoded_packet(
                response.clone(),
                UNIX_EPOCH + Duration::from_millis(1),
                sent_packet(response.clone()).wire_bytes(),
                Vec::new(),
            );
            responses.push(crate::exchange::Response {
                request_index: 0,
                response: decoded,
                latency: if self.late {
                    batch.timeout + Duration::from_millis(1)
                } else {
                    Duration::from_millis(1)
                },
            });
            if self.conflict {
                response.get_mut::<Tcp>().unwrap().window = 8192;
                responses.push(crate::exchange::Response {
                    request_index: 0,
                    response: decoded_packet(
                        response.clone(),
                        UNIX_EPOCH + Duration::from_millis(2),
                        sent_packet(response).wire_bytes(),
                        Vec::new(),
                    ),
                    latency: Duration::from_millis(2),
                });
            }
        }
        if probe.kind == Some(Probe::Echo)
            && let Some(corrupt) = self.echo_payload
        {
            let mut response = request.clone();
            if let Some(ip) = response.get_mut::<Ipv4>() {
                std::mem::swap(&mut ip.source, &mut ip.destination);
                let echo = response.get_mut::<Icmpv4>().unwrap();
                echo.icmp_type = 0;
                if corrupt {
                    let mut bytes = echo.body.to_vec();
                    bytes[7] ^= 1;
                    echo.body = bytes.into();
                }
            } else {
                let ip = response.get_mut::<Ipv6>().unwrap();
                std::mem::swap(&mut ip.source, &mut ip.destination);
                let echo = response.get_mut::<Icmpv6>().unwrap();
                echo.icmp_type = 129;
                if corrupt {
                    let mut bytes = echo.body.to_vec();
                    bytes[7] ^= 1;
                    echo.body = bytes.into();
                }
            }
            let built = sent_packet(response.clone());
            responses.push(crate::exchange::Response {
                request_index: 0,
                response: decoded_packet(
                    response,
                    UNIX_EPOCH + Duration::from_millis(1),
                    built.wire_bytes(),
                    Vec::new(),
                ),
                latency: Duration::from_millis(1),
            });
        }
        Ok(Evidence {
            permit: batch.permit,
            sent: vec![sent],
            responses,
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes,
                ..Stats::default()
            },
        })
    }
}

fn execute(
    address: IpAddr,
    fixture: &mut Fixture,
    denied: bool,
) -> Result<super::Aggregate, Error> {
    execute_target(Target::Address(address), fixture, denied)
}

fn execute_target(
    target: Target,
    fixture: &mut Fixture,
    denied: bool,
) -> Result<super::Aggregate, Error> {
    let mut request = Request::new(target, 80, 81, super::builtin_corpus().unwrap());
    request.attempts = 1;
    request.limits.max_probes = 7;
    request.timeout = Duration::from_millis(20);
    execute_request(&request, fixture, denied)
}

fn execute_request(
    request: &Request,
    fixture: &mut Fixture,
    denied: bool,
) -> Result<super::Aggregate, Error> {
    let target = &request.target;
    let address = match target {
        Target::Address(address) => *address,
        Target::ScopedAddress(scoped) => IpAddr::V6(scoped.address()),
        _ => unreachable!("numeric test target"),
    };
    let registry = packetcraftr_core::protocol::builtin::registry();
    let collector = Collector::default();
    let mut sink = collector.clone();
    let report = engine::run(
        request,
        &registry,
        &mut Deadline::new(Duration::from_secs(10)),
        &mut NoopClock,
        &mut Approval {
            address,
            deny: denied,
        },
        fixture,
        |event, _| sink.publish(event).map_err(Error::Output),
    )?;
    collector.finish(report)
}

#[test]
fn preparation_shares_retention_without_reducing_valid_exchange_ceilings() {
    use packetcraftr_core::frame::{Frame, LinkType};

    for (max_frames, max_bytes, retained_replies) in
        [(2, 4096, 1), (10, 128, 1), (1, 4096, 0), (10, 80, 0)]
    {
        let mut request = Request::new(
            Target::Address("192.0.2.2".parse().unwrap()),
            80,
            81,
            super::builtin_corpus().unwrap(),
        );
        request.attempts = 1;
        request.limits.evidence.max_frames = max_frames;
        request.limits.evidence.max_bytes = max_bytes;
        request.limits.evidence.max_undecoded = max_frames;
        request.collection.capture.max_frames = max_frames;
        request.collection.capture.max_bytes = max_bytes;
        request.collection.capture.snap_length = max_bytes.min(super::MAX_FRAME_BYTES);
        request.collection.max_responses = max_frames;
        request.collection.max_unmatched_frames = max_frames;
        let mut fixture = Fixture {
            // Zero remaining retention still accepts a valid single-frame exchange.
            conflict: max_frames > 1 && max_bytes > 80,
            preparation: Preparation {
                captured: vec![Frame::without_timestamp(LinkType(1), vec![0; 80]).unwrap()],
                ..Default::default()
            },
            ..Default::default()
        };
        let aggregate = execute_request(&request, &mut fixture, false).unwrap();
        assert_eq!(
            aggregate.report.identification.outcome,
            Outcome::Inconclusive
        );
        assert!(!aggregate.report.complete);
        assert_eq!(aggregate.report.observations.len(), retained_replies);
        assert!(aggregate.report.retained_evidence_bytes <= max_bytes);
        let open = fixture.executed.first().unwrap();
        let cleanup = fixture
            .executed
            .iter()
            .find(|probe| probe.kind.is_none())
            .unwrap();
        assert_eq!(cleanup.port, open.port);
        assert_eq!(cleanup.identity, open.identity.wrapping_add(1));
        assert_eq!(cleanup.cleanup_ack, 12346);
    }
}

#[test]
fn layer3_small_snapshots_do_not_require_neighbor_capture_minima() {
    let (client, providers) = crate::test_support::fake_client();
    let mut request = Request::new(
        Target::Address("192.0.2.2".parse().unwrap()),
        80,
        81,
        super::builtin_corpus().unwrap(),
    );
    request.attempts = 1;
    request.timeout = Duration::from_secs(1);
    request.route.link_mode = packetcraftr_netio::link::Mode::Layer3;
    request.collection.capture.snap_length = 64;
    let report = client
        .with_clock(NoopClock)
        .identify_os(request, Collector::default())
        .unwrap();
    assert!(matches!(
        report.identification.outcome,
        Outcome::Inconclusive
    ));
    assert_eq!(
        providers
            .calls()
            .iter()
            .filter(|call| matches!(call, crate::test_support::Call::Transmit(_)))
            .count(),
        2
    );
}

#[test]
fn preparation_pacing_ignores_pre_send_setup_and_respects_the_deadline() {
    for short_deadline in [false, true] {
        let mut request = Request::new(
            Target::Address("192.0.2.2".parse().unwrap()),
            80,
            81,
            super::builtin_corpus().unwrap(),
        );
        request.attempts = 1;
        request.probes_per_second = 1;
        let mut clock = RecordingClock::default();
        let mut deadline = clock.deadline(if short_deadline {
            Duration::from_millis(2100)
        } else {
            Duration::from_secs(30)
        });
        let mut fixture = Fixture {
            preparation_clock: Some(clock.clone()),
            preparation: Preparation {
                stats: Stats {
                    packets_attempted: 1,
                    packets_completed: 1,
                    bytes: 42,
                    // Setup can take longer than a rate interval before sending.
                    elapsed: Duration::from_secs(2),
                    ..Default::default()
                },
                request_bytes: Some(vec![0; 42].into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let result = engine::run(
            &request,
            &packetcraftr_core::protocol::builtin::registry(),
            &mut deadline,
            &mut clock,
            &mut Approval {
                address: "192.0.2.2".parse().unwrap(),
                deny: false,
            },
            &mut fixture,
            |_, _| Ok(()),
        );
        if short_deadline {
            assert!(matches!(result, Err(Error::Deadline(_))));
            assert!(clock.delays().is_empty());
            assert!(fixture.executed.is_empty());
        } else {
            result.unwrap();
            assert_eq!(clock.delays().first(), Some(&Duration::from_secs(1)));
            assert!(!fixture.executed.is_empty());
        }
    }
}

#[test]
fn dual_stack_collects_fingerprints_and_cleans_up_with_exact_sequence_relationships() {
    for address in [
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        IpAddr::V6(Ipv6Addr::from(0x20010db8000000000000000000000002_u128)),
    ] {
        let mut fixture = Fixture::default();
        let result = execute(address, &mut fixture, false).unwrap();
        assert_eq!(result.report.observations.len(), 3);
        assert_eq!(result.report.identification.outcome, Outcome::Unknown);
        assert_eq!(fixture.executed.len(), 6);
        for pair in fixture
            .executed
            .windows(2)
            .filter(|pair| pair[1].kind.is_none())
        {
            assert_eq!(pair[1].identity, pair[0].identity.wrapping_add(1));
            assert_eq!(pair[1].cleanup_ack, 12346);
        }
    }
}

#[test]
fn denied_or_invalid_request_precedes_preparation() {
    let mut fixture = Fixture::default();
    assert!(matches!(
        execute("192.0.2.2".parse().unwrap(), &mut fixture, true),
        Err(Error::Authorization(_))
    ));
    assert!(!fixture.prepared);
    assert!(fixture.executed.is_empty());
    let request = Request::new(
        Target::Hostname("example.test".parse().unwrap()),
        80,
        81,
        super::builtin_corpus().unwrap(),
    );
    assert!(request.validate().is_err());
}

#[test]
fn partial_conflicting_wrong_ack_and_late_evidence_are_inconclusive() {
    for mut fixture in [
        Fixture {
            silent: true,
            ..Default::default()
        },
        Fixture {
            conflict: true,
            ..Default::default()
        },
        Fixture {
            corrupt: true,
            ..Default::default()
        },
        Fixture {
            late: true,
            ..Default::default()
        },
    ] {
        let result = execute("192.0.2.2".parse().unwrap(), &mut fixture, false);
        if fixture.late {
            assert!(
                result.is_err(),
                "an executor claiming an out-of-window match violates its contract"
            );
        } else {
            assert_eq!(
                result.unwrap().report.identification.outcome,
                Outcome::Inconclusive
            );
        }
    }
}

#[test]
fn authored_wire_fields_are_verified() {
    let probe = PlannedProbe {
        sequence: 1,
        attempt: 1,
        address: "192.0.2.2".parse().unwrap(),
        interface: None,
        port: 80,
        source_port: 50000,
        identity: 99,
        kind: Some(Probe::TimestampSyn),
        cleanup_ack: 0,
    };
    let mut packet = probe.packet();
    assert!(probe.sent_matches(&packet));
    packet.get_mut::<Tcp>().unwrap().options.swap(0, 1);
    assert!(!probe.sent_matches(&packet));
}

#[test]
fn scope_is_preserved_for_every_probe_and_cleanup() {
    let target: Target = "fe80::2%fixture0".parse().unwrap();
    let mut fixture = Fixture::default();
    let result = execute_target(target.clone(), &mut fixture, false).unwrap();
    assert_eq!(result.report.target, target);
    assert!(fixture.executed.iter().all(|probe| {
        probe
            .interface
            .as_ref()
            .is_some_and(|interface| interface.name == "fixture0" && interface.index == 1)
    }));
}

#[test]
fn timestamp_and_echo_reflection_are_checked_before_qualification() {
    for address in ["192.0.2.2", "2001:db8::2"] {
        for corrupt in [false, true] {
            let mut fixture = Fixture {
                timestamp_echo: Some(corrupt),
                echo_payload: Some(corrupt),
                ..Fixture::default()
            };
            let result = execute(address.parse().unwrap(), &mut fixture, false).unwrap();
            assert_eq!(result.report.observations.len(), 4);
            assert_eq!(
                result.report.identification.outcome,
                if corrupt {
                    Outcome::Inconclusive
                } else {
                    Outcome::Unknown
                }
            );
        }
    }
}

#[test]
fn mistaken_closed_port_is_cleaned_up_before_refusing_additional_probes() {
    for address in ["192.0.2.2", "2001:db8::2"] {
        let mut fixture = Fixture {
            closed_open: true,
            ..Fixture::default()
        };
        let aggregate = execute(address.parse().unwrap(), &mut fixture, false).unwrap();
        assert_eq!(
            aggregate.report.identification.outcome,
            super::Outcome::Inconclusive
        );
        assert_eq!(fixture.executed.len(), 4);
        assert_eq!(fixture.executed[2].kind, Some(Probe::ClosedSyn));
        assert_eq!(fixture.executed[3].kind, None);
        assert_eq!(fixture.executed[3].port, 81);
        assert!(
            fixture
                .executed
                .iter()
                .all(|probe| !matches!(probe.kind, Some(Probe::TimestampSyn | Probe::Echo)))
        );
    }
}
