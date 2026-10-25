// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::{budget::Deadline, document::os_fingerprints as core, registry::Registry};

use super::{
    Collector, Error, Event, Match, Outcome, Probe, Report, Request,
    error::probe_error,
    evidence::Fingerprints,
    executor::{Native, OsExecutor},
    plan::PlannedProbe,
};
use crate::{
    Client, Sink,
    client::admission::{FamilyGate, admit_operation, wire_limits},
    clock::Clock,
    policy::Authorizer,
    probe::{
        Workflow,
        runner::{Batch, BatchEvidence, run_planned},
    },
    providers::{PacketProviders, TargetProviders},
    target::{Family, ResolveTarget},
};

impl<P: PacketProviders + TargetProviders, K: Clock> Client<P, K> {
    pub fn identify_os<S: Sink<Event, Ack = ()>>(
        &self,
        request: Request,
        sink: S,
    ) -> Result<Report, Error> {
        request.validate()?;
        let mut operation =
            crate::engine::operation::Operation::new(self, request.limits.max_duration);
        let mut deadline = operation.deadline(self, request.limits.max_duration);
        let publish = crate::engine::execution::publisher(
            &self.runtime,
            sink,
            Error::Deadline,
            Error::Output,
        )?;
        let mut clock = self.clock.clone();
        let mut authorizer = self.admission();
        operation.neighbors = self.neighbors.for_operation(1);
        operation.neighbor_mode = crate::engine::operation::NeighborMode::Cached;
        operation.packet_limit = request.limits.max_probes as u64;
        operation.byte_limit = request.limits.max_probes as u64 * super::MAX_WIRE_BYTES;
        let mut executor = Native {
            client: self,
            operation: &mut operation,
            preparation_timeout: request.timeout,
            send: crate::send::Options {
                plan: request.route.clone(),
                ..Default::default()
            },
            collection: request.collection.clone(),
        };
        run(
            &request,
            &self.registry,
            &mut deadline,
            &mut clock,
            &mut authorizer,
            &mut executor,
            publish,
        )
    }
}

pub(super) fn run<A, E, C, F>(
    request: &Request,
    registry: &Arc<Registry>,
    deadline: &mut Deadline,
    clock: &mut C,
    authorizer: &mut A,
    executor: &mut E,
    mut publish: F,
) -> Result<Report, Error>
where
    A: Authorizer + ResolveTarget,
    E: OsExecutor,
    C: Clock,
    F: FnMut(Event, &Deadline) -> Result<(), Error>,
{
    let started = clock.now();
    request.validate()?;
    deadline.enforce()?;
    let (selected, ()) = admit_operation(
        authorizer,
        deadline,
        probe_error,
        &request.target,
        FamilyGate::new(Family::Any, |_| {
            Error::Invalid("no numeric target selected".into())
        }),
        |_| Ok(()),
        |_| {
            Ok(wire_limits(
                request.limits.max_probes as u64,
                request.limits.max_probes as u64 * super::MAX_WIRE_BYTES,
            ))
        },
    )?;
    let target = selected
        .targets
        .first()
        .ok_or_else(|| Error::Invalid("no selected target".into()))?;
    let mut entropy = [0_u8; 8];
    getrandom::fill(&mut entropy).map_err(|source| Error::Execution {
        sequence: 0,
        source: super::executor::failure(source),
    })?;
    let base_identity = u32::from_be_bytes(entropy[..4].try_into().expect("four entropy bytes"));
    let source_port =
        49152 + u16::from_be_bytes(entropy[4..6].try_into().expect("two entropy bytes")) % 16384;
    let base = PlannedProbe {
        sequence: 1,
        attempt: 1,
        address: target.address,
        interface: target.interface().cloned(),
        port: request.open_port,
        source_port,
        identity: base_identity,
        kind: Some(Probe::OpenSyn),
        cleanup_ack: 0,
    };
    let preparation = executor.prepare(&base, deadline);
    // Expiry/cancellation observed during preparation outranks its timeout or
    // provider error, just as it does during a planned probe exchange.
    deadline.enforce()?;
    let preparation = preparation.map_err(|source| Error::Execution {
        sequence: 0,
        source,
    })?;
    // Resolution elapsed time includes pre-send setup. Without its send
    // timestamp, conservatively owe a full rate interval from completion;
    // run_planned accounts for the shared deadline before sleeping.
    let paced_after = (preparation.stats.packets_completed > 0).then(|| clock.now());
    let preparation_frames = preparation.captured.len();
    let preparation_bytes = preparation
        .captured
        .iter()
        .try_fold(0_usize, |sum, frame| sum.checked_add(frame.bytes().len()))
        .ok_or_else(|| Error::Invalid("neighbor evidence byte overflow".into()))?;
    if preparation_frames > request.limits.evidence.max_frames
        || preparation_bytes > request.limits.evidence.max_bytes
    {
        return Err(Error::Invalid(
            "neighbor capture exceeds operation evidence budget".into(),
        ));
    }
    let mut internal = Collector::default();
    let prep_stats = preparation.stats.clone();
    if preparation.request_bytes.is_some() || preparation_frames > 0 {
        let event = Event::Preparation(preparation);
        internal.publish(event.clone()).map_err(Error::Output)?;
        publish(event, deadline)?;
    }
    let mut limits = request.limits.evidence;
    limits.max_frames -= preparation_frames;
    limits.max_bytes -= preparation_bytes;
    let state = internal.clone();
    let mut evidence = BatchEvidence::new_with_retention_limits(
        Workflow::Os,
        probe_error,
        request.limits.evidence,
        limits,
        Fingerprints {
            registry,
            pending_cleanup: None,
        },
        |event: Event, deadline: &Deadline| {
            internal.publish(event.clone()).map_err(Error::Output)?;
            publish(event, deadline)
        },
    );
    let mut phase = 0_usize;
    let mut attempt = 1_u32;
    let mut sequence = 0_u64;
    let kinds = [
        Probe::OpenSyn,
        Probe::ClosedSyn,
        Probe::TimestampSyn,
        Probe::Echo,
    ];
    let mut planned = |evidence: &mut BatchEvidence<Fingerprints<'_>, _, _>,
                       _: std::time::Instant,
                       _: &Deadline| {
        if let Some(mut cleanup) = evidence.classifier_mut().pending_cleanup.take() {
            sequence += 1;
            cleanup.sequence = sequence;
            return Ok(Some(Batch {
                probes: vec![cleanup],
                timeout: request.timeout,
                sequence,
                permit: crate::evidence::ExecutionPermit::new(),
            }));
        }
        if phase >= kinds.len() {
            return Ok(None);
        }
        if phase == 2 && attempt == 1 {
            let observations = state.observations();
            for kind in [Probe::OpenSyn, Probe::ClosedSyn] {
                let flags = if kind == Probe::ClosedSyn { 0x14 } else { 0x12 };
                if !observations
                    .iter()
                    .any(|observation| observation.probe == kind)
                    || !observations
                        .iter()
                        .filter(|observation| observation.probe == kind)
                        .all(|observation| {
                            observation.suitable
                                && observation
                                    .tcp
                                    .as_ref()
                                    .is_some_and(|tcp| tcp.flags == flags)
                        })
                {
                    return Ok(None);
                }
            }
        }
        let kind = kinds[phase];
        sequence += 1;
        let probe = PlannedProbe {
            sequence,
            attempt,
            kind: Some(kind),
            port: if kind == Probe::ClosedSyn {
                request.closed_port
            } else {
                request.open_port
            },
            identity: base_identity.wrapping_add(sequence as u32),
            ..base.clone()
        };
        attempt += 1;
        if attempt > request.attempts {
            phase += 1;
            attempt = 1;
        }
        Ok(Some(Batch {
            probes: vec![probe],
            timeout: request.timeout,
            sequence,
            permit: crate::evidence::ExecutionPermit::new(),
        }))
    };
    let mut stats = run_planned(
        &mut planned,
        Some(request.probes_per_second),
        paced_after,
        deadline,
        clock,
        executor,
        &mut evidence,
    )?;
    let retained_evidence_bytes = evidence.retained_evidence_bytes() + preparation_bytes;
    drop(evidence);
    stats
        .checked_add_assign(&prep_stats)
        .map_err(|source| (probe_error)(sequence, crate::error::Failure::StatsOverflow(source)))?;
    let observations = state.observations();
    let complete = !state.incomplete();
    let identification = if complete {
        core::evaluate(&request.corpus, &observations)?
    } else {
        Match {
            outcome: Outcome::Inconclusive,
            reason: "fingerprint evidence retention was exhausted".into(),
            candidates: Vec::new(),
        }
    };
    deadline.enforce()?;
    stats.elapsed = stats
        .elapsed
        .max(clock.now().saturating_duration_since(started));
    Ok(Report {
        target: request.target.clone(),
        probe_set: core::PROBE_SET_V1,
        corpus: request.corpus.name.clone(),
        corpus_version: request.corpus.version.clone(),
        identification,
        observations,
        retained_evidence_bytes,
        complete,
        stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Stats,
        engine::execution::Executor,
        evidence::SentPacket,
        policy::{DestinationConstraint, Policy},
        probe::runner::Evidence,
    };
    use packetcraftr_core::{
        build::{Builder, BuiltPacket},
        decode::{DecodedPacket, Dissector},
        error::{BoundaryError, Classified, Coordinate},
        frame::{Frame, LinkType},
        packet::{MacAddress, Packet},
        protocol::{
            builtin,
            link::Ethernet,
            network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
            transport::{Tcp, TcpOption},
        },
    };
    use packetcraftr_netio::{
        capture, interface,
        link::{Capability, Mode},
        route::{Decision, Scope, SelectionReason},
        transmit,
    };
    use std::{
        convert::Infallible,
        net::IpAddr,
        sync::Mutex,
        time::{Duration, Instant, UNIX_EPOCH},
    };

    #[derive(Clone)]
    struct TestClock(Arc<Mutex<Instant>>);

    impl Clock for TestClock {
        type Error = Infallible;

        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }

        fn sleep(&self, delay: Duration, _: &Deadline) -> Result<(), Self::Error> {
            *self.0.lock().unwrap() += delay;
            Ok(())
        }
    }

    struct NumericOnly;

    impl crate::target::Resolver for NumericOnly {
        fn resolve(
            &self,
            _: &crate::target::Hostname,
            _: usize,
        ) -> Result<Vec<IpAddr>, crate::target::Error> {
            panic!("numeric OS targets must not resolve hostnames")
        }
    }

    fn corpus(signatures: Vec<core::Signature>) -> Arc<core::Corpus> {
        Arc::new(core::Corpus {
            schema: core::SCHEMA_V1.into(),
            probe_set: core::PROBE_SET_V1.into(),
            name: "controlled-corpus".into(),
            version: "supplied-version".into(),
            maintainer: "test fixture".into(),
            signatures,
        })
    }

    fn signature(v6: bool, window: u16) -> core::Signature {
        core::Signature {
            id: "controlled-stack".into(),
            family: core::Family::Linux,
            address_family: if v6 {
                core::AddressFamily::Ipv6
            } else {
                core::AddressFamily::Ipv4
            },
            reference: "supplied reply fixture".into(),
            predicates: [
                (Probe::OpenSyn, Tcp::SYN | Tcp::ACK),
                (Probe::ClosedSyn, Tcp::RST | Tcp::ACK),
                (Probe::TimestampSyn, Tcp::SYN | Tcp::ACK),
            ]
            .into_iter()
            .flat_map(|(probe, flags)| {
                [
                    core::Predicate {
                        probe,
                        test: core::Test::Flags(flags),
                    },
                    core::Predicate {
                        probe,
                        test: core::Test::Window(window),
                    },
                ]
            })
            .collect(),
        }
    }

    fn request(v6: bool) -> Request {
        let mut request = Request::new(
            crate::target::Target::Address(target(v6)),
            443,
            80,
            corpus(Vec::new()),
        );
        request.attempts = 2;
        request.timeout = Duration::from_millis(100);
        request.probes_per_second = 10;
        request.route.link_mode = Mode::Layer3;
        request
    }

    fn target(v6: bool) -> IpAddr {
        if v6 { "fd00::9" } else { "10.0.0.9" }.parse().unwrap()
    }

    fn source(v6: bool) -> IpAddr {
        if v6 { "fd00::2" } else { "10.0.0.2" }.parse().unwrap()
    }

    const SOURCE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 2]);
    const TARGET_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 9]);

    fn materialized(v6: bool, mode: Mode) -> crate::route::Materialized {
        let layer2 = mode == Mode::Layer2;
        crate::route::Materialized {
            plan: crate::route::Plan {
                decision: Decision {
                    interface: interface::Id {
                        index: 1,
                        name: "controlled0".into(),
                    },
                    source_mac: layer2.then_some(SOURCE_MAC),
                    selected_source: Some(source(v6)),
                    preferred_source: None,
                    next_hop: None,
                    selection_reason: SelectionReason::OnLink,
                    destination_scope: Scope::Private,
                    mtu: 1500,
                    capability: Capability::Layer2AndLayer3,
                    link_type: if layer2 {
                        LinkType::ETHERNET
                    } else {
                        LinkType::RAW
                    },
                },
                mode,
                lookup_destination: Some(target(v6)),
                final_destination: Some(target(v6)),
                visited_destinations: Vec::new(),
                packet_source: Some(source(v6)),
                neighbor_source: layer2.then_some(source(v6)),
                neighbor_target: layer2.then_some(target(v6)),
                destination_mac: layer2.then_some(TARGET_MAC),
                source_mac: layer2.then_some(SOURCE_MAC),
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: layer2,
            },
            neighbor_resolution: None,
        }
    }

    fn build(mut packet: Packet) -> BuiltPacket {
        if let Some(ip) = packet.get_mut::<Ipv4>()
            && ip.source.is_unspecified()
        {
            ip.source = "10.0.0.2".parse().unwrap();
        }
        if let Some(ip) = packet.get_mut::<Ipv6>()
            && ip.source.is_unspecified()
        {
            ip.source = "fd00::2".parse().unwrap();
        }
        Builder::new(builtin::registry())
            .build(packet, Default::default(), Default::default())
            .unwrap()
    }

    fn decoded(packet: Packet) -> DecodedPacket {
        let link_type = if packet.get::<Ethernet>().is_some() {
            LinkType::ETHERNET
        } else {
            LinkType::RAW
        };
        let built = build(packet);
        Dissector::new(builtin::registry())
            .decode(
                Frame::new(UNIX_EPOCH, link_type, built.bytes).unwrap(),
                Default::default(),
            )
            .unwrap()
    }

    // ARP fields and Ethernet padding, RFC 826/RFC 894, checked 2026-10-25.
    // https://www.rfc-editor.org/rfc/rfc826.html https://www.rfc-editor.org/rfc/rfc894.html
    // EtherTypes https://www.iana.org/assignments/ieee-802-numbers, checked 2026-10-25.
    fn arp_preparation() -> (Frame, Frame) {
        let request = [
            &[0xff; 6][..],
            &SOURCE_MAC.0,
            &[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 1],
            &SOURCE_MAC.0,
            &[10, 0, 0, 2],
            &[0; 6],
            &[10, 0, 0, 9],
            &[0; 18],
        ]
        .concat();
        let reply = [
            &SOURCE_MAC.0[..],
            &TARGET_MAC.0,
            &[0x08, 0x06, 0, 1, 0x08, 0, 6, 4, 0, 2],
            &TARGET_MAC.0,
            &[10, 0, 0, 9],
            &SOURCE_MAC.0,
            &[10, 0, 0, 2],
        ]
        .concat();
        let reply = [reply.as_slice(), vec![0; 256 - reply.len()].as_slice()].concat();
        (
            Frame::new(UNIX_EPOCH, LinkType::ETHERNET, request).unwrap(),
            Frame::new(UNIX_EPOCH, LinkType::ETHERNET, reply).unwrap(),
        )
    }

    #[derive(Clone, Copy)]
    enum Replies {
        Complete,
        MissingOpen,
        WrongClosedFlags,
        WrongTimestampEcho,
        WrongEchoBody,
        AlteredSent,
        AlteredClosed,
        Prepared,
    }

    struct Lab {
        clock: TestClock,
        mode: Replies,
        transmitted: Vec<(Instant, Frame)>,
        requested_tcp_sources: Vec<u16>,
        refused_request: Option<(u64, u16)>,
        captured: Vec<Frame>,
    }

    impl Lab {
        fn mode(&self) -> Mode {
            if matches!(self.mode, Replies::Prepared) {
                Mode::Layer2
            } else {
                Mode::Layer3
            }
        }

        // TCP acknowledgements and echo replies, RFC 9293, RFC 792 and RFC 4443, checked 2026-10-25.
        // https://www.rfc-editor.org/rfc/rfc9293 https://www.rfc-editor.org/rfc/rfc792 https://www.rfc-editor.org/rfc/rfc4443
        fn response(&self, sent: &Packet) -> Option<DecodedPacket> {
            let v6 = sent.get::<Ipv6>().is_some();
            let mut packet = Packet::new();
            if v6 {
                packet.push(Ipv6 {
                    source: target(true).to_string().parse().unwrap(),
                    destination: source(true).to_string().parse().unwrap(),
                    hop_limit: 51,
                    ..Default::default()
                });
            } else {
                packet.push(Ipv4 {
                    source: target(false).to_string().parse().unwrap(),
                    destination: source(false).to_string().parse().unwrap(),
                    ttl: 51,
                    identification: 0x2222,
                    dont_fragment: true,
                    ..Default::default()
                });
            }
            if let Some(tcp) = sent.get::<Tcp>() {
                if tcp.flags & Tcp::RST != 0
                    || (tcp.destination_port == 443 && matches!(self.mode, Replies::MissingOpen))
                {
                    return None;
                }
                let closed = tcp.destination_port == 80;
                // MSS/window-scale negotiation uses SYN segments, checked 2026-10-25.
                // https://www.rfc-editor.org/rfc/rfc9293.html#section-3.2
                // https://www.rfc-editor.org/rfc/rfc7323.html#section-2
                let mut options = if closed {
                    Vec::new()
                } else {
                    vec![
                        TcpOption::Mss(1200),
                        TcpOption::WindowScale(5),
                        TcpOption::SackPermitted,
                    ]
                };
                if let Some(value) = tcp.options.iter().find_map(|option| match option {
                    TcpOption::Timestamps { value, .. } => Some(*value),
                    _ => None,
                }) {
                    options.push(TcpOption::Timestamps {
                        value: 0x11223344,
                        echo_reply: if matches!(self.mode, Replies::WrongTimestampEcho) {
                            value.wrapping_add(1)
                        } else {
                            value
                        },
                    });
                }
                packet.push(Tcp {
                    source_port: tcp.destination_port,
                    destination_port: tcp.source_port,
                    sequence: if closed { 0x02030405 } else { 0x01020304 },
                    acknowledgment: tcp.sequence.wrapping_add(1),
                    flags: if closed && !matches!(self.mode, Replies::WrongClosedFlags) {
                        Tcp::RST | Tcp::ACK
                    } else {
                        Tcp::SYN | Tcp::ACK
                    },
                    window: 4096,
                    options,
                    ..Default::default()
                });
            } else {
                let body = sent
                    .get::<Icmpv4>()
                    .map(|icmp| icmp.body.clone())
                    .or_else(|| sent.get::<Icmpv6>().map(|icmp| icmp.body.clone()))
                    .unwrap();
                let body = if matches!(self.mode, Replies::WrongEchoBody) {
                    [&body[..body.len() - 1], &[body[body.len() - 1] ^ 1]]
                        .concat()
                        .into()
                } else {
                    body
                };
                if v6 {
                    packet.push(Icmpv6 {
                        icmp_type: 129,
                        code: 0,
                        body,
                        ..Default::default()
                    });
                } else {
                    packet.push(Icmpv4 {
                        icmp_type: 0,
                        code: 0,
                        body,
                        ..Default::default()
                    });
                }
            }
            if self.mode() == Mode::Layer2 {
                packet
                    .insert(
                        0,
                        Ethernet {
                            source: TARGET_MAC.0,
                            destination: SOURCE_MAC.0,
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            Some(decoded(packet))
        }
    }

    impl OsExecutor for Lab {
        fn prepare(
            &mut self,
            _: &PlannedProbe,
            _: &Deadline,
        ) -> Result<super::super::Preparation, BoundaryError> {
            if !matches!(self.mode, Replies::Prepared) {
                return Ok(Default::default());
            }
            let (sent, received) = arp_preparation();
            let stats = Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: sent.bytes().len() as u64,
                capture: capture::Stats {
                    received_frames: 1,
                    received_bytes: received.bytes().len() as u64,
                    ..Default::default()
                },
                ..Default::default()
            };
            let request_bytes = Some(sent.bytes().clone());
            self.transmitted.push((self.clock.now(), sent));
            self.captured.push(received.clone());
            Ok(super::super::Preparation {
                stats,
                captured: vec![received],
                request_bytes,
                interface: Some(interface::Id {
                    index: 1,
                    name: "controlled0".into(),
                }),
                target: Some(target(false)),
            })
        }
    }

    impl Executor<Batch<PlannedProbe>> for Lab {
        fn execute(&mut self, batch: &Batch<PlannedProbe>) -> Result<Evidence, BoundaryError> {
            let mut sent = Vec::new();
            let mut responses = Vec::new();
            for (index, probe) in batch.probes.iter().enumerate() {
                if probe.kind != Some(Probe::Echo) {
                    self.requested_tcp_sources.push(probe.source_port);
                }
                let mut packet = probe.packet();
                if self.mode() == Mode::Layer2 {
                    packet
                        .insert(
                            0,
                            Ethernet {
                                source: SOURCE_MAC.0,
                                destination: TARGET_MAC.0,
                                ..Default::default()
                            },
                        )
                        .unwrap();
                }
                if (matches!(self.mode, Replies::AlteredSent)
                    || matches!(self.mode, Replies::AlteredClosed) && probe.port == 80)
                    && let Some(tcp) = packet.get_mut::<Tcp>()
                {
                    self.refused_request = Some((probe.sequence, probe.port));
                    tcp.destination_port = tcp.destination_port.wrapping_add(1);
                }
                let built = build(packet);
                if let Some(response) = self.response(&built.packet) {
                    self.captured.push(response.frame.clone());
                    responses.push(crate::exchange::Response {
                        request_index: index,
                        response,
                        latency: Duration::from_millis(2),
                    });
                }
                let report = transmit::Report::committed(built.bytes.len(), built.bytes.clone());
                let current = SentPacket::try_new(
                    built,
                    materialized(probe.address.is_ipv6(), self.mode()),
                    report,
                )
                .unwrap();
                self.transmitted
                    .push((self.clock.now(), current.frame().clone()));
                sent.push(current);
            }
            let stats = Stats {
                packets_attempted: sent.len() as u64,
                packets_completed: sent.len() as u64,
                bytes: sent.iter().map(|packet| packet.bytes_sent() as u64).sum(),
                capture: capture::Stats {
                    received_frames: responses.len() as u64,
                    received_bytes: responses
                        .iter()
                        .map(|response| response.response.frame.bytes().len() as u64)
                        .sum(),
                    ..Default::default()
                },
                ..Default::default()
            };
            Ok(Evidence {
                observation_quality: Some(
                    packetcraftr_netio::capture::ObservationQuality::NoReportedLoss,
                ),
                permit: batch.permit,
                sent,
                responses,
                unsolicited: Vec::new(),
                undecoded: Vec::new(),
                diagnostics: Vec::new(),
                stats,
            })
        }
    }

    fn execute(request: &Request, mode: Replies) -> (Result<super::super::Aggregate, Error>, Lab) {
        let clock = TestClock(Arc::new(Mutex::new(Instant::now())));
        let control = clock.clone();
        let mut deadline =
            Deadline::with_time_source(request.limits.max_duration, move || control.now());
        let mut lab = Lab {
            clock: clock.clone(),
            mode,
            transmitted: Vec::new(),
            requested_tcp_sources: Vec::new(),
            refused_request: None,
            captured: Vec::new(),
        };
        let policy = Policy {
            allowed_destinations: vec![DestinationConstraint::Exact(
                request.target.to_string().parse().unwrap(),
            )],
            ..Default::default()
        };
        let mut authorizer = crate::client::admission::Admission::new(&policy, &NumericOnly);
        let mut collector = Collector::default();
        let result = run(
            request,
            &builtin::registry(),
            &mut deadline,
            &mut clock.clone(),
            &mut authorizer,
            &mut lab,
            |event, _| collector.publish(event).map_err(Error::Output),
        )
        .and_then(|report| collector.finish(report));
        (result, lab)
    }

    fn packets(events: &[Event]) -> Vec<&super::super::ProbeEvidence> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Probe(probe) => Some(probe),
                _ => None,
            })
            .collect()
    }

    fn packet(frame: &Frame) -> Packet {
        Dissector::new(builtin::registry())
            .decode(frame.clone(), Default::default())
            .unwrap()
            .packet
    }

    fn retention_request(max_frames: usize, max_bytes: usize) -> Request {
        let mut request = request(false);
        request.route.link_mode = Mode::Layer2;
        request.limits.evidence = crate::evidence::Limits {
            max_frames,
            max_bytes,
            max_undecoded: 1,
        };
        request.collection.capture = capture::Limits {
            max_frames: 1,
            max_bytes: 256,
            snap_length: 256,
            overflow_policy: capture::OverflowPolicy::Fail,
        };
        request.collection.max_responses = 1;
        request.collection.max_unmatched_frames = 1;
        request
    }

    #[test]
    fn complete_probe_set_publishes_wire_fields_observations_and_cleanup() {
        for v6 in [false, true] {
            let mut request = request(v6);
            request.corpus = corpus(vec![signature(v6, 4096)]);
            let (aggregate, lab) = execute(&request, Replies::Complete);
            let super::super::Aggregate { report, events } = aggregate.unwrap();
            assert!(report.complete);
            assert_eq!(report.target, request.target);
            assert_eq!(report.corpus, request.corpus.name);
            assert_eq!(report.corpus_version, request.corpus.version);
            assert_eq!(report.probe_set, request.corpus.probe_set);
            assert_eq!(report.identification.outcome, Outcome::Matched);
            let [candidate] = report.identification.candidates.as_slice() else {
                panic!("supplied replies must identify the controlled signature")
            };
            assert_eq!(candidate.signature, "controlled-stack");
            assert_eq!(candidate.family, core::Family::Linux);
            assert_eq!(candidate.corpus, request.corpus.name);
            assert_eq!(candidate.corpus_version, request.corpus.version);
            assert_eq!(candidate.reference, "supplied reply fixture");
            let records = packets(&events);
            assert_eq!(report.stats.packets_completed, records.len() as u64);
            assert_eq!(
                report.stats.bytes,
                lab.transmitted
                    .iter()
                    .map(|(_, frame)| frame.bytes().len() as u64)
                    .sum::<u64>()
            );
            assert!(
                records
                    .windows(2)
                    .all(|pair| pair[0].sequence < pair[1].sequence)
            );
            for kind in [
                Probe::OpenSyn,
                Probe::ClosedSyn,
                Probe::TimestampSyn,
                Probe::Echo,
            ] {
                assert_eq!(
                    records
                        .iter()
                        .filter(|record| record.probe == Some(kind))
                        .map(|record| record.attempt)
                        .collect::<Vec<_>>(),
                    (1..=request.attempts).collect::<Vec<_>>()
                );
                assert_eq!(
                    report
                        .observations
                        .iter()
                        .filter(|observation| observation.probe == kind)
                        .count(),
                    request.attempts as usize
                );
            }
            for observation in &report.observations {
                assert!(observation.suitable);
                assert_eq!(observation.observed_hop_limit, 51);
                if let Some(tcp) = &observation.tcp {
                    assert_eq!(
                        tcp.flags,
                        if observation.probe == Probe::ClosedSyn {
                            Tcp::RST | Tcp::ACK
                        } else {
                            Tcp::SYN | Tcp::ACK
                        }
                    );
                    assert_eq!(tcp.window, 4096);
                    if observation.probe == Probe::ClosedSyn {
                        assert_eq!(tcp.mss, None);
                        assert_eq!(tcp.window_scale, None);
                        assert!(!tcp.sack_permitted);
                    } else {
                        assert_eq!(tcp.mss, Some(1200));
                        assert_eq!(tcp.window_scale, Some(5));
                        assert!(tcp.sack_permitted);
                    }
                }
            }
            let mut syn_acks = Vec::new();
            let mut cleanups = Vec::new();
            let mut ports = Vec::new();
            let mut probe_identities = Vec::new();
            for record in &records {
                let sent = packet(&record.sent);
                if let Some(ip) = sent.get::<Ipv4>() {
                    assert_eq!(IpAddr::V4(ip.destination), target(false));
                    assert_eq!(ip.ttl, 64);
                    assert!(ip.dont_fragment);
                    assert_ne!(ip.identification, 0);
                } else {
                    let ip = sent.get::<Ipv6>().unwrap();
                    assert_eq!(IpAddr::V6(ip.destination), target(true));
                    assert_eq!(ip.hop_limit, 64);
                }
                if let Some(tcp) = sent.get::<Tcp>() {
                    assert_ne!(tcp.source_port, 0);
                    ports.push(tcp.source_port);
                    assert_eq!(
                        tcp.destination_port,
                        if record.probe == Some(Probe::ClosedSyn) {
                            80
                        } else {
                            443
                        }
                    );
                    if record.probe.is_none() {
                        assert_ne!(tcp.flags & Tcp::RST, 0);
                        assert_eq!(tcp.flags & Tcp::SYN, 0);
                        cleanups.push(tcp.clone());
                    } else {
                        probe_identities.push(tcp.sequence);
                        assert_eq!(record.latency, Some(Duration::from_millis(2)));
                        assert!(record.observation.is_some());
                        assert_eq!(tcp.flags, Tcp::SYN);
                        assert_eq!(tcp.window, 65535);
                        if record.probe != Some(Probe::ClosedSyn) {
                            assert!(tcp.options.contains(&TcpOption::Mss(1460)));
                            assert!(tcp.options.contains(&TcpOption::SackPermitted));
                            assert!(tcp.options.contains(&TcpOption::WindowScale(7)));
                        }
                        if record.probe == Some(Probe::TimestampSyn) {
                            assert!(tcp.options.iter().any(|option| matches!(option, TcpOption::Timestamps { value, echo_reply: 0 } if *value == tcp.sequence)));
                        }
                    }
                    if let Some(response) = &record.response {
                        let response = packet(response);
                        if let Some(tcp) = response.get::<Tcp>()
                            && tcp.flags == Tcp::SYN | Tcp::ACK
                        {
                            syn_acks.push(tcp.clone());
                        }
                    }
                } else if v6 {
                    // RFC 4443 section 4.1, checked 2026-10-25.
                    // https://www.rfc-editor.org/rfc/rfc4443.html#section-4.1
                    let icmp = sent.get::<Icmpv6>().unwrap();
                    assert_eq!((icmp.icmp_type, icmp.code), (128, 0));
                    assert!(icmp.body.len() >= 8);
                } else {
                    // RFC 792 echo message format, checked 2026-10-25.
                    // https://www.rfc-editor.org/rfc/rfc792.html
                    let icmp = sent.get::<Icmpv4>().unwrap();
                    assert_eq!((icmp.icmp_type, icmp.code), (8, 0));
                    assert!(icmp.body.len() >= 8);
                }
            }
            assert!(ports.iter().all(|port| *port == ports[0]));
            assert_eq!(ports, lab.requested_tcp_sources);
            assert_eq!(
                probe_identities
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                probe_identities.len()
            );
            assert_eq!(cleanups.len(), syn_acks.len());
            // RFC 9293 reset generation, checked 2026-10-25.
            // https://www.rfc-editor.org/rfc/rfc9293.html#section-3.5.2
            for response in syn_acks {
                assert!(
                    cleanups
                        .iter()
                        .any(|cleanup| cleanup.sequence == response.acknowledgment
                            && (cleanup.flags & Tcp::ACK == 0
                                || cleanup.acknowledgment == response.sequence.wrapping_add(1)))
                );
            }
            assert!(
                lab.transmitted
                    .windows(2)
                    .all(|pair| pair[1].0.duration_since(pair[0].0) >= Duration::from_millis(100))
            );
            let mut unmatched = request.clone();
            unmatched.corpus = corpus(vec![signature(v6, 4097)]);
            let (aggregate, _) = execute(&unmatched, Replies::Complete);
            let report = aggregate.unwrap().report;
            assert!(report.complete);
            assert_eq!(report.identification.outcome, Outcome::Unknown);
            assert!(report.identification.candidates.is_empty());
        }
    }

    #[test]
    fn preparation_and_responses_share_frame_and_byte_retention_limits() {
        let (full, _) = execute(&retention_request(16, 4096), Replies::Prepared);
        let full = full.unwrap();
        assert!(full.report.complete);
        let response_bytes = packets(&full.events)
            .iter()
            .find_map(|probe| probe.response.as_ref())
            .unwrap()
            .bytes()
            .len();
        let (arp_request, arp_reply) = arp_preparation();
        let preparation_bytes = arp_reply.bytes().len();
        for (max_frames, max_bytes, keep_response) in [
            (2, 4096, true),
            (16, preparation_bytes + response_bytes, true),
            (1, 4096, false),
            (16, preparation_bytes, false),
        ] {
            let request = retention_request(max_frames, max_bytes);
            let (aggregate, lab) = execute(&request, Replies::Prepared);
            let super::super::Aggregate { report, events } = aggregate.unwrap();
            assert!(!report.complete);
            assert_eq!(report.identification.outcome, Outcome::Inconclusive);
            let preparations = events
                .iter()
                .filter_map(|event| match event {
                    Event::Preparation(preparation) => Some(preparation),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let [preparation] = preparations.as_slice() else {
                panic!("neighbor preparation must be published once")
            };
            assert_eq!(
                preparation.request_bytes.as_ref().unwrap(),
                arp_request.bytes()
            );
            assert_eq!(preparation.target, Some(target(false)));
            assert_eq!(preparation.interface.as_ref().unwrap().name, "controlled0");
            let [retained_neighbor] = preparation.captured.as_slice() else {
                panic!("neighbor answer must remain in preparation evidence")
            };
            assert_eq!(retained_neighbor.bytes(), arp_reply.bytes());
            assert_eq!(retained_neighbor.link_type, LinkType::ETHERNET);
            let records = packets(&events);
            let retained = records
                .iter()
                .filter_map(|probe| probe.response.as_ref())
                .collect::<Vec<_>>();
            if keep_response {
                let [response] = retained.as_slice() else {
                    panic!("the shared limit must retain one response after preparation")
                };
                let supplied_response = lab
                    .captured
                    .iter()
                    .find(|frame| packet(frame).get::<Tcp>().is_some())
                    .unwrap();
                assert_eq!(response.bytes(), supplied_response.bytes());
                assert_eq!(response.link_type, supplied_response.link_type);
            } else {
                assert!(retained.is_empty());
            }
            assert!(
                records
                    .iter()
                    .any(|probe| probe.latency.is_some() && probe.response.is_none())
            );
            assert_eq!(
                report.retained_evidence_bytes,
                preparation_bytes + if keep_response { response_bytes } else { 0 }
            );
            assert_eq!(report.stats.packets_completed, lab.transmitted.len() as u64);
            assert_eq!(
                report.stats.bytes,
                lab.transmitted
                    .iter()
                    .map(|(_, frame)| frame.bytes().len() as u64)
                    .sum::<u64>()
            );
            assert_eq!(
                report.stats.capture.received_frames,
                lab.captured.len() as u64
            );
            assert_eq!(
                report.stats.capture.received_bytes,
                lab.captured
                    .iter()
                    .map(|frame| frame.bytes().len() as u64)
                    .sum::<u64>()
            );
            assert!(
                lab.transmitted
                    .windows(2)
                    .all(|pair| pair[1].0.duration_since(pair[0].0) >= Duration::from_millis(100))
            );
        }
    }

    #[test]
    fn missing_or_wrong_base_responses_stop_optional_probe_kinds() {
        for mode in [Replies::MissingOpen, Replies::WrongClosedFlags] {
            let request = request(false);
            let (aggregate, _) = execute(&request, mode);
            let super::super::Aggregate { report, events } = aggregate.unwrap();
            assert_eq!(report.identification.outcome, Outcome::Inconclusive);
            let records = packets(&events);
            assert!(
                records
                    .iter()
                    .any(|record| record.probe == Some(Probe::ClosedSyn))
            );
            assert!(
                records
                    .iter()
                    .all(|record| !matches!(record.probe, Some(Probe::TimestampSyn | Probe::Echo)))
            );
            if matches!(mode, Replies::MissingOpen) {
                assert!(
                    report
                        .observations
                        .iter()
                        .all(|observation| observation.probe != Probe::OpenSyn)
                );
            } else {
                assert!(
                    report
                        .observations
                        .iter()
                        .filter(|observation| observation.probe == Probe::ClosedSyn)
                        .all(|observation| observation.tcp.as_ref().unwrap().flags
                            == Tcp::SYN | Tcp::ACK)
                );
            }
        }
    }

    #[test]
    fn nonce_and_echo_reflection_failures_cannot_qualify_observations() {
        for (mode, kind) in [
            (Replies::WrongTimestampEcho, Probe::TimestampSyn),
            (Replies::WrongEchoBody, Probe::Echo),
        ] {
            for v6 in [false, true] {
                let (aggregate, _) = execute(&request(v6), mode);
                let report = aggregate.unwrap().report;
                assert_eq!(report.identification.outcome, Outcome::Inconclusive);
                let affected = report
                    .observations
                    .iter()
                    .filter(|observation| observation.probe == kind)
                    .collect::<Vec<_>>();
                assert!(!affected.is_empty());
                assert!(affected.iter().all(|observation| !observation.suitable));
            }
        }
    }

    #[test]
    fn changed_final_tcp_destination_is_refused_as_probe_evidence() {
        for mode in [Replies::AlteredSent, Replies::AlteredClosed] {
            let (report, lab) = execute(&request(false), mode);
            let error = report.unwrap_err();
            assert_eq!(error.classification().code, "internal.identify_os_evidence");
            let (sequence, port) = lab.refused_request.unwrap();
            if matches!(mode, Replies::AlteredSent) {
                assert_eq!(error.context(), Some(Coordinate::ProbeSequence(1)));
            }
            assert_eq!(error.context(), Some(Coordinate::ProbeSequence(sequence)));
            let sent = packet(&lab.transmitted.last().unwrap().1);
            assert_eq!(
                sent.get::<Tcp>().unwrap().destination_port,
                port.wrapping_add(1)
            );
        }
    }
}
