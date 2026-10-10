// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Library multi-host trace results covering every published host shape.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::probe::{ProbeStatus, Transport};
use packetcraftr::scan::{Reply, Stage};
use packetcraftr::traceroute::hosts::{
    self as library, Basis, Host, HostTrace, NotTraced, Observed, ReusedHop, Selection, State,
    Strategy,
};
use packetcraftr::traceroute::{Hop, ProbeEvidence, ResponseKind, Termination};
use packetcraftr_core::frame::{Frame, LinkType};

pub(crate) fn address(octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet))
}

fn probe(
    sequence: u64,
    hop_limit: u8,
    destination: IpAddr,
    kind: Option<ResponseKind>,
    responder: Option<IpAddr>,
) -> ProbeEvidence {
    ProbeEvidence {
        sequence,
        hop_limit,
        attempt: 1,
        destination,
        strategy: Transport::Tcp,
        destination_port: Some(443),
        status: if kind.is_some() {
            ProbeStatus::Response
        } else {
            ProbeStatus::Timeout
        },
        response_kind: kind,
        responder,
        sent_at: UNIX_EPOCH + Duration::from_secs(sequence),
        received_at: kind.map(|_| UNIX_EPOCH + Duration::from_secs(sequence + 1)),
        latency: kind.map(|_| Duration::from_secs(1)),
        response: kind.map(|_| {
            Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0x45, 0, 0, 20]).expect("fixture frame")
        }),
        reason: "fixture".to_owned(),
    }
}

fn strategy() -> Strategy {
    Strategy {
        transport: Transport::Tcp,
        destination_port: Some(443),
    }
}

/// One complete host traced from a scan observation, one that reused a hop of
/// the first, one the hop bounds left incomplete, one requested probe, and
/// two that were not traced.
pub(crate) fn hosts() -> Vec<(Host, Vec<ProbeEvidence>)> {
    let router = address(1);
    let observed = Host {
        address: address(10),
        scope: None,
        state: State::Complete,
        selection: Some(Selection {
            strategy: strategy(),
            basis: Basis::Observed(Observed {
                address: address(10),
                transport: Transport::Tcp,
                destination_port: Some(443),
                stage: Stage::Scan,
                sequence: 4,
                reply: Reply::TcpSynAck,
                observed_at: Some(UNIX_EPOCH + Duration::from_secs(5)),
            }),
        }),
        termination: Some(Termination::DestinationReached),
        probes: vec![0, 1],
        reused: Vec::new(),
    };
    let observed_probes = vec![
        probe(
            0,
            1,
            address(10),
            Some(ResponseKind::Intermediate),
            Some(router),
        ),
        probe(
            1,
            2,
            address(10),
            Some(ResponseKind::DestinationReached),
            Some(address(10)),
        ),
    ];
    let reusing = Host {
        address: address(11),
        scope: None,
        state: State::Complete,
        selection: Some(Selection {
            strategy: Strategy {
                transport: Transport::Icmp,
                destination_port: None,
            },
            basis: Basis::Requested,
        }),
        termination: Some(Termination::Unreachable),
        probes: vec![2],
        reused: vec![ReusedHop {
            hop_limit: 1,
            source: address(10),
            probes: vec![0],
            responders: vec![router],
            observed_at: Some(UNIX_EPOCH + Duration::from_secs(1)),
            age: Duration::from_secs(3),
        }],
    };
    let mut unreachable = probe(
        2,
        2,
        address(11),
        Some(ResponseKind::Unreachable),
        Some(router),
    );
    unreachable.strategy = Transport::Icmp;
    unreachable.destination_port = None;
    let incomplete = Host {
        address: address(12),
        scope: None,
        state: State::Incomplete,
        selection: Some(Selection {
            strategy: strategy(),
            basis: Basis::Requested,
        }),
        termination: Some(Termination::Timeout),
        probes: vec![3],
        reused: Vec::new(),
    };
    let untraced = |octet, reason| Host {
        address: address(octet),
        scope: None,
        state: State::NotTraced(reason),
        selection: None,
        termination: None,
        probes: Vec::new(),
        reused: Vec::new(),
    };
    let scoped = Host {
        address: IpAddr::V6("fe80::1".parse().expect("link-local fixture")),
        scope: Some(packetcraftr::target::ResolvedZone {
            zone: "eth0".parse().expect("zone"),
            interface: packetcraftr_netio::interface::Id {
                name: "eth0".to_owned(),
                index: 2,
            },
        }),
        ..untraced(0, NotTraced::ScopedTarget)
    };
    vec![
        (observed, observed_probes),
        (reusing, vec![unreachable]),
        (incomplete, vec![probe(3, 1, address(12), None, None)]),
        (untraced(13, NotTraced::NoResponsiveProbe), Vec::new()),
        (scoped, Vec::new()),
    ]
}

pub(crate) fn aggregate() -> library::Aggregate {
    let traces: Vec<_> = hosts()
        .into_iter()
        .map(|(host, probes)| {
            let mut hops: Vec<Hop> = Vec::new();
            for probe in probes {
                match hops.iter_mut().find(|hop| hop.hop_limit == probe.hop_limit) {
                    Some(hop) => hop.probes.push(probe),
                    None => hops.push(Hop {
                        hop_limit: probe.hop_limit,
                        probes: vec![probe],
                    }),
                }
            }
            HostTrace { host, hops }
        })
        .collect();
    library::Aggregate {
        target: "192.0.2.0/28".to_owned(),
        resolved_addresses: traces.iter().map(|trace| trace.host.address).collect(),
        hosts: traces,
        undecoded: vec![library::UndecodedEvidence {
            destination: address(10),
            hop_limit: 1,
            frame: Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0xff]).expect("fixture frame"),
        }],
        diagnostics: Vec::new(),
        reuse: Some(library::Reuse {
            max_age: Duration::from_secs(30),
        }),
        retained_evidence_bytes: 7,
        stats: packetcraftr::Stats::default(),
    }
}

/// The stream a trace of `aggregate` publishes, host records after their last
/// probe.
pub(crate) fn events() -> Vec<library::Event> {
    let mut events = Vec::new();
    for (host, probes) in hosts() {
        events.extend(probes.into_iter().map(library::Event::Probe));
        events.push(library::Event::Host(host));
    }
    events.push(library::Event::Undecoded(library::UndecodedEvidence {
        destination: address(10),
        hop_limit: 1,
        frame: Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0xff]).expect("fixture frame"),
    }));
    events
}
