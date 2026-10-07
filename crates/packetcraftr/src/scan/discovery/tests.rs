// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use packetcraftr_core::packet::MacAddress;

use super::{
    Basis, Composer, Evidence, Host, Link, Mode, Neighbor, NeighborOutcome, NextHop, Observation,
    Options, ReasonKind, Scan, State, Unresponsive,
};
use crate::probe::ProbeEndpoint;
use crate::scan::{Error, Reply};
use crate::target::SelectedAddress;

const GATEWAY_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);

fn address(text: &str) -> IpAddr {
    text.parse().unwrap()
}

fn targets(addresses: &[&str]) -> Vec<SelectedAddress> {
    addresses
        .iter()
        .map(|text| SelectedAddress::new(address(text)))
        .collect()
}

fn observation(sequence: u64, target: &str, response: Option<(ReasonKind, &str)>) -> Observation {
    Observation {
        sequence,
        address: address(target),
        interface: None,
        response: response.map(|(kind, responder)| (kind, address(responder))),
        observed_at: SystemTime::UNIX_EPOCH,
    }
}

fn neighbor(outcome: NeighborOutcome) -> Neighbor {
    Neighbor {
        outcome,
        attempts: 1,
        observed_at: SystemTime::UNIX_EPOCH,
    }
}

fn resolved(octet: u8, cached: bool) -> NeighborOutcome {
    NeighborOutcome::Resolved(Link {
        address: MacAddress([2, 0, 0, 0, 0, octet]),
        cached,
    })
}

fn compose(
    addresses: &[&str],
    mode: Mode,
    unresponsive: Unresponsive,
    observations: Vec<Observation>,
) -> Vec<Host> {
    let mut composer = Composer::new(&targets(addresses), mode, unresponsive);
    for observation in observations {
        assert!(composer.observe(observation));
    }
    composer.finish()
}

#[test]
fn closed_but_responsive_tcp_marks_the_host_responded() {
    let hosts = compose(
        &["192.0.2.10"],
        Mode::Before,
        Unresponsive::Skip,
        vec![observation(
            0,
            "192.0.2.10",
            Some((ReasonKind::Reply(Reply::TcpReset), "192.0.2.10")),
        )],
    );
    let host = &hosts[0];
    assert_eq!((host.state, host.scan), (State::Responded, Scan::Scanned));
    assert_eq!(host.reasons.len(), 1);
    let reason = &host.reasons[0];
    assert_eq!(
        (reason.kind, reason.basis, reason.probe),
        (ReasonKind::Reply(Reply::TcpReset), Basis::Direct, Some(0))
    );
    assert_eq!(reason.kind.evidence(), Evidence::Wire);
    assert_eq!(ReasonKind::Refused.evidence(), Evidence::Socket);
}

#[test]
fn silence_and_router_errors_leave_the_host_uncertain() {
    for (unresponsive, scan) in [
        (Unresponsive::Skip, Scan::Skipped),
        (Unresponsive::Scan, Scan::Scanned),
    ] {
        let hosts = compose(
            &["192.0.2.10"],
            Mode::Before,
            unresponsive,
            vec![
                observation(0, "192.0.2.10", None),
                // An error from a router speaks for the path, not the host.
                observation(
                    1,
                    "192.0.2.10",
                    Some((
                        ReasonKind::Reply(Reply::IcmpDestinationUnreachable),
                        "192.0.2.1",
                    )),
                ),
            ],
        );
        let host = &hosts[0];
        assert_eq!((host.state, host.scan), (State::NoResponse, scan));
        assert!(host.reasons.is_empty());
        assert_eq!(host.probes, [0, 1]);
    }
}

#[test]
fn omitted_and_skipped_discovery_claim_no_reachability() {
    for (mode, state) in [
        (Mode::Omitted, State::NotRequested),
        (Mode::Skipped, State::Skipped),
    ] {
        let hosts = compose(&["192.0.2.10"], mode, Unresponsive::Skip, Vec::new());
        assert_eq!((hosts[0].state, hosts[0].scan), (state, Scan::Scanned));
        assert!(hosts[0].reasons.is_empty() && hosts[0].probes.is_empty());
    }
    let hosts = compose(&["192.0.2.10"], Mode::Only, Unresponsive::Skip, Vec::new());
    assert_eq!(
        (hosts[0].state, hosts[0].scan),
        (State::NoResponse, Scan::NotRequested)
    );
}

#[test]
fn neighbor_evidence_keeps_direct_cached_routed_and_proxy_apart() {
    let addresses = [
        "192.0.2.10",
        "192.0.2.11",
        "198.51.100.7",
        "192.0.2.12",
        "192.0.2.13",
        "192.0.2.14",
    ];
    let mut composer = Composer::new(&targets(&addresses), Mode::Before, Unresponsive::Skip);
    composer.neighbor(0, neighbor(resolved(10, false)));
    composer.neighbor(1, neighbor(resolved(11, true)));
    composer.neighbor(
        2,
        neighbor(NeighborOutcome::Routed(NextHop {
            address: address("192.0.2.1"),
            link: Some(Link {
                address: GATEWAY_MAC,
                cached: false,
            }),
        })),
    );
    // The gateway's link address answering for an on-link target.
    composer.neighbor(3, neighbor(resolved(1, false)));
    // Two targets answered from one link address.
    composer.neighbor(4, neighbor(resolved(20, false)));
    composer.neighbor(5, neighbor(resolved(20, false)));
    let hosts = composer.finish();

    let first = |index: usize| {
        let reason = &hosts[index].reasons[0];
        (reason.kind, reason.basis, reason.link_address)
    };
    assert_eq!(
        first(0),
        (
            ReasonKind::NeighborReply,
            Basis::Direct,
            Some(MacAddress([2, 0, 0, 0, 0, 10]))
        )
    );
    assert_eq!(first(1).0.evidence(), Evidence::Cache);
    assert_eq!(first(1).1, Basis::Cached);
    // A routed host's next hop is never evidence for the host itself.
    assert_eq!(
        (hosts[2].state, hosts[2].scan, hosts[2].reasons.len()),
        (State::NoResponse, Scan::Skipped, 0)
    );
    for index in [3, 4, 5] {
        assert_eq!(first(index).1, Basis::PossibleProxy);
        assert_eq!(hosts[index].state, State::Responded);
    }
}

#[test]
fn a_dual_stack_host_and_its_own_routes_are_not_proxies() {
    let addresses = ["192.0.2.1", "2001:db8::1", "198.51.100.7"];
    let mut composer = Composer::new(&targets(&addresses), Mode::Only, Unresponsive::Skip);
    composer.neighbor(0, neighbor(resolved(1, false)));
    composer.neighbor(1, neighbor(resolved(1, false)));
    composer.neighbor(
        2,
        neighbor(NeighborOutcome::Routed(NextHop {
            address: address("192.0.2.1"),
            link: Some(Link {
                address: GATEWAY_MAC,
                cached: true,
            }),
        })),
    );
    let hosts = composer.finish();

    for host in &hosts[..2] {
        assert_eq!(host.reasons[0].basis, Basis::Direct);
        assert_eq!(host.reasons[0].link_address, Some(GATEWAY_MAC));
    }
    assert!(hosts[2].reasons.is_empty());
}

#[test]
fn neighbor_reasons_precede_probe_reasons() {
    let mut composer = Composer::new(&targets(&["192.0.2.10"]), Mode::Only, Unresponsive::Skip);
    assert!(composer.observe(observation(
        1,
        "192.0.2.10",
        Some((ReasonKind::Reply(Reply::IcmpEchoReply), "192.0.2.10")),
    )));
    assert!(composer.observe(observation(0, "192.0.2.10", None)));
    assert!(!composer.observe(observation(2, "192.0.2.99", None)));
    composer.neighbor(0, neighbor(resolved(10, false)));
    let host = &composer.finish()[0];
    assert_eq!(host.probes, [0, 1]);
    assert_eq!(
        host.reasons
            .iter()
            .map(|reason| (reason.kind, reason.probe))
            .collect::<Vec<_>>(),
        [
            (ReasonKind::NeighborReply, None),
            (ReasonKind::Reply(Reply::IcmpEchoReply), Some(1)),
        ]
    );
}

fn limits() -> crate::scan::Limits {
    crate::scan::Limits {
        max_ports: 8,
        ..crate::scan::Limits::default()
    }
}

fn validate(options: &Options) -> Result<(), Error> {
    options.validate(
        Duration::from_secs(1),
        &crate::route::Options::default(),
        &limits(),
    )
}

#[test]
fn options_reject_probes_that_would_not_run_or_cannot_be_bounded() {
    let tcp = ProbeEndpoint::Tcp { port: 80 };
    let running = Options {
        mode: Mode::Before,
        probes: vec![tcp],
        ..Options::default()
    };
    assert!(validate(&Options::default()).is_ok());
    assert!(validate(&running).is_ok());
    for invalid in [
        Options {
            mode: Mode::Omitted,
            ..running.clone()
        },
        Options {
            mode: Mode::Skipped,
            probes: Vec::new(),
            neighbor: true,
            ..Options::default()
        },
        Options {
            unresponsive: Unresponsive::Scan,
            ..Options::default()
        },
        Options {
            mode: Mode::Only,
            unresponsive: Unresponsive::Scan,
            ..running.clone()
        },
        Options {
            probes: Vec::new(),
            ..running.clone()
        },
        Options {
            probes: vec![tcp, tcp],
            ..running.clone()
        },
    ] {
        assert!(
            matches!(validate(&invalid), Err(Error::InvalidDiscovery { .. })),
            "{invalid:?}"
        );
    }
    let wide = Options {
        probes: (1..=9).map(|port| ProbeEndpoint::Tcp { port }).collect(),
        ..running.clone()
    };
    assert!(matches!(
        validate(&wide),
        Err(Error::InvalidLimit {
            field: "discovery_probes",
            ..
        })
    ));

    let neighbor = Options {
        neighbor: true,
        ..running
    };
    assert!(validate(&neighbor).is_ok());
    let layer3 = crate::route::Options {
        link_mode: packetcraftr_netio::link::Mode::Layer3,
        ..Default::default()
    };
    assert!(
        neighbor
            .validate(Duration::from_secs(1), &layer3, &limits())
            .is_err()
    );
    // The resolver's own bounds apply to the scan's timeout and evidence
    // limits.
    let default_route = crate::route::Options::default();
    assert!(
        neighbor
            .validate(Duration::from_secs(31), &default_route, &limits())
            .is_err()
    );
    let unsnappable = crate::scan::Limits {
        max_evidence_bytes: 64,
        ..limits()
    };
    assert!(
        neighbor
            .validate(Duration::from_secs(1), &default_route, &unsnappable)
            .is_err()
    );
}
