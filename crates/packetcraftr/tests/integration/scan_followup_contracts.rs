// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::common;

use std::collections::HashMap;
use std::convert::Infallible;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::clock::VirtualClock;
use common::responder::{Arrival, Io, Path, Routes, State};
use packetcraftr::clock::{Clock, SystemClock};
use packetcraftr::dns::{self, batch};
use packetcraftr::policy::Policy;
use packetcraftr::probe::{ProbeEndpoint, Transport};
use packetcraftr::scan::followup::{self, Collector, Event, Report, Request};
use packetcraftr::scan::{self, discovery};
use packetcraftr::target::{Family, Target};
use packetcraftr::traceroute::hosts::{self, Strategy};
use packetcraftr::{Client, Stats};
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_netio::link::Mode;

type Providers = common::FakeProviders<Routes, Io>;

fn host(octet: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, octet)
}

fn network(octets: &[u8]) -> Arc<Mutex<State>> {
    Arc::new(Mutex::new(State {
        paths: octets
            .iter()
            .map(|octet| (host(*octet), Path::new(&[1, 2], Arrival::Reply)))
            .collect::<HashMap<_, _>>(),
        ..State::default()
    }))
}

fn client(state: &Arc<Mutex<State>>, policy: Policy) -> Client<Providers> {
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        common::providers(Routes, Io(Arc::clone(state))),
    )
}

fn scan_request(octets: &[u8]) -> scan::Request {
    let mut collection = packetcraftr::exchange::Collection::default();
    collection.capture.snap_length = 1500;
    scan::Request {
        target_sources: Vec::new(),
        max_in_flight: 1,
        targets: packetcraftr::target::Selection {
            include: octets
                .iter()
                .map(|octet| host(*octet).to_string().parse().unwrap())
                .collect(),
            exclude: Vec::new(),
        },
        address_family: Family::Any,
        endpoints: vec![ProbeEndpoint::Tcp { port: 80 }],
        discovery: Default::default(),
        attempts: 1,
        adaptive: None,
        timeout: Duration::from_millis(50),
        probes_per_second: None,
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        limits: scan::Limits {
            max_duration: Duration::from_secs(10),
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        collection,
    }
}

fn trace() -> followup::Trace {
    followup::Trace {
        strategy: Some(Strategy {
            transport: Transport::Tcp,
            destination_port: Some(80),
        }),
        first_hop: 1,
        max_hops: 4,
        attempts: 1,
        max_probes: 1_000,
        reuse: None,
        runtime: None,
    }
}

/// A UDP lookup of a documentation server, which the fixture answers with
/// port-unreachable errors, so every question ends the same way each run.
fn reverse_dns() -> followup::ReverseDns {
    followup::ReverseDns {
        server: Target::Address(host(53).into()),
        server_port: dns::DEFAULT_SERVER_PORT,
        transport: dns::TransportMode::Udp,
    }
}

fn request(octets: &[u8]) -> Request {
    Request {
        scan: scan_request(octets),
        trace: Some(trace()),
        reverse_dns: Some(reverse_dns()),
    }
}

fn streamed(octets: &[u8]) -> (Report, Vec<Event>) {
    let state = network(octets);
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&events);
    let report = client(&state, Policy::default())
        .scan_with_followups(request(octets), move |event: Event| {
            recorded.lock().unwrap().push(event);
            Ok(())
        })
        .unwrap();
    let events = events.lock().unwrap().clone();
    (report, events)
}

#[test]
fn the_trace_continues_the_scans_probe_sequence_namespace() {
    let (report, events) = streamed(&[7, 8]);

    let scanned: Vec<u64> = events
        .iter()
        .filter_map(|event| match event {
            Event::Scan(scan::Event::Probe { probe, .. }) => Some(probe.sequence),
            _ => None,
        })
        .collect();
    let traced: Vec<u64> = events
        .iter()
        .filter_map(|event| match event {
            Event::Trace(hosts::Event::Probe(probe)) => Some(probe.sequence),
            _ => None,
        })
        .collect();
    assert!(!scanned.is_empty() && !traced.is_empty());
    assert_eq!(
        traced.iter().min().copied(),
        scanned.iter().max().map(|last| last + 1)
    );
    assert!(report.trace.is_some());
}

#[test]
fn the_report_totals_the_scan_the_trace_and_the_lookups() {
    let (report, _) = streamed(&[7, 8]);

    let trace = report.trace.as_ref().expect("the trace ran");
    let lookups = report.reverse_dns.as_ref().expect("lookups were requested");
    assert!(report.scan.stats.packets_attempted > 0);
    assert!(trace.stats.packets_attempted > 0);
    let mut expected = report.scan.stats.clone();
    expected.checked_add_assign(&trace.stats).unwrap();
    expected
        .checked_add_assign(&lookups.stats.clone().unwrap_or_default())
        .unwrap();
    assert_eq!(report.stats, expected);
    assert_eq!(lookups.lookups.len(), report.scan.hosts.len());
}

#[test]
fn lookups_the_policy_refuses_fail_while_the_scan_succeeds() {
    let state = network(&[7]);
    // The one scan probe spends the whole packet allowance.
    let policy = Policy {
        max_packets_per_operation: 1,
        ..Policy::default()
    };
    let report = client(&state, policy)
        .scan_with_followups(
            Request {
                trace: None,
                ..request(&[7])
            },
            |_: Event| Ok(()),
        )
        .expect("the scan still succeeds");

    assert_eq!(report.scan.stats.packets_attempted, 1);
    assert_eq!(report.stats, report.scan.stats);
    let lookups = report.reverse_dns.expect("lookups were requested");
    let lookup = lookups.lookups[0]
        .as_ref()
        .expect("the host keeps a record");
    assert_eq!(lookup.status, batch::QuestionStatus::Failed, "{lookup:?}");
    assert!(lookup.error.is_some(), "{lookup:?}");
    assert_eq!(lookups.stats, Some(Stats::default()));
    assert_eq!(state.lock().unwrap().sends, 1, "no lookup was sent");
}

#[test]
fn collected_events_agree_with_the_streamed_report() {
    let (streamed, _) = streamed(&[7, 8]);

    let state = network(&[7, 8]);
    let collector = Collector::default();
    let report = client(&state, Policy::default())
        .scan_with_followups(request(&[7, 8]), collector.clone())
        .unwrap();
    let aggregate = collector.finish(report).unwrap();

    let addresses = |hosts: &[discovery::Host]| {
        hosts
            .iter()
            .map(|host| (host.address, format!("{:?}", host.state)))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        addresses(&aggregate.scan.hosts),
        addresses(&streamed.scan.hosts)
    );
    let traced = |hosts: &[hosts::Host]| {
        hosts
            .iter()
            .map(|host| (host.address, format!("{:?}", host.state)))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        traced(
            &aggregate
                .trace
                .as_ref()
                .expect("the trace ran")
                .hosts
                .iter()
                .map(|trace| trace.host.clone())
                .collect::<Vec<_>>()
        ),
        traced(&streamed.trace.as_ref().expect("the trace ran").hosts)
    );
    let names = |lookups: &followup::ReverseLookups| {
        lookups
            .lookups
            .iter()
            .map(|lookup| {
                lookup.as_ref().map(|lookup| {
                    (
                        lookup.query_name.clone(),
                        lookup.status,
                        lookup.names.clone(),
                    )
                })
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(aggregate.reverse_dns.as_ref().expect("lookups ran")),
        names(streamed.reverse_dns.as_ref().expect("lookups ran"))
    );
}

/// Advances once between the operation's first time sample and scan setup.
#[derive(Clone)]
struct SetupClock {
    clock: VirtualClock,
    advance: Arc<Mutex<Option<Duration>>>,
}

impl Clock for SetupClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        let now = self.clock.now();
        if let Some(advance) = self.advance.lock().unwrap().take() {
            self.clock.advance(advance);
        }
        now
    }

    fn sleep(&self, delay: Duration, deadline: &Deadline) -> Result<(), Self::Error> {
        self.clock.sleep(delay, deadline)
    }
}

#[test]
fn the_shared_deadline_counts_setup_on_the_clients_clock() {
    let state = network(&[7]);
    let request = Request {
        trace: None,
        reverse_dns: None,
        ..request(&[7])
    };
    let clock = SetupClock {
        clock: VirtualClock::default(),
        advance: Arc::new(Mutex::new(Some(
            request.scan.limits.max_duration + Duration::from_secs(1),
        ))),
    };
    let error = client(&state, Policy::default())
        .with_clock(clock)
        .scan_with_followups(request, |_: Event| Ok(()))
        .expect_err("setup consumed the shared duration");
    assert!(
        matches!(
            error,
            followup::Error::Scan(scan::Error::DurationLimit { .. })
        ),
        "{error:?}"
    );
    assert_eq!(state.lock().unwrap().sends, 0);
}

#[derive(Clone)]
struct FollowupClock {
    scan_finished: Arc<AtomicBool>,
    cancel: Option<Cancellation>,
}

impl Clock for FollowupClock {
    type Error = io::Error;

    fn sleep(&self, delay: Duration, deadline: &Deadline) -> Result<(), Self::Error> {
        if self.scan_finished.load(Ordering::SeqCst) {
            if let Some(cancel) = &self.cancel {
                cancel.cancel();
                return Ok(());
            }
            return Err(io::Error::other("follow-up pacing failed"));
        }
        let Ok(()) = SystemClock.sleep(delay, deadline);
        Ok(())
    }
}

#[test]
fn reverse_dns_pacing_failures_stop_raw_and_connect_followups() {
    for connect in [false, true] {
        for cancel in [false, true] {
            let state = network(&[7]);
            let cancellation = Cancellation::default();
            let scan_finished = Arc::new(AtomicBool::new(false));
            let clock = FollowupClock {
                scan_finished: Arc::clone(&scan_finished),
                cancel: cancel.then(|| cancellation.clone()),
            };
            let client = client(&state, Policy::default())
                .with_clock(clock)
                .with_cancellation(cancellation);
            let mut scan = scan_request(&[7]);
            scan.probes_per_second = Some(1);
            let result = if connect {
                scan.route = Default::default();
                client
                    .scan_connect_with_followups(
                        followup::ConnectRequest {
                            scan,
                            reverse_dns: Some(reverse_dns()),
                        },
                        move |_: scan::connect::Event| {
                            scan_finished.store(true, Ordering::SeqCst);
                            Ok(())
                        },
                    )
                    .map(|_| ())
            } else {
                client
                    .scan_with_followups(
                        Request {
                            scan,
                            trace: None,
                            reverse_dns: Some(reverse_dns()),
                        },
                        move |event: Event| {
                            if matches!(event, Event::Scan(scan::Event::Probe { .. })) {
                                scan_finished.store(true, Ordering::SeqCst);
                            }
                            Ok(())
                        },
                    )
                    .map(|_| ())
            };
            let error = result.expect_err("interrupted DNS pacing cannot report success");
            if cancel {
                assert!(
                    matches!(error, followup::Error::Dns(dns::Error::Cancelled(_))),
                    "connect={connect}: {error:?}"
                );
            } else if let followup::Error::Dns(dns::Error::Clock { source, .. }) = error {
                assert_eq!(source.to_string(), "follow-up pacing failed");
                assert!(source.downcast_ref::<io::Error>().is_some());
            } else {
                panic!("connect={connect}: {error:?}");
            }
            assert_eq!(
                state.lock().unwrap().sends,
                usize::from(!connect),
                "no DNS query was sent"
            );
        }
    }
}
