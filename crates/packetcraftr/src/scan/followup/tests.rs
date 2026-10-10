// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, UNIX_EPOCH};

use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_core::frame::{Frame, LinkType};

use super::request::{ReverseDns, Trace};
use super::reverse::{Lookup, ReverseLookup, batched, last_batch_send, names, retain_names};
use super::trace::{Retained, Stage};
use crate::dns::{self, batch};
use crate::probe::Transport;
use crate::scan::discovery::{Host, Scan, State};
use crate::target::{Selection, Target};
use crate::test_support::FakeProviders;
use crate::traceroute::hosts;
use crate::{Client, Stats, scan};

fn scan_request() -> scan::Request {
    scan::Request {
        max_in_flight: 1,
        targets: Target::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).into(),
        target_sources: Vec::new(),
        endpoints: vec![crate::probe::ProbeEndpoint::Icmp],
        discovery: Default::default(),
        adaptive: None,
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        address_family: crate::target::Family::Any,
        attempts: 1,
        timeout: Duration::from_millis(100),
        probes_per_second: Some(10),
        limits: scan::Limits {
            max_duration: Duration::from_secs(60),
            ..Default::default()
        },
        // The unit fixtures describe scan requests, not link-layer
        // route constraints; a layer-3 route reserves no neighbor pacing.
        route: crate::route::Options {
            link_mode: packetcraftr_netio::link::Mode::Layer3,
            ..Default::default()
        },
        collection: Default::default(),
    }
}

fn options() -> Trace {
    Trace {
        strategy: Some(hosts::Strategy {
            transport: Transport::Icmp,
            destination_port: None,
        }),
        first_hop: 1,
        max_hops: 8,
        attempts: 1,
        max_probes: 1000,
        reuse: Some(hosts::Reuse {
            max_age: Duration::from_secs(5),
        }),
        runtime: None,
    }
}

fn host(address: IpAddr, scope: Option<crate::target::ResolvedZone>) -> Host {
    Host {
        address,
        scope,
        state: State::Responded,
        reasons: Vec::new(),
        neighbor: None,
        scan: Scan::Scanned,
        probes: Vec::new(),
    }
}

fn frame(byte: u8) -> Frame {
    Frame::new(UNIX_EPOCH, LinkType::RAW, vec![byte, 0, 0, 20]).expect("fixture frame")
}

fn probe_evidence(
    sequence: u64,
    address: IpAddr,
    reply: Option<scan::Reply>,
) -> scan::ProbeEvidence {
    // The evidence names the probe it could have answered.
    let (transport, port) = match reply {
        Some(scan::Reply::IcmpEchoReply) => (Transport::Icmp, None),
        _ => (Transport::Tcp, Some(80)),
    };
    scan::ProbeEvidence {
        sequence,
        stage: scan::Stage::Scan,
        address,
        scope: None,
        transport,
        port,
        attempt: 1,
        status: if reply.is_some() {
            crate::probe::ProbeStatus::Response
        } else {
            crate::probe::ProbeStatus::Timeout
        },
        classification: scan::Classification::Open,
        reply,
        responder: reply.map(|_| address),
        sent_at: UNIX_EPOCH,
        received_at: reply.map(|_| UNIX_EPOCH),
        latency: None,
        response: reply.map(|_| frame(0x45)),
        reason: String::new(),
        application: None,
    }
}

fn endpoint(address: IpAddr, probes: Vec<scan::ProbeEvidence>) -> scan::Endpoint {
    scan::Endpoint {
        address,
        scope: None,
        transport: Transport::Tcp,
        port: Some(80),
        classification: scan::Classification::Open,
        port_hint: None,
        inference: None,
        probes,
    }
}

fn aggregate(
    hosts: Vec<Host>,
    discovery: Vec<scan::ProbeEvidence>,
    endpoints: Vec<scan::Endpoint>,
    undecoded: Vec<Frame>,
    unattributed: Vec<scan::Unattributed>,
    retained_evidence_bytes: usize,
) -> scan::Aggregate {
    scan::Aggregate {
        planned_duration: Duration::ZERO,
        target: String::new(),
        resolved_addresses: Vec::new(),
        hosts,
        discovery,
        endpoints,
        undecoded,
        unattributed,
        diagnostics: Vec::new(),
        retained_evidence_bytes,
        stats: Stats::default(),
        rtt: scan::Rtt::default(),
        scheduling: Default::default(),
    }
}

#[test]
fn the_request_follows_the_scan_hosts_and_what_remains_of_its_duration() {
    let stage = Stage::new(&options(), &scan_request()).expect("a valid stage");
    let zone = crate::target::ResolvedZone {
        zone: "eth0".parse().unwrap(),
        interface: packetcraftr_netio::interface::Id {
            name: "eth0".to_owned(),
            index: 2,
        },
    };
    let aggregate = aggregate(
        vec![
            host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), None),
            host("fe80::1".parse().unwrap(), Some(zone)),
        ],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        0,
    );
    let started = Instant::now()
        .checked_sub(Duration::from_secs(10))
        .expect("an instant ten seconds ago");

    let request = stage
        .request(
            &aggregate,
            Retained::of(&aggregate),
            started,
            Instant::now(),
            Some(Instant::now()),
        )
        .expect("a request");

    // The resolved handoff names the exact scan hosts while `targets`
    // keeps the scan's original bounded declaration.
    let resolved: Vec<_> = request
        .resolved_targets
        .as_ref()
        .expect("the resolved hosts hand off")
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(resolved, ["192.0.2.7", "fe80::1%eth0"]);
    assert_eq!(request.targets, scan_request().targets);
    assert!(request.paced_after.is_some());
    assert!(request.limits.max_duration <= Duration::from_secs(50));
    assert!(request.limits.max_duration > Duration::from_secs(49));
    assert_eq!(request.max_targets, scan_request().limits.max_targets);
    assert_eq!(
        request.strategy,
        Some(hosts::Strategy {
            transport: Transport::Icmp,
            destination_port: None
        })
    );
}

#[test]
fn a_spent_duration_leaves_the_trace_a_typed_limit_to_fail() {
    let stage = Stage::new(&options(), &scan_request()).expect("a valid stage");
    let started = Instant::now()
        .checked_sub(Duration::from_secs(3600))
        .expect("an instant an hour ago");
    let aggregate = aggregate(
        vec![host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), None)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        0,
    );

    let request = stage
        .request(
            &aggregate,
            Retained::of(&aggregate),
            started,
            Instant::now(),
            None,
        )
        .unwrap();

    assert_eq!(request.limits.max_duration, Duration::from_nanos(1));
    assert!(request.paced_after.is_none());
}

#[test]
fn the_trace_request_deducts_the_scans_retained_evidence() {
    let stage = Stage::new(&options(), &scan_request()).expect("a valid stage");
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    // The host record names the same discovery probe; it must not be
    // charged twice.
    let mut scanned = host(address, None);
    scanned.probes = vec![0];
    let discovery = vec![probe_evidence(0, address, Some(scan::Reply::IcmpEchoReply))];
    let aggregate = aggregate(
        vec![scanned],
        discovery,
        vec![endpoint(
            address,
            vec![probe_evidence(1, address, Some(scan::Reply::TcpReset))],
        )],
        vec![frame(0x02)],
        vec![scan::Unattributed {
            attribution: scan::Attribution::Late,
            sequence: Some(1),
            frame: frame(0x03),
        }],
        1_024,
    );
    let limits = stage.template.limits;
    let template = stage.template.collection.clone();

    let request = stage
        .request(
            &aggregate,
            Retained::of(&aggregate),
            Instant::now(),
            Instant::now(),
            None,
        )
        .expect("the narrowed request validates");

    // Two answered probes, one undecoded frame, one unattributed frame.
    assert_eq!(
        request.limits.max_evidence_frames,
        limits.max_evidence_frames - 4
    );
    assert_eq!(
        request.limits.max_evidence_bytes,
        limits.max_evidence_bytes - 1_024
    );
    assert_eq!(request.limits.max_undecoded, limits.max_undecoded - 1);
    assert!(request.limits.max_undecoded <= request.limits.max_evidence_frames);
    assert_eq!(
        request.collection.capture.max_frames,
        request.limits.max_evidence_frames
    );
    assert_eq!(
        request.collection.capture.max_bytes,
        request.limits.max_evidence_bytes
    );
    assert!(request.collection.max_responses <= request.collection.capture.max_frames);
    assert!(request.collection.max_unmatched_frames <= request.collection.capture.max_frames);
    // The collection is narrowed, never widened; snap/decode sizes stay.
    assert!(request.collection.capture.max_frames <= template.capture.max_frames);
    assert_eq!(
        request.collection.capture.snap_length,
        template.capture.snap_length
    );
    assert!(request.validate().is_ok());
}

#[test]
fn an_exhausted_evidence_budget_fails_with_a_typed_limit_before_tracing() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    // Scan and trace share the queue: the template pairs a four-frame
    // evidence budget with a four-frame collection, like the CLI builds.
    let mut scan = scan_request();
    scan.limits.max_evidence_frames = 4;
    scan.limits.max_undecoded = 4;
    scan.collection.capture.max_frames = 4;
    scan.collection.max_responses = 4;
    scan.collection.max_unmatched_frames = 4;
    let held = |count: usize| {
        aggregate(
            vec![host(address, None)],
            vec![probe_evidence(0, address, Some(scan::Reply::IcmpEchoReply))],
            Vec::new(),
            (0..count).map(|byte| frame(byte as u8 + 1)).collect(),
            Vec::new(),
            0,
        )
    };
    for (options, held_frames, name) in [
        (
            Trace {
                attempts: 3,
                ..options()
            },
            2usize,
            "fewer frames left than one hop's responses",
        ),
        (options(), 4usize, "no frames left"),
    ] {
        let stage = Stage::new(&options, &scan).expect("the template itself is valid");
        let aggregate = held(held_frames);
        let error = stage
            .request(
                &aggregate,
                Retained::of(&aggregate),
                Instant::now(),
                Instant::now(),
                None,
            )
            .expect_err("the trace cannot retain a hop's responses");
        assert_eq!(
            error.classification().code,
            "cli.traceroute_limit",
            "{name}: {error}"
        );
    }
}

#[test]
fn a_byte_budget_under_one_snap_length_is_rejected() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    // The scan's retained frames leave less than one snapshot length.
    let retained = scan_request().limits.max_evidence_bytes
        - (scan_request().collection.capture.snap_length - 1);
    let stage = Stage::new(&options(), &scan_request()).expect("the template itself is valid");
    let aggregate = aggregate(
        vec![host(address, None)],
        vec![probe_evidence(0, address, Some(scan::Reply::IcmpEchoReply))],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        retained,
    );

    let error = stage
        .request(
            &aggregate,
            Retained::of(&aggregate),
            Instant::now(),
            Instant::now(),
            None,
        )
        .expect_err("no response fits inside the remaining bytes");

    assert_eq!(error.classification().kind, Kind::Usage, "{error}");
}

#[test]
fn an_untraceable_scan_keeps_the_whole_evidence_budget() {
    let mut silent = options();
    silent.strategy = None;
    let stage = Stage::new(&silent, &scan_request()).expect("a valid stage");
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    // The scan retained undecoded and unattributed traffic and no host
    // answered anything the trace could rest on; nothing is deducted
    // because the trace keeps no evidence for a host it will not probe.
    let aggregate = aggregate(
        vec![host(address, None)],
        vec![probe_evidence(0, address, None)],
        Vec::new(),
        vec![frame(0x02)],
        vec![scan::Unattributed {
            attribution: scan::Attribution::Ambiguous,
            sequence: None,
            frame: frame(0x03),
        }],
        usize::MAX,
    );

    let request = stage
        .request(
            &aggregate,
            Retained::of(&aggregate),
            Instant::now(),
            Instant::now(),
            None,
        )
        .expect("a plan of only not_traced hosts needs no evidence budget");

    assert_eq!(
        request.limits.max_evidence_frames,
        stage.template.limits.max_evidence_frames
    );
    assert_eq!(
        request.limits.max_evidence_bytes,
        stage.template.limits.max_evidence_bytes
    );
    assert_eq!(
        request.limits.max_undecoded,
        stage.template.limits.max_undecoded
    );
    assert_eq!(request.collection, stage.template.collection);
}

fn policy_client(policy: crate::policy::Policy) -> Client<FakeProviders> {
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        FakeProviders::default(),
    )
}

#[test]
fn the_trace_spends_only_the_policy_allowance_the_scan_left() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let mut scan = aggregate(
        vec![host(address, None)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        0,
    );
    scan.stats = Stats {
        packets_attempted: 1,
        bytes: 27,
        ..Stats::default()
    };
    let mut trace_options = options();
    trace_options.max_hops = 1;
    let stage = Stage::new(&trace_options, &scan_request()).expect("a valid stage");

    // The scan used the policy's one packet: the trace plan's worst case
    // is refused before any provider I/O.
    let packet_capped = policy_client(crate::policy::Policy {
        max_packets_per_operation: 1,
        ..crate::policy::Policy::default()
    });
    let error = stage
        .stream(
            &packet_capped,
            &scan,
            Retained::of(&scan),
            Instant::now(),
            None,
            |_| Ok(()),
        )
        .err()
        .unwrap_or_else(|| panic!("the stream path narrows the packet allowance"));
    assert_eq!(
        error.classification().code,
        "policy.packet_limit",
        "{error:?}"
    );

    // The byte ceiling narrows identically: 73 remaining bytes cannot
    // fit even one worst-case trace probe.
    let byte_capped = policy_client(crate::policy::Policy {
        max_bytes_per_operation: 100,
        ..crate::policy::Policy::default()
    });
    let error = stage
        .stream(
            &byte_capped,
            &scan,
            Retained::of(&scan),
            Instant::now(),
            None,
            |_| Ok(()),
        )
        .err()
        .unwrap_or_else(|| panic!("the stream path narrows bytes the same way"));
    assert_eq!(
        error.classification().code,
        "policy.byte_limit",
        "{error:?}"
    );

    // A plan that sends nothing never trips the exhausted allowance:
    // with no strategy and no observations, the host is reported
    // not-traced instead of erroring.
    let mut not_traced = trace_options;
    not_traced.strategy = None;
    let stage = Stage::new(&not_traced, &scan_request()).expect("a valid stage");
    let streamed = stage
        .stream(
            &packet_capped,
            &scan,
            Retained::of(&scan),
            Instant::now(),
            None,
            |_| Ok(()),
        )
        .unwrap_or_else(|error| panic!("the empty plan also admits: {error:?}"));
    assert_eq!(streamed.report.stats.packets_attempted, 0);
    assert!(
        streamed
            .report
            .hosts
            .iter()
            .all(|host| matches!(host.state, hosts::State::NotTraced(_))),
        "{:?}",
        streamed.report.hosts
    );
}

#[test]
fn the_request_continues_the_scan_probe_sequence_namespace() {
    let stage = Stage::new(&options(), &scan_request()).expect("a valid stage");
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    // Discovery and endpoint probes share one namespace: the trace
    // starts one past their highest.
    let mut scanned = aggregate(
        vec![host(address, None)],
        vec![probe_evidence(7, address, Some(scan::Reply::IcmpEchoReply))],
        vec![endpoint(
            address,
            vec![probe_evidence(0, address, Some(scan::Reply::TcpSynAck))],
        )],
        Vec::new(),
        Vec::new(),
        0,
    );
    let request = stage
        .request(
            &scanned,
            Retained::of(&scanned),
            Instant::now(),
            Instant::now(),
            None,
        )
        .expect("a request");
    assert_eq!(request.first_sequence, 8);

    let empty = aggregate(
        vec![host(address, None)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        0,
    );
    let request = stage
        .request(
            &empty,
            Retained::of(&empty),
            Instant::now(),
            Instant::now(),
            None,
        )
        .expect("a request");
    assert_eq!(request.first_sequence, 0);

    scanned.discovery = vec![probe_evidence(
        u64::MAX,
        address,
        Some(scan::Reply::IcmpEchoReply),
    )];
    let error = stage
        .request(
            &scanned,
            Retained::of(&scanned),
            Instant::now(),
            Instant::now(),
            None,
        )
        .expect_err("no sequence space remains");
    assert_eq!(
        error.classification().code,
        "cli.traceroute_limit",
        "{error:?}"
    );
}

#[test]
fn the_exact_hosts_hand_off_as_targets_not_declarations() {
    let mut scan = scan_request();
    scan.targets = Selection {
        include: vec![
            "2001:db8::/116".parse().unwrap(),
            "2001:db8::1000".parse().unwrap(),
        ],
        exclude: Vec::new(),
    };
    scan.limits.max_targets = 5_000;
    let mut options = options();
    options.strategy = None;
    let stage = Stage::new(&options, &scan).expect("a valid stage");
    let hosts: Vec<Host> = (0..4_097u16)
        .map(|index| {
            host(
                IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, index)),
                None,
            )
        })
        .collect();
    let aggregate = aggregate(hosts, Vec::new(), Vec::new(), Vec::new(), Vec::new(), 0);
    let request = stage
        .request(
            &aggregate,
            Retained::of(&aggregate),
            Instant::now(),
            Instant::now(),
            None,
        )
        .expect("the exact hosts hand off");
    assert_eq!(
        request
            .resolved_targets
            .as_ref()
            .expect("the handoff list")
            .len(),
        4_097
    );
    assert_eq!(
        request.targets.include.len(),
        2,
        "the compact declaration stays for audit"
    );
    request
        .validate()
        .expect("the request validates without resolution");
}

#[test]
fn the_scan_pacing_marker_passes_through_monotonic() {
    let stage = Stage::new(&options(), &scan_request()).expect("a valid stage");
    let aggregate = aggregate(
        vec![host(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), None)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        0,
    );
    for last_sent in [
        Instant::now().checked_sub(Duration::from_secs(3600)),
        Some(Instant::now() + Duration::from_secs(3600)),
    ] {
        let request = stage
            .request(
                &aggregate,
                Retained::of(&aggregate),
                Instant::now(),
                Instant::now(),
                last_sent,
            )
            .expect("a request");
        // The monotonic marker is carried through exactly: a far-future
        // one still owes its interval under the runner's saturating wait.
        assert_eq!(request.paced_after, last_sent);
    }
    let request = stage
        .request(
            &aggregate,
            Retained::of(&aggregate),
            Instant::now(),
            Instant::now(),
            None,
        )
        .expect("a request");
    assert!(request.paced_after.is_none());
}

#[test]
fn the_finalized_queue_configuration_is_validated() {
    let mut scan = scan_request();
    scan.collection.capture.max_frames = 1;
    scan.collection.max_responses = 1;
    scan.collection.max_unmatched_frames = 1;
    let attempts = Trace {
        attempts: 3,
        ..options()
    };
    let error = attempts
        .validate(&scan)
        .expect_err("three attempts a hop cannot retain in one queue slot");
    assert_eq!(
        error.classification().code,
        "cli.traceroute_limit",
        "{error}"
    );
    options()
        .validate(&scan)
        .expect("one attempt fits and an equivalent workflow collection still validates");
}

#[test]
fn streamed_events_count_what_a_stripped_aggregate_no_longer_holds() {
    let stage = Stage::new(&options(), &scan_request()).expect("a valid stage");
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let responded = probe_evidence(0, address, Some(scan::Reply::IcmpEchoReply));
    let mut retained = Retained::default();
    retained.observe(&scan::Event::Probe {
        target: std::sync::Arc::from("192.0.2.7"),
        probe: responded.clone(),
    });
    retained.observe(&scan::Event::Undecoded { frame: frame(0x02) });
    retained.observe(&scan::Event::Unattributed(scan::Unattributed {
        attribution: scan::Attribution::Late,
        sequence: Some(0),
        frame: frame(0x03),
    }));
    retained.observe(&scan::Event::Diagnostic(
        packetcraftr_core::diagnostic::Diagnostic::info("test.retained", "holds nothing"),
    ));
    // A metadata reply with no retained frame is not held evidence.
    let mut untimed = probe_evidence(1, address, Some(scan::Reply::IcmpEchoReply));
    untimed.response = None;
    retained.observe(&scan::Event::Probe {
        target: std::sync::Arc::from("192.0.2.7"),
        probe: untimed,
    });

    // The tracker keeps the outcome but strips the frame, and keeps no
    // undecoded or unattributed events at all.
    let mut stripped = responded;
    stripped.response = None;
    let aggregate = aggregate(
        vec![host(address, None)],
        vec![stripped],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        512,
    );

    let request = stage
        .request(&aggregate, retained, Instant::now(), Instant::now(), None)
        .expect("the narrowed request validates");

    assert_eq!(
        request.limits.max_evidence_frames,
        stage.template.limits.max_evidence_frames - 3
    );
    assert_eq!(
        request.limits.max_undecoded,
        stage.template.limits.max_undecoded - 1
    );
    assert_eq!(
        request.limits.max_evidence_bytes,
        stage.template.limits.max_evidence_bytes - 512
    );
}

#[test]
fn an_exactly_full_frame_budget_fails_with_a_typed_limit() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let mut scan = scan_request();
    scan.limits.max_evidence_frames = 1;
    scan.limits.max_undecoded = 1;
    scan.collection.capture.max_frames = 1;
    scan.collection.max_responses = 1;
    scan.collection.max_unmatched_frames = 1;
    let stage = Stage::new(&options(), &scan).expect("the template itself is valid");
    let aggregate = aggregate(
        vec![host(address, None)],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        0,
    );
    let retained = Retained {
        frames: 1,
        undecoded: 0,
    };

    let error = stage
        .request(&aggregate, retained, Instant::now(), Instant::now(), None)
        .expect_err("the scan used the whole shared frame budget");

    assert_eq!(
        error.classification().code,
        "cli.traceroute_limit",
        "{error}"
    );
}

fn responding(count: usize) -> Vec<Host> {
    (0..count)
        .map(|index| Host {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, u8::try_from(index % 256).unwrap())),
            scope: None,
            state: State::Responded,
            reasons: Vec::new(),
            neighbor: None,
            scan: Scan::Scanned,
            probes: Vec::new(),
        })
        .collect()
}

/// A UDP lookup of a documentation server over `link_mode`.
fn udp_lookup(link_mode: packetcraftr_netio::link::Mode) -> Lookup {
    Lookup {
        template: dns::Request {
            server: Target::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))),
            address_family: crate::target::Family::Any,
            server_port: dns::DEFAULT_SERVER_PORT,
            source_port: 0,
            query_name: String::new(),
            query_type: dns::QueryType::PTR,
            transaction_id: 0,
            recursion_desired: true,
            edns: None,
            transport: dns::TransportMode::Udp,
            attempts: 1,
            timeout: Duration::from_millis(20),
            queries_per_second: None,
            limits: dns::Limits::default(),
            route: crate::route::Options {
                link_mode,
                ..crate::route::Options::default()
            },
            collection: crate::exchange::Collection::default(),
        },
    }
}

fn packet_budget(packets: usize) -> crate::policy::Policy {
    crate::policy::Policy {
        max_packets_per_operation: u64::try_from(packets).unwrap(),
        ..crate::policy::Policy::default()
    }
}

/// A client whose policy allows `packets` per operation and whose
/// resolver sends up to `neighbor_attempts` requests per resolution.
fn budget_client(packets: usize, neighbor_attempts: u32) -> Client<FakeProviders> {
    policy_client(packet_budget(packets))
        .with_neighbor_options(crate::neighbor::Options {
            max_attempts: neighbor_attempts,
            ..crate::neighbor::Options::default()
        })
        .expect("valid resolver options")
}

#[test]
fn a_lookup_runs_in_the_allowance_the_scan_and_trace_left() {
    let lookup = udp_lookup(packetcraftr_netio::link::Mode::Layer3);
    let client = budget_client(2, 3);
    // The earlier stages spent the whole two-packet allowance: the
    // narrowed view authorizes no question, so the host keeps a failed
    // record and no traffic leaves, without the command failing.
    let spent = Stats {
        packets_attempted: 2,
        ..Stats::default()
    };
    let view = client.with_remaining_budget(&spent);
    assert_eq!(view.policy().max_packets_per_operation, 0);
    let (records, stats) = lookup.run(&view, &responding(1), Instant::now(), None);
    assert_eq!(records.len(), 1);
    let record = records[0].as_ref().expect("the host keeps a record");
    assert_eq!(record.status, batch::QuestionStatus::Failed, "{record:?}");
    assert_eq!(stats.packets_attempted, 0, "nothing was sent");
}

#[test]
fn every_batch_of_lookups_shares_one_policy_budget() {
    let lookup = udp_lookup(packetcraftr_netio::link::Mode::Layer3);
    let client = budget_client(batch::MAX_QUESTIONS, 3);
    assert_eq!(
        lookup.authorize(&client, &responding(batch::MAX_QUESTIONS)),
        Ok(())
    );
    // Two batches, each within the budget alone, exceed it together.
    assert!(
        lookup
            .authorize(&client, &responding(2 * batch::MAX_QUESTIONS))
            .is_err()
    );
}

#[test]
fn link_layer_lookups_budget_every_neighbor_attempt_per_query() {
    let lookup = udp_lookup(packetcraftr_netio::link::Mode::Auto);
    // Enough for the queries alone, not for the requests before each.
    let budget = batch::MAX_QUESTIONS;
    for (attempts, fits) in [(1, budget / 2), (3, budget / 4)] {
        let client = budget_client(budget, attempts);
        assert_eq!(
            lookup.authorize(&client, &responding(fits)),
            Ok(()),
            "{attempts}"
        );
        assert!(
            lookup.authorize(&client, &responding(fits + 1)).is_err(),
            "{attempts}"
        );
    }
}

#[test]
fn hosts_that_never_responded_report_no_lookup_statistics() {
    let lookup = udp_lookup(packetcraftr_netio::link::Mode::Layer3);
    let client = policy_client(packet_budget(1));
    let silent: Vec<Host> = responding(2)
        .into_iter()
        .map(|host| Host {
            state: State::NoResponse,
            ..host
        })
        .collect();
    let result = names(
        Some(&lookup),
        &client,
        &silent,
        Instant::now(),
        Some(Instant::now()),
    )
    .expect("a lookup was requested");
    assert_eq!(result.lookups, [None, None]);
    assert_eq!(result.stats, None, "no lookup ran, so none has statistics");
    // A refused lookup still leaves a record, and its statistics.
    let result = names(
        Some(&lookup),
        &client,
        &responding(1),
        Instant::now(),
        Some(Instant::now()),
    )
    .expect("a lookup was requested");
    assert!(result.lookups[0].is_some());
    assert!(result.stats.is_some());
}

#[test]
fn refused_lookups_wait_for_no_batch() {
    let mut lookup = udp_lookup(packetcraftr_netio::link::Mode::Layer3);
    lookup.template.queries_per_second = Some(1);
    // The policy refuses the lookups, so nothing is sent.
    let client = policy_client(packet_budget(1));
    let (names, stats) = lookup.run(
        &client,
        &responding(batch::MAX_QUESTIONS + 1),
        Instant::now(),
        Some(Instant::now()),
    );
    assert!(
        names
            .iter()
            .flatten()
            .all(|name| name.status == batch::QuestionStatus::Failed)
    );
    assert_eq!(
        stats.elapsed,
        Duration::ZERO,
        "no batch waits for questions that are never sent"
    );
}

fn answered(names: &[&str]) -> ReverseLookup {
    ReverseLookup {
        names: names.iter().map(|name| (*name).to_owned()).collect(),
        ..ReverseLookup::ended(
            "10.2.0.192.in-addr.arpa.".to_owned(),
            batch::QuestionStatus::Completed,
            None,
        )
    }
}

#[test]
fn a_batch_waits_only_what_remains_of_the_pause() {
    let hour = Duration::from_secs(3600);
    let waited = |last_sent, pause| {
        let (_, stats) = batched(
            &responding(1),
            pause,
            batch::MAX_QUESTIONS,
            last_sent,
            Instant::now().checked_add(hour),
            Some(&Cancellation::default()),
            usize::MAX,
            Instant::now,
            std::thread::sleep,
            |addresses, _| {
                let lookups = addresses.iter().map(|_| answered(&[])).collect();
                (lookups, Stats::default(), None)
            },
        );
        stats.elapsed
    };

    let pause = Duration::from_millis(50);
    assert_eq!(waited(None, pause), Duration::ZERO);
    // A transmission a whole pause ago, such as a probe whose reply took
    // that long, already satisfied the rate.
    assert_eq!(
        waited(Instant::now().checked_sub(pause), pause),
        Duration::ZERO
    );
    let owed = waited(Some(Instant::now()), pause);
    assert!(!owed.is_zero() && owed <= pause, "{owed:?}");
}

#[test]
fn a_batch_counting_no_packets_still_spaces_the_next_from_its_sends() {
    let hosts = responding(batch::MAX_QUESTIONS + 1);
    let pause = Duration::from_millis(50);
    let (_, stats) = batched(
        &hosts,
        pause,
        batch::MAX_QUESTIONS,
        None,
        Instant::now().checked_add(Duration::from_secs(60)),
        Some(&Cancellation::default()),
        usize::MAX,
        Instant::now,
        std::thread::sleep,
        // A TCP lookup reports its send but no packets.
        |addresses, _| {
            let lookups = addresses.iter().map(|_| answered(&[])).collect();
            (lookups, Stats::default(), Some(Instant::now()))
        },
    );
    assert!(
        stats.elapsed > Duration::ZERO,
        "the second batch waits for the first's send"
    );
}

#[test]
fn a_window_too_short_for_one_question_leaves_its_lookups_unattempted() {
    let lookup = udp_lookup(packetcraftr_netio::link::Mode::Layer3);
    let client = budget_client(batch::MAX_QUESTIONS, 1);
    let addresses = [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))];
    let (records, stats, sent) = lookup.lookup(&client, &addresses, Duration::from_millis(1));
    assert_eq!(
        records[0].status,
        batch::QuestionStatus::Unattempted,
        "{:?}",
        records[0]
    );
    assert_eq!((stats.packets_attempted, sent), (0, None));
}

#[test]
fn a_batchs_questions_share_the_scans_evidence_limits() {
    let mut lookup = udp_lookup(packetcraftr_netio::link::Mode::Layer3);
    let snap_length = lookup.template.collection.capture.snap_length;
    lookup.template.limits.max_evidence_frames = 1_000;
    lookup.template.limits.max_evidence_bytes = 4 * snap_length;
    assert_eq!(lookup.batch_size(), 4, "each share still holds a frame");
    lookup.template.limits.max_evidence_bytes = 1_000 * snap_length;
    lookup.template.limits.max_evidence_frames = 3;
    assert_eq!(lookup.batch_size(), 3);

    lookup.template.limits.max_evidence_frames = 1_000;
    let addresses: Vec<IpAddr> = (1..=4)
        .map(|host| IpAddr::V4(Ipv4Addr::new(192, 0, 2, host)))
        .collect();
    let questions = lookup
        .questions(&addresses, Duration::from_secs(1))
        .expect("questions build");
    let frames: usize = questions.iter().map(|q| q.limits.max_evidence_frames).sum();
    let bytes: usize = questions.iter().map(|q| q.limits.max_evidence_bytes).sum();
    assert_eq!((frames, bytes), (1_000, 1_000 * snap_length));
}

#[test]
fn a_question_that_failed_after_sending_paces_from_the_batchs_end() {
    let failed = batch::Question::<dns::Aggregate> {
        query_name: dns::reverse_name(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        query_type: dns::QueryType::PTR,
        transaction_id: 0,
        status: batch::QuestionStatus::Failed,
        result: None,
        error: None,
    };
    let before = Instant::now();
    let sent_tcp = Stats {
        bytes: 64,
        ..Stats::default()
    };
    let sent = last_batch_send(std::slice::from_ref(&failed), &sent_tcp, Instant::now());
    assert!(sent.is_some_and(|sent| sent >= before), "{sent:?}");
    assert_eq!(
        last_batch_send(&[failed], &Stats::default(), Instant::now()),
        None,
        "a question that failed before sending paces nothing"
    );
}

#[test]
fn a_cancelled_scan_waits_for_and_sends_no_further_batch() {
    let hosts = responding(batch::MAX_QUESTIONS + 1);
    let hour = Duration::from_secs(3600);
    let run = |cancellation: &Cancellation, pause| {
        let mut windows = Vec::new();
        let (names, _) = batched(
            &hosts,
            pause,
            batch::MAX_QUESTIONS,
            Some(Instant::now()),
            Instant::now().checked_add(hour),
            Some(cancellation),
            usize::MAX,
            Instant::now,
            std::thread::sleep,
            |addresses, remaining| {
                windows.push(remaining);
                let lookups = addresses.iter().map(|_| answered(&[])).collect();
                (lookups, Stats::default(), None)
            },
        );
        assert!(
            names.iter().all(Option::is_some),
            "every host keeps a record"
        );
        windows
    };

    let live = run(&Cancellation::default(), Duration::ZERO);
    assert_eq!(live.len(), 2);
    assert!(live.iter().all(|remaining| !remaining.is_zero()));

    // An hour's pause before the second batch would hold the test.
    let cancelled = Cancellation::default();
    cancelled.cancel();
    assert_eq!(run(&cancelled, hour), [Duration::ZERO, Duration::ZERO]);
}

#[test]
fn names_beyond_the_scans_evidence_bytes_are_dropped_and_marked() {
    let held = |name: &str| size_of::<String>() + name.len();
    let mut budget = held("a.example.") + held("b.example.");
    let mut first = answered(&["a.example."]);
    retain_names(&mut first, &mut budget);
    assert_eq!(first.names, ["a.example."]);
    assert!(!first.names_truncated);

    // The budget spans lookups: the next host keeps only what remains.
    let mut second = answered(&["b.example.", "c.example."]);
    retain_names(&mut second, &mut budget);
    assert_eq!(second.names, ["b.example."]);
    assert!(second.names_truncated);
    assert_eq!(budget, 0);

    let mut third = answered(&["d.example."]);
    retain_names(&mut third, &mut budget);
    assert!(third.names.is_empty());
    assert!(third.names_truncated);

    // A lookup without names drops nothing.
    let mut empty = answered(&[]);
    retain_names(&mut empty, &mut budget);
    assert!(!empty.names_truncated);
}

#[test]
fn a_scoped_server_is_refused_before_any_scan() {
    let scoped = ReverseDns {
        server: "fe80::1%eth0".parse().unwrap(),
        server_port: dns::DEFAULT_SERVER_PORT,
        transport: dns::TransportMode::Udp,
    };
    assert!(matches!(
        scoped.validate(&scan_request()),
        Err(super::Error::Dns(dns::Error::ScopedServer { .. }))
    ));
}
