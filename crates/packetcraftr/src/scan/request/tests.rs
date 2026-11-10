// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use crate::scan::{
    Base, DiscoverySelection, EndpointSelection, Limits, Request, Schedule, Selection, Targets,
    TcpScan, Udp, catalog,
};
use crate::target::Family;

fn base() -> Base {
    endpoints_base(crate::scan::PortTransport::Tcp)
}

fn endpoints_base(transport: crate::scan::PortTransport) -> Base {
    let scan = vec![80, 53]
        .into_iter()
        .map(|port| crate::scan::Term {
            transport: None,
            selector: crate::scan::Selector::Ports(crate::scan::PortSpec::Single(port)),
        })
        .collect();
    let endpoints = crate::scan::PortSelection::new(vec![transport], scan, Vec::new()).unwrap();
    let selection = Selection::new(
        Some(EndpointSelection::Ports(endpoints)),
        DiscoverySelection::Omitted,
    )
    .prepare(
        catalog::bundled(),
        crate::scan::DEFAULT_MAX_PORTS,
        TcpScan::Syn,
        Default::default(),
        false,
    )
    .unwrap();
    Base {
        selection,
        targets: Targets {
            selection: "192.0.2.1".parse::<crate::target::Target>().unwrap().into(),
            sources: vec!["inventory:1".to_owned()],
            family: Family::Any,
        },
        udp: Udp {
            payload: bytes::Bytes::new(),
            profiles: Default::default(),
        },
        schedule: Schedule {
            max_in_flight: 1,
            attempts: 1,
            adaptive: None,
            timeout: Duration::from_millis(100),
            probes_per_second: None,
        },
        limits: Limits::default(),
    }
}

#[test]
fn checked_construction_admits_udp_configuration_only_with_udp_probes() {
    let mut udp = endpoints_base(crate::scan::PortTransport::Udp);
    udp.udp.payload = bytes::Bytes::from_static(b"payload");
    udp.udp.profiles = crate::scan::profile::compile(vec![
        packetcraftr_core::document::udp_profiles::Assignment {
            ports: vec![53],
            profile: packetcraftr_core::document::udp_profiles::Config {
                name: "test".to_owned(),
                request: packetcraftr_core::document::udp_profiles::Payload::Bytes {
                    data: bytes::Bytes::from_static(b"profile"),
                },
                response: packetcraftr_core::document::udp_profiles::ResponseCheck::Any {},
            },
        },
    ])
    .unwrap();
    let request = Request::new(udp.clone(), Default::default(), Default::default()).unwrap();
    assert!(request.probes(crate::probe::Transport::Udp));
    assert!(!request.probes(crate::probe::Transport::Tcp));
    assert_eq!(request.udp_payload().as_ref(), b"payload");
    assert_eq!(request.udp_profiles().len(), 1);

    let mut tcp = base();
    tcp.udp = udp.udp.clone();
    assert!(matches!(
        Request::new(tcp, Default::default(), Default::default()),
        Err(crate::scan::Error::InvalidLimit {
            field: "udp_profiles",
            ..
        })
    ));

    udp.selection = Selection::new(
        None,
        DiscoverySelection::Only(
            crate::scan::Probes::new(
                vec![crate::scan::DiscoveryProbe::Udp],
                Some(
                    crate::scan::PortSelection::new(
                        vec![crate::scan::PortTransport::Udp],
                        vec![crate::scan::Term {
                            transport: None,
                            selector: crate::scan::Selector::Ports(crate::scan::PortSpec::Single(
                                53,
                            )),
                        }],
                        Vec::new(),
                    )
                    .unwrap(),
                ),
                None,
            )
            .unwrap(),
        ),
    )
    .prepare(
        catalog::bundled(),
        crate::scan::DEFAULT_MAX_PORTS,
        TcpScan::Syn,
        Default::default(),
        false,
    )
    .unwrap();
    let request = Request::new(udp, Default::default(), Default::default()).unwrap();
    assert!(request.probes(crate::probe::Transport::Udp));
}

#[test]
fn checked_requests_allow_udp_profiles_only_at_a_udp_endpoint_boundary() {
    for port_count in [1, 4096] {
        let assignment = packetcraftr_core::document::udp_profiles::Assignment {
            ports: (0..port_count).collect(),
            profile: packetcraftr_core::document::udp_profiles::Config {
                name: "test".to_owned(),
                request: packetcraftr_core::document::udp_profiles::Payload::Bytes {
                    data: bytes::Bytes::from_static(b"profile"),
                },
                response: packetcraftr_core::document::udp_profiles::ResponseCheck::Any {},
            },
        };
        let profiles = crate::scan::profile::compile(vec![assignment]).unwrap();
        let mut tcp = base();
        tcp.udp.profiles = profiles.clone();
        assert!(Request::new(tcp, Default::default(), Default::default()).is_err());
        let mut udp = endpoints_base(crate::scan::PortTransport::Udp);
        udp.udp.profiles = profiles;
        assert!(Request::new(udp, Default::default(), Default::default()).is_ok());
    }
}

#[test]
fn checked_construction_enforces_udp_payload_size_and_transport_boundaries() {
    let mut udp = endpoints_base(crate::scan::PortTransport::Udp);
    udp.udp.payload = bytes::Bytes::from(vec![0; crate::scan::MAX_UDP_PAYLOAD_BYTES]);
    assert!(Request::new(udp.clone(), Default::default(), Default::default()).is_ok());
    udp.udp.payload = bytes::Bytes::from(vec![0; crate::scan::MAX_UDP_PAYLOAD_BYTES + 1]);
    assert!(Request::new(udp, Default::default(), Default::default()).is_err());
    let mut tcp = base();
    tcp.udp.payload = bytes::Bytes::from(vec![1]);
    assert!(Request::new(tcp, Default::default(), Default::default()).is_err());
}

#[test]
fn protocol_only_requests_reject_udp_configuration_after_checked_planning() {
    let selection = Selection::new(
        Some(EndpointSelection::IpProtocols(
            crate::scan::IpProtocolSelection {
                include: vec![crate::scan::IpProtocolSpec::Single(1)],
                exclude: Vec::new(),
            },
        )),
        DiscoverySelection::Omitted,
    )
    .prepare(
        catalog::bundled(),
        crate::scan::DEFAULT_MAX_PORTS,
        TcpScan::Syn,
        Default::default(),
        false,
    )
    .unwrap();
    let mut base = base();
    base.selection = selection;
    assert!(Request::new(base.clone(), Default::default(), Default::default()).is_ok());
    base.udp.payload = bytes::Bytes::from_static(b"UDP only");
    assert!(Request::new(base, Default::default(), Default::default()).is_err());
}

#[test]
fn checked_requests_reject_profiles_above_the_document_storage_budget() {
    let profile = |port, mask: Option<Vec<u8>>| {
        let check = packetcraftr_core::document::udp_profiles::ByteCheck {
            offset: 0,
            data: bytes::Bytes::from(vec![0; 1024]),
            mask: mask.map(bytes::Bytes::from),
        };
        packetcraftr_core::document::udp_profiles::Assignment {
            ports: vec![port],
            profile: packetcraftr_core::document::udp_profiles::Config {
                name: "test".to_owned(),
                request: packetcraftr_core::document::udp_profiles::Payload::Bytes {
                    data: bytes::Bytes::from(vec![port as u8; 1024]),
                },
                response: packetcraftr_core::document::udp_profiles::ResponseCheck::Bytes {
                    checks: vec![check],
                    min_length: 1024,
                    max_length: 1024,
                },
            },
        }
    };
    let mut shared = endpoints_base(crate::scan::PortTransport::Udp);
    shared.udp.profiles = crate::scan::profile::compile(vec![profile(53, None)]).unwrap();
    let first = shared.udp.profiles.values().next().unwrap().clone();
    shared.udp.profiles.insert(54, first.clone());
    shared.udp.profiles.insert(55, first);
    assert!(Request::new(shared, Default::default(), Default::default()).is_ok());
    let mut multiple = endpoints_base(crate::scan::PortTransport::Udp);
    for port in 4096..8192 {
        multiple
            .udp
            .profiles
            .extend(crate::scan::profile::compile(vec![profile(port, None)]).unwrap());
    }
    assert!(Request::new(multiple, Default::default(), Default::default()).is_err());
    let large = endpoints_base(crate::scan::PortTransport::Udp);
    assert_eq!(large.selection.excluded_endpoints(), 0);
    let mut large = large;
    let mut mask = Some(vec![0; 1024]);
    for port in 0..4096 {
        large
            .udp
            .profiles
            .extend(crate::scan::profile::compile(vec![profile(port, mask.take())]).unwrap());
    }
    assert!(Request::new(large, Default::default(), Default::default()).is_err());
}

#[test]
fn checked_requests_enforce_exact_aggregate_profile_storage() {
    let profile = |port| packetcraftr_core::document::udp_profiles::Assignment {
        ports: vec![port],
        profile: packetcraftr_core::document::udp_profiles::Config {
            name: "x".repeat(21),
            request: packetcraftr_core::document::udp_profiles::Payload::Bytes {
                data: bytes::Bytes::from(vec![port as u8; 65_003]),
            },
            response: packetcraftr_core::document::udp_profiles::ResponseCheck::Any {},
        },
    };
    let count = u16::try_from(1024 * 1024 / 65_536).unwrap();
    let allocate = |start| {
        (start..start + count)
            .flat_map(|port| crate::scan::profile::compile(vec![profile(port)]).unwrap())
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let mut at_limit = endpoints_base(crate::scan::PortTransport::Udp);
    at_limit.udp.profiles = allocate(0);
    assert!(Request::new(at_limit.clone(), Default::default(), Default::default()).is_ok());
    at_limit.udp.profiles.extend(allocate(count));
    assert!(Request::new(at_limit, Default::default(), Default::default()).is_err());
}

#[test]
fn checked_workflow_revalidation_rejects_invalid_capture_limits() {
    let request = Request::new(base(), Default::default(), Default::default()).unwrap();
    let invalid = crate::exchange::Collection {
        max_responses: usize::MAX,
        ..Default::default()
    };
    assert!(request.with_workflow(Default::default(), invalid).is_err());
}
#[test]
fn checked_construction_admits_valid_requests_and_rejects_invalid_configuration() {
    let request = Request::new(base(), Default::default(), Default::default()).unwrap();
    assert_eq!(
        request.endpoints(),
        [
            crate::probe::Endpoint::Tcp { port: 80 },
            crate::probe::Endpoint::Tcp { port: 53 },
        ]
    );
    assert_eq!(request.target_sources(), ["inventory:1"]);
    assert_eq!(request.selection_excluded_endpoints(), 0);
    assert_eq!(request.discovery_excluded(), 0);

    let mut exact_budget = base();
    exact_budget.limits.max_ports = 2;
    assert!(Request::new(exact_budget, Default::default(), Default::default()).is_ok());
    let mut insufficient_budget = base();
    insufficient_budget.limits.max_ports = 1;
    let mut empty_sources = base();
    empty_sources.targets.sources = Vec::new();
    empty_sources.targets.selection.exclude = Vec::new();
    empty_sources.targets.selection.include = Vec::new();
    let mut wrong_transport = base();
    wrong_transport.udp.payload = bytes::Bytes::from_static(b"not UDP");
    let mut empty_scan = base();
    empty_scan.selection = Selection::new(None, DiscoverySelection::Omitted)
        .prepare(
            catalog::bundled(),
            crate::scan::DEFAULT_MAX_PORTS,
            TcpScan::Syn,
            Default::default(),
            true,
        )
        .unwrap();
    assert!(matches!(
        Request::new(empty_scan, Default::default(), Default::default()),
        Err(crate::scan::Error::InvalidPort { .. })
    ));

    let mut invalid = Vec::new();
    let mut exact_source_length = base();
    exact_source_length.targets.sources = vec!["a".repeat(4096)];
    assert!(Request::new(exact_source_length, Default::default(), Default::default()).is_ok());
    let mut exact_port_limit = base();
    exact_port_limit.limits.max_ports = usize::from(u16::MAX) + 1;
    assert!(Request::new(exact_port_limit, Default::default(), Default::default()).is_ok());
    let mut in_flight_boundary = base();
    in_flight_boundary.schedule.max_in_flight = crate::scan::MAX_IN_FLIGHT;
    assert!(Request::new(in_flight_boundary, Default::default(), Default::default()).is_ok());
    for limit in [0, usize::from(u16::MAX) + 2, usize::MAX] {
        let mut candidate = base();
        candidate.limits.max_ports = limit;
        invalid.push(candidate);
    }
    for value in [0, crate::scan::MAX_IN_FLIGHT + 1] {
        let mut candidate = base();
        candidate.schedule.max_in_flight = value;
        invalid.push(candidate);
    }
    for value in [0, crate::scan::MAX_PROBE_ATTEMPTS + 1] {
        let mut candidate = base();
        candidate.schedule.attempts = value;
        invalid.push(candidate);
    }
    for value in [
        vec!["extra:1".to_owned(), "extra:2".to_owned()],
        vec![String::new()],
        vec!["a".repeat(4097)],
    ] {
        let mut candidate = base();
        candidate.targets.sources = value;
        invalid.push(candidate);
    }
    invalid.extend([insufficient_budget, empty_sources, wrong_transport]);
    for candidate in invalid {
        assert!(Request::new(candidate, Default::default(), Default::default()).is_err());
    }
}

#[test]
fn checked_requests_preserve_scan_and_discovery_exclusion_counts() {
    let ports = |values: &[u16], excluded: Option<u16>| {
        crate::scan::PortSelection::new(
            vec![crate::scan::PortTransport::Tcp],
            values
                .iter()
                .map(|port| crate::scan::Term {
                    transport: None,
                    selector: crate::scan::Selector::Ports(crate::scan::PortSpec::Single(*port)),
                })
                .collect(),
            excluded
                .map(|port| crate::scan::Term {
                    transport: None,
                    selector: crate::scan::Selector::Ports(crate::scan::PortSpec::Single(port)),
                })
                .into_iter()
                .collect(),
        )
        .unwrap()
    };
    let discovery = crate::scan::Probes::new(
        vec![crate::scan::DiscoveryProbe::Tcp],
        Some(ports(&[53, 54], Some(54))),
        None,
    )
    .unwrap();
    let mut base = base();
    base.selection = Selection::new(
        Some(EndpointSelection::Ports(ports(&[80, 443], Some(443)))),
        DiscoverySelection::Before {
            probes: discovery,
            unresponsive: Default::default(),
        },
    )
    .prepare(
        catalog::bundled(),
        crate::scan::DEFAULT_MAX_PORTS,
        TcpScan::Syn,
        Default::default(),
        false,
    )
    .unwrap();
    let request = Request::new(base, Default::default(), Default::default()).unwrap();
    assert_eq!(request.selection_excluded_endpoints(), 1);
    assert_eq!(request.discovery_excluded(), 1);
}
