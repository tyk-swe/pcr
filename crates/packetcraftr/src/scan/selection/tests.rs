// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::probe::Endpoint;
use crate::scan::discovery::{Mode, Unresponsive};
use crate::scan::{SctpScan, TcpScan};

fn ports(
    transports: &[PortTransport],
    include: &[u16],
    exclude: &[(Option<PortTransport>, u16)],
) -> PortSelection {
    PortSelection::new(
        transports.to_vec(),
        include
            .iter()
            .map(|number| Term {
                transport: None,
                selector: Selector::Ports(PortSpec::Single(*number)),
            })
            .collect(),
        exclude
            .iter()
            .map(|(transport, number)| Term {
                transport: *transport,
                selector: Selector::Ports(PortSpec::Single(*number)),
            })
            .collect(),
    )
    .unwrap()
}

fn discovery(
    mode: Mode,
    probes: &[DiscoveryProbe],
    ports: Option<PortSelection>,
) -> DiscoverySelection {
    let probes = Probes::new(probes.to_vec(), ports, None).unwrap();
    match mode {
        Mode::Before => DiscoverySelection::Before {
            probes,
            unresponsive: Unresponsive::Skip,
        },
        Mode::Only => DiscoverySelection::Only(probes),
        _ => panic!("test uses a running discovery mode"),
    }
}

fn prepare(scan: Option<EndpointSelection>, discovery: DiscoverySelection) -> Prepared {
    Selection::new(scan, discovery)
        .prepare(
            crate::scan::catalog::bundled(),
            1024,
            TcpScan::Syn,
            SctpScan::Init,
            false,
        )
        .unwrap()
}

#[test]
fn discovery_construction_rejects_probe_selector_mismatches() {
    for (probes, ports, protocols) in [
        (vec![DiscoveryProbe::Tcp], None, None),
        (
            vec![DiscoveryProbe::Icmp],
            Some(ports(&[PortTransport::Tcp], &[80], &[])),
            None,
        ),
        (vec![DiscoveryProbe::Ip], None, None),
        (
            vec![DiscoveryProbe::Icmp],
            None,
            Some(IpProtocolSelection {
                include: vec![IpProtocolSpec::Single(1)],
                exclude: Vec::new(),
            }),
        ),
    ] {
        assert!(matches!(
            Probes::new(probes, ports, protocols),
            Err(Error::InvalidDiscovery { .. })
        ));
    }
    assert!(
        Probes::new(
            vec![DiscoveryProbe::Tcp],
            Some(ports(&[PortTransport::Tcp], &[80], &[])),
            None,
        )
        .is_ok()
    );
}

#[test]
fn fully_excluded_port_and_protocol_selections_reject() {
    for endpoint in [
        EndpointSelection::Ports(ports(
            &[PortTransport::Tcp, PortTransport::Udp],
            &[1024],
            &[(None, 1024)],
        )),
        EndpointSelection::IpProtocols(IpProtocolSelection {
            include: vec![IpProtocolSpec::Single(1)],
            exclude: vec![IpProtocolSpec::Single(1)],
        }),
    ] {
        assert!(prepare_result(endpoint, DiscoverySelection::Omitted).is_err());
    }
}

#[test]
fn discovery_and_scan_share_transport_exclusions_independently() {
    let exclude = [
        (Some(PortTransport::Udp), 53),
        (Some(PortTransport::Tcp), 80),
    ];
    let discovery_ports = ports(&[PortTransport::Udp], &[53, 54], &exclude);
    let scan_ports = ports(&[PortTransport::Tcp], &[53, 80], &exclude);
    let prepared = prepare(
        Some(EndpointSelection::Ports(scan_ports)),
        discovery(Mode::Before, &[DiscoveryProbe::Udp], Some(discovery_ports)),
    );
    assert_eq!(prepared.endpoints(), [Endpoint::Tcp { port: 53 }]);
    assert_eq!(prepared.excluded_endpoints(), 1);
    assert_eq!(prepared.discovery().probes(), [Endpoint::Udp { port: 54 }]);
    assert_eq!(prepared.discovery_excluded(), 1);
}

#[test]
fn discovery_excludes_each_tcp_variant_once_without_duplicate_probes() {
    let prepared = prepare(
        None,
        discovery(
            Mode::Only,
            &[
                DiscoveryProbe::Tcp,
                DiscoveryProbe::TcpAck,
                DiscoveryProbe::Tcp,
                DiscoveryProbe::TcpAck,
            ],
            Some(ports(
                &[PortTransport::Tcp],
                &[22, 22, 53],
                &[(Some(PortTransport::Tcp), 53)],
            )),
        ),
    );
    assert!(prepared.endpoints().is_empty());
    assert_eq!(
        prepared.discovery().probes(),
        [Endpoint::Tcp { port: 22 }, Endpoint::TcpAck { port: 22 }]
    );
    assert_eq!(prepared.discovery_excluded(), 2);
}

#[test]
fn discovery_keeps_named_icmp_kinds_once_in_first_seen_order() {
    let prepared = prepare(
        None,
        DiscoverySelection::Only(
            Probes::new(
                vec![
                    DiscoveryProbe::Icmp,
                    DiscoveryProbe::IcmpTimestamp,
                    DiscoveryProbe::IcmpNetmask,
                    DiscoveryProbe::Icmp,
                    DiscoveryProbe::IcmpTimestamp,
                    DiscoveryProbe::IcmpNetmask,
                ],
                None,
                None,
            )
            .unwrap(),
        ),
    );
    assert_eq!(
        prepared.discovery().probes(),
        [
            Endpoint::Icmp,
            Endpoint::IcmpTimestamp,
            Endpoint::IcmpNetmask
        ]
    );
}

#[test]
fn mixed_discovery_and_scan_budget_counts_distinct_endpoints_once() {
    let result = Selection::new(
        Some(EndpointSelection::Ports(ports(
            &[PortTransport::Tcp],
            &[53],
            &[],
        ))),
        discovery(
            Mode::Before,
            &[DiscoveryProbe::TcpAck, DiscoveryProbe::Udp],
            Some(ports(&[PortTransport::Tcp, PortTransport::Udp], &[53], &[])),
        ),
    )
    .prepare(
        crate::scan::catalog::bundled(),
        2,
        TcpScan::Syn,
        SctpScan::Init,
        false,
    );
    assert!(matches!(
        result,
        Err(Error::InvalidLimit { field: "ports", .. })
    ));
}

#[test]
fn expansion_preserves_transport_identity_and_catalog_lookup() {
    let catalog = crate::scan::catalog::bundled();
    let tcp = catalog
        .entries
        .iter()
        .find(|entry| entry.transport == packetcraftr_core::document::port_catalog::Transport::Tcp)
        .unwrap();
    let udp = catalog
        .entries
        .iter()
        .find(|entry| entry.transport == packetcraftr_core::document::port_catalog::Transport::Udp)
        .unwrap();
    let selection = PortSelection::new(
        vec![PortTransport::Tcp, PortTransport::Udp, PortTransport::Sctp],
        vec![
            Term {
                transport: None,
                selector: Selector::Name(tcp.name.to_owned()),
            },
            Term {
                transport: Some(PortTransport::Udp),
                selector: Selector::Name(udp.name.to_owned()),
            },
        ],
        Vec::new(),
    )
    .unwrap();
    let prepared = prepare(
        Some(EndpointSelection::Ports(selection)),
        DiscoverySelection::Omitted,
    );
    assert_eq!(
        prepared.endpoints(),
        [
            Endpoint::Tcp { port: tcp.port },
            Endpoint::Udp { port: udp.port },
        ]
    );
    assert!(
        PortSelection::new(
            vec![PortTransport::Tcp],
            vec![Term {
                transport: Some(PortTransport::Udp),
                selector: Selector::Ports(PortSpec::Single(53)),
            }],
            Vec::new(),
        )
        .is_ok()
    );
}

#[test]
fn ranges_reject_descending_input_and_exclude_before_expansion_budget() {
    assert!(PortSpec::new(10, 9).is_err());
    assert!(IpProtocolSpec::new(10, 9).is_err());
    let prepared = prepare(
        Some(EndpointSelection::IpProtocols(IpProtocolSelection {
            include: vec![IpProtocolSpec::new(1, 6).unwrap()],
            exclude: vec![IpProtocolSpec::Single(6)],
        })),
        DiscoverySelection::Omitted,
    );
    assert_eq!(
        prepared.scan().unwrap().ip_protocols().collect::<Vec<_>>(),
        [1, 2, 3, 4, 5]
    );
    assert_eq!(prepared.excluded_endpoints(), 1);
    let result = prepare_result(
        EndpointSelection::IpProtocols(IpProtocolSelection {
            include: vec![IpProtocolSpec::Single(1)],
            exclude: vec![IpProtocolSpec::Single(1)],
        }),
        DiscoverySelection::Omitted,
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("IP-protocol exclusions removed every selected IP protocol")
    );
    let result = prepare_result(
        EndpointSelection::Ports(ports(&[PortTransport::Tcp], &[80], &[(None, 80)])),
        DiscoverySelection::Omitted,
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("port exclusions removed every selected port")
    );
}

#[test]
fn transport_labels_name_every_applicable_transport_in_catalog_errors() {
    let name = "test-missing-transport-name";
    assert!(
        !crate::scan::catalog::bundled()
            .entries
            .iter()
            .any(|entry| entry.name == name)
    );
    for (transports, label) in [
        (vec![PortTransport::Sctp], "for sctp"),
        (
            vec![PortTransport::Tcp, PortTransport::Udp],
            "for tcp or udp",
        ),
        (
            vec![PortTransport::Tcp, PortTransport::Sctp],
            "for tcp or sctp",
        ),
    ] {
        let selection = PortSelection::new(
            transports,
            vec![Term {
                transport: None,
                selector: Selector::Name(name.to_owned()),
            }],
            Vec::new(),
        )
        .unwrap();
        let result = prepare_result(
            EndpointSelection::Ports(selection),
            DiscoverySelection::Omitted,
        );
        let error = result.unwrap_err().to_string();
        assert!(error.contains(label), "{error}");
    }
}

#[test]
fn omitted_scan_has_no_endpoints() {
    let prepared = Selection::new(None, DiscoverySelection::Omitted)
        .prepare(
            crate::scan::catalog::bundled(),
            1024,
            TcpScan::Syn,
            SctpScan::Init,
            true,
        )
        .unwrap();
    assert!(prepared.endpoints().is_empty());
    assert!(!prepared.publish_scan());
}

#[test]
fn discovery_only_rejects_scan_endpoints_but_accepts_shared_exclusions() {
    let only = || {
        discovery(
            Mode::Only,
            &[DiscoveryProbe::TcpAck],
            Some(ports(&[PortTransport::Tcp], &[80], &[])),
        )
    };
    for scan in [
        EndpointSelection::Ports(ports(&[PortTransport::Tcp], &[80], &[])),
        EndpointSelection::Icmp,
        EndpointSelection::IpProtocols(IpProtocolSelection {
            include: vec![IpProtocolSpec::Single(1)],
            exclude: Vec::new(),
        }),
    ] {
        assert!(matches!(
            prepare_result(scan, only()),
            Err(Error::InvalidDiscovery { message }) if message.contains("discovery only")
        ));
    }
    let prepared = prepare(
        Some(EndpointSelection::Ports(ports(
            &[PortTransport::Tcp],
            &[],
            &[(Some(PortTransport::Tcp), 80)],
        ))),
        only(),
    );
    assert_eq!(prepared.endpoints(), []);
}

fn prepare_result(
    scan: EndpointSelection,
    discovery: DiscoverySelection,
) -> Result<Prepared, Error> {
    Selection::new(Some(scan), discovery).prepare(
        crate::scan::catalog::bundled(),
        1024,
        TcpScan::Syn,
        SctpScan::Init,
        false,
    )
}

#[test]
fn no_terms_has_no_executable_scan_stage_before_mode_validation() {
    let empty = EndpointSelection::Ports(ports(&[PortTransport::Tcp], &[], &[]));
    for listing in [false, true] {
        let result = Selection::new(Some(empty.clone()), DiscoverySelection::Omitted).prepare(
            crate::scan::catalog::bundled(),
            1024,
            TcpScan::Ack,
            SctpScan::Init,
            listing,
        );
        assert!(matches!(
            result,
            Err(Error::InvalidLimit {
                field: "tcp_scan",
                ..
            })
        ));
    }
    for scan in [
        None,
        Some(EndpointSelection::Ports(ports(
            &[PortTransport::Tcp],
            &[],
            &[],
        ))),
    ] {
        assert!(
            Selection::new(scan, DiscoverySelection::Omitted)
                .prepare(
                    crate::scan::catalog::bundled(),
                    1024,
                    TcpScan::Syn,
                    SctpScan::Init,
                    true,
                )
                .unwrap()
                .endpoints()
                .is_empty()
        );
    }
}

#[test]
fn port_transport_labels_preserve_identity_for_selection_diagnostics() {
    assert_eq!(PortTransport::Tcp.to_string(), "tcp");
    assert_eq!(PortTransport::Udp.to_string(), "udp");
    assert_eq!(PortTransport::Sctp.as_str(), "sctp");
}

#[test]
fn selection_checks_observable_term_presence_and_budgets() {
    for selection in [
        EndpointSelection::Icmp,
        EndpointSelection::Ports(ports(&[PortTransport::Tcp], &[], &[])),
        EndpointSelection::IpProtocols(IpProtocolSelection {
            include: Vec::new(),
            exclude: Vec::new(),
        }),
    ] {
        assert!(!selection.has_terms());
    }
    assert!(EndpointSelection::Ports(ports(&[PortTransport::Tcp], &[], &[(None, 80)])).has_terms());
    assert!(
        EndpointSelection::IpProtocols(IpProtocolSelection {
            include: Vec::new(),
            exclude: vec![IpProtocolSpec::Single(6)],
        })
        .has_terms()
    );
    let prepared = Selection::new(Some(EndpointSelection::Icmp), DiscoverySelection::Omitted)
        .prepare(
            crate::scan::catalog::bundled(),
            1024,
            TcpScan::Syn,
            SctpScan::Init,
            true,
        )
        .unwrap();
    assert!(!prepared.publish_scan());
    let result = Selection::new(
        Some(EndpointSelection::Ports(ports(
            &[PortTransport::Tcp],
            &[80, 81],
            &[(None, 81)],
        ))),
        DiscoverySelection::Omitted,
    )
    .prepare(
        crate::scan::catalog::bundled(),
        1,
        TcpScan::Syn,
        SctpScan::Init,
        false,
    )
    .unwrap();
    assert_eq!(result.endpoints(), [Endpoint::Tcp { port: 80 }]);
    assert_eq!(result.excluded_endpoints(), 1);
    for budget in [0, 1, 2] {
        let selection =
            EndpointSelection::Ports(ports(&[PortTransport::Tcp], &[1, 2], &[(None, 2)]));
        let result = Selection::new(Some(selection), DiscoverySelection::Omitted).prepare(
            crate::scan::catalog::bundled(),
            budget,
            TcpScan::Syn,
            SctpScan::Init,
            false,
        );
        assert_eq!(result.is_err(), budget < 1);
    }
    for selection in [
        EndpointSelection::Ports(ports(&[PortTransport::Tcp], &[80], &[])),
        EndpointSelection::IpProtocols(IpProtocolSelection {
            include: vec![IpProtocolSpec::Single(1)],
            exclude: Vec::new(),
        }),
    ] {
        assert!(prepare(Some(selection), DiscoverySelection::Omitted).publish_scan());
    }
    let transport_mismatch = EndpointSelection::Ports(
        PortSelection::new(
            vec![PortTransport::Tcp, PortTransport::Udp],
            vec![Term {
                transport: Some(PortTransport::Sctp),
                selector: Selector::Ports(PortSpec::Single(9898)),
            }],
            Vec::new(),
        )
        .unwrap(),
    );
    assert!(prepare_result(transport_mismatch, DiscoverySelection::Omitted).is_err());
    let excess_terms = || {
        vec![
            Term {
                transport: None,
                selector: Selector::Ports(PortSpec::Single(80)),
            };
            MAX_PORT_TERMS + 1
        ]
    };
    assert!(PortSelection::new(vec![PortTransport::Tcp], excess_terms(), Vec::new()).is_err());
    assert!(
        PortSelection::new(
            vec![PortTransport::Tcp],
            vec![Term {
                transport: None,
                selector: Selector::Name("test-name".into()),
            }],
            Vec::new(),
        )
        .is_ok()
    );
    assert!(PortSelection::new(vec![PortTransport::Tcp], excess_terms(), excess_terms()).is_err());
    let mut terms = excess_terms();
    terms.pop();
    let limit = PortSelection::new(
        vec![PortTransport::Tcp],
        terms[..MAX_PORT_TERMS - 1].to_vec(),
        terms[MAX_PORT_TERMS - 1..].to_vec(),
    );
    assert!(limit.is_ok());
    assert!(PortSelection::new(vec![PortTransport::Tcp], terms.clone(), terms).is_err());
}

#[test]
fn exclusions_owned_by_scan_are_not_dropped_by_discovery() {
    let prepared = prepare(
        Some(EndpointSelection::Ports(ports(
            &[PortTransport::Tcp],
            &[80],
            &[(Some(PortTransport::Udp), 80)],
        ))),
        discovery(
            Mode::Before,
            &[DiscoveryProbe::Udp],
            Some(ports(&[PortTransport::Udp], &[53], &[])),
        ),
    );
    assert_eq!(prepared.endpoints(), [Endpoint::Tcp { port: 80 }]);
    assert_eq!(prepared.discovery().probes(), [Endpoint::Udp { port: 53 }]);
    assert_eq!(prepared.discovery_excluded(), 0);
}

#[test]
fn catalog_names_and_presets_preserve_transport_specific_expansion() {
    let catalog = crate::scan::catalog::bundled();
    let tcp = catalog
        .entries
        .iter()
        .find(|entry| entry.transport == packetcraftr_core::document::port_catalog::Transport::Tcp)
        .unwrap();
    let selection = PortSelection::new(
        vec![PortTransport::Tcp, PortTransport::Udp],
        vec![Term {
            transport: None,
            selector: Selector::Name(tcp.name.clone()),
        }],
        Vec::new(),
    )
    .unwrap();
    let expected_name_endpoints = [PortTransport::Tcp, PortTransport::Udp]
        .into_iter()
        .filter_map(|transport| {
            let catalog_transport = match transport {
                PortTransport::Tcp => packetcraftr_core::document::port_catalog::Transport::Tcp,
                _ => packetcraftr_core::document::port_catalog::Transport::Udp,
            };
            let port = catalog
                .named(catalog_transport, &tcp.name)
                .map(|entry| entry.port)?;
            Some(match transport {
                PortTransport::Tcp => Endpoint::Tcp { port },
                _ => Endpoint::Udp { port },
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        prepare(
            Some(EndpointSelection::Ports(selection)),
            DiscoverySelection::Omitted,
        )
        .endpoints(),
        expected_name_endpoints
    );
    let preset = catalog.presets.first().unwrap();
    let selection = PortSelection::new(
        vec![PortTransport::Tcp, PortTransport::Udp],
        vec![Term {
            transport: None,
            selector: Selector::Preset(preset.name.clone()),
        }],
        Vec::new(),
    )
    .unwrap();
    let expected = preset
        .members()
        .map(|(transport, name)| {
            let entry = catalog.named(transport, name).unwrap();
            match transport {
                packetcraftr_core::document::port_catalog::Transport::Tcp => {
                    Endpoint::Tcp { port: entry.port }
                }
                _ => Endpoint::Udp { port: entry.port },
            }
        })
        .collect::<Vec<_>>();
    let prepared = prepare(
        Some(EndpointSelection::Ports(selection)),
        DiscoverySelection::Omitted,
    );
    let actual = prepared
        .endpoints()
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let expected_set = expected
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(actual, expected_set);
    let sctp_name = PortSelection::new(
        vec![PortTransport::Sctp],
        vec![Term {
            transport: None,
            selector: Selector::Name(tcp.name.clone()),
        }],
        Vec::new(),
    )
    .unwrap();
    assert!(
        prepare_result(
            EndpointSelection::Ports(sctp_name),
            DiscoverySelection::Omitted,
        )
        .is_err()
    );
}

#[test]
fn sctp_zero_endpoint_is_rejected_but_tcp_zero_is_valid() {
    assert_eq!(
        prepare(
            Some(EndpointSelection::Ports(ports(
                &[PortTransport::Tcp],
                &[0],
                &[],
            ))),
            DiscoverySelection::Omitted,
        )
        .endpoints(),
        [Endpoint::Tcp { port: 0 }]
    );
    assert!(matches!(
        prepare_result(
            EndpointSelection::Ports(ports(&[PortTransport::Sctp], &[0], &[])),
            DiscoverySelection::Omitted,
        ),
        Err(Error::InvalidPort { .. })
    ));
}

#[test]
fn diagnostic_modes_require_matching_scan_endpoints_even_for_discovery_only() {
    for scan in [
        Selection::new(
            Some(EndpointSelection::Ports(ports(
                &[PortTransport::Udp],
                &[53],
                &[],
            ))),
            DiscoverySelection::Omitted,
        ),
        Selection::new(
            None,
            discovery(
                Mode::Only,
                &[DiscoveryProbe::Tcp],
                Some(ports(&[PortTransport::Tcp], &[80], &[])),
            ),
        ),
    ] {
        assert!(
            scan.prepare(
                crate::scan::catalog::bundled(),
                1024,
                TcpScan::Ack,
                SctpScan::Init,
                false,
            )
            .is_err()
        );
    }
}

#[test]
fn unrelated_discovery_exclusions_do_not_invalidate_scan() {
    let prepared = prepare(
        Some(EndpointSelection::Ports(ports(
            &[PortTransport::Tcp],
            &[80],
            &[],
        ))),
        discovery(
            Mode::Before,
            &[DiscoveryProbe::Udp],
            Some(ports(
                &[PortTransport::Udp],
                &[53],
                &[(Some(PortTransport::Tcp), 80)],
            )),
        ),
    );
    assert_eq!(prepared.endpoints(), [Endpoint::Tcp { port: 80 }]);
    assert_eq!(prepared.excluded_endpoints(), 0);
}
