// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Catalog presets, names, numeric ports, and exclusions across transports.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr::probe::{ProbeEndpoint, Transport};
use packetcraftr::scan::{
    self, PortSelection, PortSpec, Request, Selected, Selector, Term, catalog, select_endpoints,
};
use packetcraftr::{Client, policy::Policy, target::Target};
use packetcraftr_core::protocol::builtin;
use packetcraftr_netio::link::Mode;

use crate::common;
use common::responder::{Io, Routes, State};

const TCP: Option<Transport> = Some(Transport::Tcp);
const UDP: Option<Transport> = Some(Transport::Udp);

fn term(transport: Option<Transport>, selector: &str) -> Term {
    let selector = if let Some(preset) = selector.strip_prefix('@') {
        Selector::Preset(preset.to_owned())
    } else if let Some((Ok(start), Ok(end))) = selector
        .split_once('-')
        .map(|(start, end)| (start.parse(), end.parse()))
    {
        Selector::Ports(PortSpec::RangeInclusive { start, end })
    } else if let Ok(port) = selector.parse() {
        Selector::Ports(PortSpec::Single(port))
    } else {
        Selector::Name(selector.to_owned())
    };
    Term {
        transport,
        selector,
    }
}

fn select(
    transports: &[Transport],
    include: &[(Option<Transport>, &str)],
    exclude: &[(Option<Transport>, &str)],
    max_ports: usize,
) -> Result<Selected, scan::Error> {
    let terms = |terms: &[(Option<Transport>, &str)]| {
        terms
            .iter()
            .map(|(transport, selector)| term(*transport, selector))
            .collect()
    };
    select_endpoints(
        &PortSelection {
            transports: transports.to_vec(),
            include: terms(include),
            exclude: terms(exclude),
        },
        catalog::bundled(),
        max_ports,
    )
}

fn tcp(port: u16) -> ProbeEndpoint {
    ProbeEndpoint::Tcp { port }
}

fn udp(port: u16) -> ProbeEndpoint {
    ProbeEndpoint::Udp { port }
}

#[test]
fn selections_expand_in_term_order_and_keep_transports_apart() {
    type Terms<'a> = &'a [(Option<Transport>, &'a str)];
    /// Transports, includes, exclusions, expected endpoints, excluded count.
    type Case<'a> = (
        &'a [Transport],
        Terms<'a>,
        Terms<'a>,
        Vec<ProbeEndpoint>,
        usize,
    );
    let both = [Transport::Tcp, Transport::Udp];
    let cases: &[Case] = &[
        (
            &[Transport::Tcp],
            &[(None, "@web")],
            &[],
            vec![tcp(80), tcp(443)],
            0,
        ),
        (
            &[Transport::Tcp],
            &[(None, "ssh"), (None, "http"), (None, "22")],
            &[],
            vec![tcp(22), tcp(80)],
            0,
        ),
        // One name on both transports is two endpoints, never one.
        (&both, &[(None, "dns")], &[], vec![tcp(53), udp(53)], 0),
        (
            &[Transport::Udp, Transport::Tcp],
            &[(None, "@name-services")],
            &[],
            vec![udp(53), udp(5353), udp(137), tcp(53), tcp(853)],
            0,
        ),
        (
            &both,
            &[(TCP, "http"), (UDP, "ntp")],
            &[],
            vec![tcp(80), udp(123)],
            0,
        ),
        (&both, &[(None, "53")], &[(UDP, "53")], vec![tcp(53)], 1),
        (
            &[Transport::Tcp],
            &[(None, "@web")],
            &[(None, "https")],
            vec![tcp(80)],
            1,
        ),
        (
            &[Transport::Udp],
            &[(None, "120-125")],
            &[(None, "ntp"), (None, "999")],
            vec![udp(120), udp(121), udp(122), udp(124), udp(125)],
            1,
        ),
    ];
    for (transports, include, exclude, endpoints, excluded) in cases {
        let selected = select(transports, include, exclude, 1024).unwrap();
        assert_eq!(&selected.endpoints, endpoints, "{include:?} - {exclude:?}");
        assert_eq!(selected.excluded, *excluded, "{include:?} - {exclude:?}");
    }
}

#[test]
fn presets_resolve_through_the_catalog_and_its_names_are_hints() {
    let both = [Transport::Tcp, Transport::Udp];
    let selected = select(&both, &[(None, "@name-services")], &[], 1024).unwrap();
    let preset = catalog::bundled().preset("name-services").unwrap();
    assert_eq!(
        selected.endpoints.len(),
        preset.tcp.len() + preset.udp.len()
    );
    for endpoint in &selected.endpoints {
        let port = endpoint.port().unwrap();
        let hint = scan::catalog::hint(endpoint.transport(), port).unwrap();
        let members = match endpoint.transport() {
            Transport::Tcp => &preset.tcp,
            _ => &preset.udp,
        };
        assert!(members.iter().any(|member| member == hint), "{endpoint}");
    }
}

#[test]
fn catalog_expansions_share_the_numeric_port_bound_and_exclusions_apply_first() {
    let both = [Transport::Tcp, Transport::Udp];
    let all = catalog::bundled().entries.len();
    assert_eq!(
        select(&both, &[(None, "@all")], &[], all)
            .unwrap()
            .endpoints
            .len(),
        all
    );
    let error = select(&both, &[(None, "@all")], &[], all - 1).unwrap_err();
    assert!(
        matches!(error, scan::Error::InvalidLimit { field: "ports", .. }),
        "{error}"
    );
    let trimmed = select(&both, &[(None, "@all")], &[(TCP, "http")], all - 1).unwrap();
    assert_eq!((trimmed.endpoints.len(), trimmed.excluded), (all - 1, 1));
    assert!(!trimmed.endpoints.contains(&tcp(80)));
}

#[test]
fn unknown_names_presets_and_empty_results_are_rejected() {
    let tcp_only = [Transport::Tcp];
    for (include, exclude) in [
        (&[(None, "not-a-service")][..], &[][..]),
        (&[(None, "@not-a-preset")][..], &[][..]),
        (&[(UDP, "53")][..], &[][..]),
        (&[(None, "80")][..], &[(None, "80")][..]),
    ] {
        let error = select(&tcp_only, include, exclude, 1024).unwrap_err();
        assert!(
            matches!(error, scan::Error::InvalidPort { .. }),
            "{include:?}: {error}"
        );
    }
}

#[test]
fn unresolved_preset_members_return_an_error_in_includes_and_exclusions() {
    let mut catalog = catalog::bundled().clone();
    catalog.entries.retain(|entry| entry.name != "http");
    for exclude in [false, true] {
        let mut selection = PortSelection {
            transports: vec![Transport::Tcp],
            include: vec![term(None, "@web")],
            exclude: Vec::new(),
        };
        if exclude {
            selection.include = vec![term(None, "22")];
            selection.exclude = vec![term(None, "@web")];
        }
        let error = select_endpoints(&selection, &catalog, 1024).unwrap_err();
        let scan::Error::InvalidPort { message } = error else {
            panic!("expected an invalid port error: {error}");
        };
        assert!(message.contains("web"), "{message}");
        assert!(message.contains("http"), "{message}");
        assert!(message.contains("tcp"), "{message}");
    }
}

#[test]
fn no_probe_reaches_an_excluded_port() {
    let selected = select(&[Transport::Tcp], &[(None, "80-84")], &[(None, "82")], 1024).unwrap();
    let state = Arc::new(Mutex::new(State::default()));
    let client = Client::new(
        builtin::registry(),
        Policy {
            max_packets_per_operation: 32,
            max_bytes_per_operation: 32 * 1500,
            ..Default::default()
        },
        common::providers(Routes, Io(Arc::clone(&state))),
    );
    let request = Request {
        max_in_flight: 2,
        targets: Target::Address("192.0.2.2".parse().unwrap()).into(),
        address_family: packetcraftr::target::Family::Any,
        endpoints: selected.endpoints,
        attempts: 2,
        timeout: Duration::from_millis(20),
        probes_per_second: None,
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        limits: scan::Limits::default(),
        route: packetcraftr::route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        collection: {
            let mut collection = packetcraftr::exchange::Collection::default();
            collection.capture.snap_length = 1500;
            collection
        },
    };
    let collector = scan::Collector::default();
    let report = client.scan(request, collector.clone()).unwrap();
    let aggregate = collector.finish(report).unwrap();

    let state = state.lock().unwrap();
    let mut ports: Vec<u16> = state
        .sent_wires
        .iter()
        .map(|wire| {
            let tcp = usize::from(wire[0] & 0x0f) * 4;
            u16::from_be_bytes([wire[tcp + 2], wire[tcp + 3]])
        })
        .collect();
    ports.sort_unstable();
    assert_eq!(ports, [80, 80, 81, 81, 83, 83, 84, 84]);
    assert!(
        aggregate
            .endpoints
            .iter()
            .all(|endpoint| endpoint.port != Some(82))
    );
}
