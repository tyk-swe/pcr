// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::scan::catalog::bundled;

fn term(transport: Option<Transport>, selector: Selector) -> Term {
    Term {
        transport,
        selector,
    }
}

fn ports(start: u16, end: u16) -> Selector {
    Selector::Ports(PortSpec::RangeInclusive { start, end })
}

fn select(
    transports: &[Transport],
    include: Vec<Term>,
    exclude: Vec<Term>,
    max_ports: usize,
) -> Result<Selected, Error> {
    select_endpoints(
        &PortSelection {
            transports: transports.to_vec(),
            include,
            exclude,
        },
        bundled(),
        max_ports,
    )
}

#[test]
fn unqualified_terms_expand_per_transport_and_stay_distinct() {
    let selected = select(
        &[Transport::Tcp, Transport::Udp],
        vec![term(None, Selector::Ports(PortSpec::Single(53)))],
        Vec::new(),
        8,
    )
    .expect("selection");
    assert_eq!(
        selected.endpoints,
        [
            ProbeEndpoint::Tcp { port: 53 },
            ProbeEndpoint::Udp { port: 53 }
        ]
    );
}

#[test]
fn names_resolve_only_where_the_catalog_has_them() {
    let selected = select(
        &[Transport::Tcp, Transport::Udp],
        vec![term(None, Selector::Name("ssh".into()))],
        Vec::new(),
        8,
    )
    .expect("ssh has a TCP entry");
    assert_eq!(selected.endpoints, [ProbeEndpoint::Tcp { port: 22 }]);
    let error = select(
        &[Transport::Udp],
        vec![term(None, Selector::Name("ssh".into()))],
        Vec::new(),
        8,
    )
    .expect_err("no UDP ssh entry");
    assert!(error.to_string().contains("\"ssh\""), "{error}");
}

#[test]
fn exclusions_apply_after_expansion_and_before_the_port_bound() {
    let selected = select(
        &[Transport::Tcp],
        vec![term(None, ports(1, 1024))],
        vec![term(None, ports(3, 1024))],
        2,
    )
    .expect("the bound applies to the remainder");
    assert_eq!(
        selected.endpoints,
        [
            ProbeEndpoint::Tcp { port: 1 },
            ProbeEndpoint::Tcp { port: 2 }
        ]
    );
    assert_eq!(selected.excluded, 1022);
    let error = select(
        &[Transport::Tcp],
        vec![term(None, ports(1, 3))],
        Vec::new(),
        2,
    )
    .expect_err("three ports exceed two");
    assert!(error.to_string().contains("max_ports=2"), "{error}");
}

#[test]
fn qualified_exclusions_leave_the_other_transport_alone() {
    let selected = select(
        &[Transport::Tcp, Transport::Udp],
        vec![term(None, Selector::Preset("name-services".into()))],
        vec![term(Some(Transport::Udp), Selector::Name("dns".into()))],
        16,
    )
    .expect("selection");
    assert!(
        selected
            .endpoints
            .contains(&ProbeEndpoint::Tcp { port: 53 })
    );
    assert!(
        !selected
            .endpoints
            .contains(&ProbeEndpoint::Udp { port: 53 })
    );
    assert!(
        selected
            .endpoints
            .contains(&ProbeEndpoint::Udp { port: 5353 })
    );
    assert_eq!(selected.excluded, 1);
}

#[test]
fn invalid_selections_fail_before_planning() {
    let cases = [
        (
            select(
                &[Transport::Tcp],
                vec![term(Some(Transport::Udp), ports(1, 1))],
                Vec::new(),
                8,
            ),
            "among the scan transports",
        ),
        (
            select(
                &[Transport::Tcp],
                vec![term(None, ports(9, 1))],
                Vec::new(),
                8,
            ),
            "descending",
        ),
        (
            select(
                &[Transport::Udp],
                vec![term(None, Selector::Preset("web".into()))],
                Vec::new(),
                8,
            ),
            "has no udp members",
        ),
        (
            select(
                &[Transport::Tcp],
                vec![term(None, Selector::Preset("top-100".into()))],
                Vec::new(),
                8,
            ),
            "is not in catalog",
        ),
        (
            select(
                &[Transport::Tcp],
                vec![term(None, ports(80, 80))],
                vec![term(None, ports(80, 80))],
                8,
            ),
            "removed every selected port",
        ),
        (
            select(
                &[Transport::Icmp],
                vec![term(None, ports(80, 80))],
                Vec::new(),
                8,
            ),
            "TCP and/or UDP",
        ),
        (
            select(
                &[Transport::Tcp],
                vec![term(None, ports(1, 1)); MAX_PORT_TERMS + 1],
                Vec::new(),
                8,
            ),
            "port terms",
        ),
    ];
    for (result, expected) in cases {
        let error = result.expect_err(expected);
        assert!(error.to_string().contains(expected), "{expected}: {error}");
    }
}
