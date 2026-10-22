// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr::scan::{IpProtocolSpec, PortSpec, Selector, Term};

fn port(transport: Option<Transport>, value: u16) -> arguments::PortTerm {
    arguments::PortTerm(Term {
        transport,
        selector: Selector::Ports(PortSpec::Single(value)),
    })
}

fn protocol(value: u8) -> arguments::IpProtocolTerm {
    arguments::IpProtocolTerm(IpProtocolSpec::Single(value))
}

fn endpoint_request(
    transports: &[Transport],
    ports: Vec<arguments::PortTerm>,
    exclude_ports: Vec<arguments::PortTerm>,
    ip_protocols: Vec<arguments::IpProtocolTerm>,
    exclude_ip_protocols: Vec<arguments::IpProtocolTerm>,
) -> EndpointRequest {
    EndpointRequest {
        transports: transports.to_vec(),
        ports,
        exclude_ports,
        ip_protocols,
        exclude_ip_protocols,
        max_ports: 1024,
    }
}

fn discovery_request(probes: Vec<arguments::DiscoveryProbe>) -> DiscoveryRequest {
    DiscoveryRequest {
        mode: Some(arguments::Discovery::Before),
        probes,
        ports: vec![port(None, 22), port(None, 53)],
        exclude_ports: vec![port(Some(Transport::Tcp), 53)],
        ip_protocols: Vec::new(),
        exclude_ip_protocols: Vec::new(),
        unresponsive: None,
        max_ports: 1024,
    }
}

#[test]
fn live_port_selection_requires_omitted_ports() {
    let error = endpoint_request(&[Transport::Tcp], vec![], vec![], vec![], vec![])
        .select()
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid scan ports: TCP and UDP scans require at least one destination port"
    );
}

#[test]
fn listing_omits_an_unrequested_default_port_selection() {
    let selected = endpoint_request(&[Transport::Tcp], vec![], vec![], vec![], vec![])
        .select_if_requested()
        .expect("an omitted list selection is valid");
    assert!(selected.is_none());
}

#[test]
fn ip_protocol_only_selection_uses_protocol_endpoints() {
    let selected = endpoint_request(
        &[Transport::Ip],
        vec![],
        vec![],
        vec![protocol(1), protocol(6)],
        vec![protocol(6)],
    )
    .select()
    .unwrap();
    assert_eq!(selected.endpoints, [probe::Endpoint::Ip { protocol: 1 }]);
    assert_eq!(selected.excluded, 1);
}

#[test]
fn invalid_port_and_protocol_combinations_keep_their_messages() {
    let cases = [
        (
            endpoint_request(
                &[Transport::Ip],
                vec![port(None, 80)],
                vec![],
                vec![],
                vec![],
            ),
            "--ports and --exclude-ports do not apply to portless IP-protocol scans; use --ip-protocols",
        ),
        (
            endpoint_request(
                &[Transport::Icmp],
                vec![port(None, 80)],
                vec![],
                vec![],
                vec![],
            ),
            "--ports and --exclude-ports do not apply to portless ICMP echo scans",
        ),
        (
            endpoint_request(
                &[Transport::Tcp],
                vec![port(None, 80)],
                vec![],
                vec![protocol(1)],
                vec![],
            ),
            "--ip-protocols and --exclude-ip-protocols require --transport ip",
        ),
    ];
    for (request, expected) in cases {
        assert_eq!(request.select().unwrap_err().to_string(), expected);
    }
}

#[test]
fn listing_preserves_icmp_combined_invalid_option_precedence() {
    let listing = endpoint_request(
        &[Transport::Icmp],
        vec![port(None, 80)],
        vec![],
        vec![protocol(1)],
        vec![],
    )
    .select_if_requested()
    .unwrap_err();
    assert_eq!(
        listing.to_string(),
        "--ip-protocols and --exclude-ip-protocols require --transport ip"
    );

    let scan = endpoint_request(
        &[Transport::Icmp],
        vec![port(None, 80)],
        vec![],
        vec![protocol(1)],
        vec![],
    )
    .select()
    .unwrap_err();
    assert_eq!(
        scan.to_string(),
        "--ports and --exclude-ports do not apply to portless ICMP echo scans"
    );
}

#[test]
fn transport_specific_exclusions_only_remove_matching_endpoints() {
    let selected = endpoint_request(
        &[Transport::Tcp, Transport::Udp],
        vec![port(None, 53), port(None, 80)],
        vec![port(Some(Transport::Tcp), 53)],
        vec![],
        vec![],
    )
    .select()
    .unwrap();
    assert_eq!(
        selected.endpoints,
        [
            probe::Endpoint::Udp { port: 53 },
            probe::Endpoint::Tcp { port: 80 },
            probe::Endpoint::Udp { port: 80 },
        ]
    );
    assert_eq!(selected.excluded, 1);
}

#[test]
fn scan_exclusions_keep_terms_discovery_did_not_consume() {
    let mut request = endpoint_request(
        &[Transport::Tcp],
        vec![port(None, 53), port(None, 80)],
        vec![
            port(Some(Transport::Udp), 53),
            port(Some(Transport::Tcp), 80),
        ],
        vec![],
        vec![],
    );
    request.retain_scan_exclusions(&[Transport::Udp]);
    let selected = request.select().unwrap();
    assert_eq!(selected.endpoints, [probe::Endpoint::Tcp { port: 53 }]);
    assert_eq!(selected.excluded, 1);
}

#[test]
fn tcp_and_tcp_ack_discovery_expansion_is_deduplicated_and_counted() {
    let prepared = discovery_request(vec![
        arguments::DiscoveryProbe::Tcp,
        arguments::DiscoveryProbe::TcpAck,
        arguments::DiscoveryProbe::Tcp,
        arguments::DiscoveryProbe::TcpAck,
    ])
    .prepare()
    .unwrap();
    assert_eq!(prepared.port_transports, [Transport::Tcp]);
    assert_eq!(
        prepared.options.probes,
        [
            probe::Endpoint::Tcp { port: 22 },
            probe::Endpoint::TcpAck { port: 22 },
        ]
    );
    assert_eq!(prepared.excluded, 2);
}
