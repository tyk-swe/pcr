// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::error::Kind;

use super::{
    selection::{self, Inputs},
    validate_list_options, validate_stdin_consumers,
};
use crate::commands::network::scan::arguments::Discovery;

fn assert_usage_error(error: crate::errors::CliError) {
    assert_eq!(error.exit_code(), 2);
    assert_eq!(error.classification.kind, Kind::Usage);
    assert_eq!(error.classification.code.as_str(), "cli.error");
}

#[test]
fn rejects_multiple_stdin_consumers() {
    let error = validate_stdin_consumers(&[PathBuf::from("-")], &[PathBuf::from("-")], None, None)
        .unwrap_err();
    assert_usage_error(error);
}

fn inputs(transports: Vec<super::arguments::Transport>) -> Inputs {
    Inputs {
        transports,
        ports: Vec::new(),
        exclude_ports: Vec::new(),
        ip_protocols: Vec::new(),
        exclude_ip_protocols: Vec::new(),
        discovery: None,
        discovery_probes: Vec::new(),
        discovery_ports: Vec::new(),
        discovery_ip_protocols: Vec::new(),
        unresponsive: None,
        max_ports: 3,
        tcp_scan: Default::default(),
        sctp_scan: Default::default(),
    }
}

#[test]
fn listing_omits_sections_without_terms_including_icmp() {
    for transports in [
        vec![super::arguments::Transport::Tcp],
        vec![super::arguments::Transport::Icmp],
        vec![super::arguments::Transport::Ip],
    ] {
        let prepared = selection::prepare(inputs(transports), true).unwrap();
        assert!(prepared.scan().is_none());
    }
    let mut input = inputs(vec![super::arguments::Transport::Ip]);
    input.exclude_ip_protocols = vec!["1".parse().unwrap()];
    assert!(selection::prepare(input, true).is_err());
    let mut input = inputs(vec![super::arguments::Transport::Ip]);
    input.max_ports = 16;
    input.ip_protocols = vec!["1-5".parse().unwrap()];
    input.exclude_ip_protocols = vec!["6".parse().unwrap()];
    let prepared = selection::prepare(input, true).unwrap();
    assert!(prepared.publish_scan());
    let selected = prepared.scan().unwrap();
    assert_eq!(selected.ip_protocols().collect::<Vec<_>>(), [1, 2, 3, 4, 5]);
    assert_eq!(selected.excluded(), 0);
}

#[test]
fn protocol_listing_enforces_the_exact_distinct_endpoint_budget() {
    let mut input = inputs(vec![super::arguments::Transport::Ip]);
    input.ip_protocols = vec!["1-2".parse().unwrap()];
    input.max_ports = 2;
    let prepared = selection::prepare(input.clone(), true).unwrap();
    assert_eq!(
        prepared.scan().unwrap().ip_protocols().collect::<Vec<_>>(),
        [1, 2]
    );
    input.max_ports = 1;
    assert!(selection::prepare(input, true).is_err());
}

#[test]
fn missing_catalog_name_diagnostic_identifies_the_selected_transport() {
    let mut input = inputs(vec![super::arguments::Transport::Udp]);
    let name = "nonexistenttestname";
    assert!(
        !packetcraftr::scan::catalog::bundled()
            .entries
            .iter()
            .any(|entry| entry.name == name)
    );
    input.ports = vec![name.parse().unwrap()];
    let error = selection::prepare(input, true).unwrap_err();
    assert!(error.to_string().contains(" for udp"), "{error}");
}

#[test]
fn list_and_live_use_the_same_validation_order_and_terms() {
    let mut input = inputs(vec![super::arguments::Transport::Tcp]);
    input.tcp_scan = packetcraftr::scan::TcpScan::Ack;
    let mut live = input;
    live.ports = vec!["80".parse().unwrap()];
    let list = selection::prepare(live.clone(), true).unwrap();
    let live_prepared = selection::prepare(live, false).unwrap();
    assert_eq!(list.endpoints(), live_prepared.endpoints());
    assert_eq!(list.tcp_scan(), live_prepared.tcp_scan());
    assert_eq!(
        list.endpoints(),
        [packetcraftr::probe::Endpoint::Tcp { port: 80 }]
    );

    let mut ack = inputs(Vec::new());
    ack.tcp_scan = packetcraftr::scan::TcpScan::Ack;
    for listing in [true, false] {
        let error = selection::prepare(ack.clone(), listing).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ack scans require at least one TCP scan endpoint")
        );
    }

    let mut old_list_exception = inputs(vec![super::arguments::Transport::Icmp]);
    old_list_exception.ports = vec!["80".parse().unwrap()];
    for listing in [false, true] {
        let error = selection::prepare(old_list_exception.clone(), listing).unwrap_err();
        assert!(error.to_string().contains("do not apply to portless ICMP"));
        assert_usage_error(error);
    }
}

#[test]
fn list_rejects_live_discovery_options() {
    for error in [
        validate_list_options(true, Some(Discovery::Before), &None, false).unwrap_err(),
        validate_list_options(true, None, &Some("192.0.2.53".to_owned()), false).unwrap_err(),
        validate_list_options(true, None, &None, true).unwrap_err(),
    ] {
        assert_usage_error(error);
    }
}
