// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::error::Kind;

use super::{effective_method, validate_list_options, validate_stdin_consumers};
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

#[test]
fn automatic_effective_method_tracks_raw_capability() {
    use packetcraftr::scan::method::{Method, Requested};

    let tcp_endpoints = [packetcraftr::probe::Endpoint::Tcp { port: 443 }];
    let udp_endpoints = [packetcraftr::probe::Endpoint::Udp { port: 53 }];
    let tcp_scan = packetcraftr::scan::TcpScan::Syn;
    let sctp_scan = packetcraftr::scan::SctpScan::default();
    let unavailable = || {
        Err(packetcraftr_netio::Unsupported::new(
            packetcraftr_netio::NativeCapability::Capture,
            "test build has no raw packet I/O",
        ))
    };
    assert_eq!(
        effective_method(
            Requested::Automatic,
            Ok(()),
            false,
            &tcp_endpoints,
            &tcp_scan,
            sctp_scan,
            None,
        ),
        Method::Raw
    );
    assert_eq!(
        effective_method(
            Requested::Automatic,
            unavailable(),
            false,
            &tcp_endpoints,
            &tcp_scan,
            sctp_scan,
            None,
        ),
        Method::Connect
    );
    assert_eq!(
        effective_method(
            Requested::Automatic,
            unavailable(),
            true,
            &tcp_endpoints,
            &tcp_scan,
            sctp_scan,
            None,
        ),
        Method::Raw
    );
    assert_eq!(
        effective_method(
            Requested::Automatic,
            unavailable(),
            false,
            &udp_endpoints,
            &tcp_scan,
            sctp_scan,
            None,
        ),
        Method::Raw
    );
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
