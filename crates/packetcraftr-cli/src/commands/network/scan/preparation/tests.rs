// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::error::Kind;

use super::{validate_list_options, validate_stdin_consumers};
use crate::commands::network::scan::arguments::Discovery;

fn assert_usage_error(error: crate::errors::CliError) {
    assert_eq!(error.exit_code(), 2);
    assert_eq!(error.classification.kind, Kind::Usage);
    assert_eq!(error.classification.code, "cli.error");
}

#[test]
fn rejects_multiple_stdin_consumers() {
    let error = validate_stdin_consumers(&[PathBuf::from("-")], &[PathBuf::from("-")], None, None)
        .unwrap_err();
    assert_usage_error(error);
}

#[test]
fn list_rejects_discovery_reverse_dns_and_traceroute() {
    for error in [
        validate_list_options(true, Some(Discovery::Before), &None, false).unwrap_err(),
        validate_list_options(true, None, &Some("192.0.2.53".to_owned()), false).unwrap_err(),
        validate_list_options(true, None, &None, true).unwrap_err(),
    ] {
        assert_usage_error(error);
    }
}
