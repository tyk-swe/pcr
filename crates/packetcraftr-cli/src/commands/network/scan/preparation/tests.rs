// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use super::{validate_list_options, validate_stdin_consumers};
use crate::commands::network::scan::arguments::Discovery;

fn usage_message(error: crate::errors::CliError) -> String {
    assert_eq!(error.exit_code(), 2);
    error.to_string()
}

#[test]
fn rejects_multiple_stdin_consumers() {
    let error = validate_stdin_consumers(&[PathBuf::from("-")], &[PathBuf::from("-")], None, None)
        .unwrap_err();
    assert_eq!(
        usage_message(error),
        "stdin (`-`) can supply at most one of --targets-file, --exclude-file, --udp-payload-file, or --udp-profiles"
    );
}

#[test]
fn list_rejects_discovery() {
    let error = validate_list_options(true, Some(Discovery::Before), &None, false).unwrap_err();
    assert_eq!(
        usage_message(error),
        "--list sends no probe; remove --discovery, --reverse-dns, and --traceroute"
    );
}

#[test]
fn list_rejects_reverse_dns() {
    let error =
        validate_list_options(true, None, &Some("192.0.2.53".to_owned()), false).unwrap_err();
    assert_eq!(
        usage_message(error),
        "--list sends no probe; remove --discovery, --reverse-dns, and --traceroute"
    );
}

#[test]
fn list_rejects_traceroute() {
    let error = validate_list_options(true, None, &None, true).unwrap_err();
    assert_eq!(
        usage_message(error),
        "--list sends no probe; remove --discovery, --reverse-dns, and --traceroute"
    );
}
