// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use super::support::{binary, write_capture};

/// Builds one exact frame with the CLI, so fixtures never carry hand-computed
/// checksums that could drift from what the dissector expects.
fn built_frame(expression: &str) -> Vec<u8> {
    let output = binary()
        .args(["--output", "raw", "build", "--packet", expression])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Two Ethernet frames that differ in transport, address, and TCP flags, so a
/// filter has something to discriminate on.
fn filterable_capture() -> PathBuf {
    let udp = built_frame(
        "ethernet(source=02:00:00:00:00:01,destination=02:00:00:00:00:02)\
         /ipv4(source=10.0.0.1,destination=10.0.0.2)\
         /udp(source_port=1000,destination_port=5353)/raw(text=q)",
    );
    let tcp = built_frame(
        "ethernet(source=02:00:00:00:00:03,destination=02:00:00:00:00:04)\
         /ipv4(source=192.168.0.1,destination=192.168.0.2)\
         /tcp(source_port=1000,destination_port=443,flags=2)",
    );
    write_capture(&[&udp, &tcp], false)
}

mod analysis;
mod construction;
mod filtering;
mod follow;
