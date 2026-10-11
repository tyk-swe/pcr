// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Debug;
use std::time::Duration;

use packetcraftr::{dns, evidence, scan, traceroute};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

// These are the public layouts before evidence ceilings moved into a shared
// Rust type. Keep their field order as well as their names: binary Serde
// formats encode structs as sequences without field names.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "Limits")]
struct ScanLimits {
    max_prepared_bytes: usize,
    max_targets: usize,
    max_ports: usize,
    max_probes: usize,
    max_duration: Duration,
    max_evidence_frames: usize,
    max_evidence_bytes: usize,
    max_undecoded: usize,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "Limits")]
struct TraceLimits {
    max_probes: usize,
    max_duration: Duration,
    max_evidence_frames: usize,
    max_evidence_bytes: usize,
    max_undecoded: usize,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename = "Limits")]
struct DnsLimits {
    message: dns::MessageLimits,
    max_evidence_frames: usize,
    max_evidence_bytes: usize,
    max_undecoded: usize,
    max_duration: Duration,
}

fn compatible<N, O>(current: N, previous: O)
where
    N: Debug + PartialEq + Serialize + DeserializeOwned,
    O: Debug + PartialEq + Serialize + DeserializeOwned,
{
    let previous_json = serde_json::to_value(&previous).unwrap();
    let current_json = serde_json::to_value(&current).unwrap();
    assert_eq!(current_json, previous_json);
    assert_eq!(serde_json::from_value::<N>(previous_json).unwrap(), current);
    assert_eq!(serde_json::from_value::<O>(current_json).unwrap(), previous);

    let previous_bytes = postcard::to_allocvec(&previous).unwrap();
    let current_bytes = postcard::to_allocvec(&current).unwrap();
    assert_eq!(current_bytes, previous_bytes);
    assert_eq!(postcard::from_bytes::<N>(&previous_bytes).unwrap(), current);
    assert_eq!(postcard::from_bytes::<O>(&current_bytes).unwrap(), previous);
}

fn evidence() -> evidence::Limits {
    evidence::Limits {
        max_frames: 11,
        max_bytes: 12_288,
        max_undecoded: 3,
    }
}

#[test]
fn scan_limits_preserve_json_and_binary_serialization() {
    compatible(
        scan::Limits {
            max_prepared_bytes: 4096,
            max_targets: 5,
            max_ports: 6,
            max_probes: 7,
            max_duration: Duration::new(8, 9),
            evidence: evidence(),
        },
        ScanLimits {
            max_prepared_bytes: 4096,
            max_targets: 5,
            max_ports: 6,
            max_probes: 7,
            max_duration: Duration::new(8, 9),
            max_evidence_frames: 11,
            max_evidence_bytes: 12_288,
            max_undecoded: 3,
        },
    );
}

#[test]
fn trace_limits_preserve_json_and_binary_serialization() {
    compatible(
        traceroute::Limits {
            max_probes: 7,
            max_duration: Duration::new(8, 9),
            evidence: evidence(),
        },
        TraceLimits {
            max_probes: 7,
            max_duration: Duration::new(8, 9),
            max_evidence_frames: 11,
            max_evidence_bytes: 12_288,
            max_undecoded: 3,
        },
    );
}

#[test]
fn dns_limits_preserve_json_and_binary_serialization() {
    let message = dns::MessageLimits {
        max_message_bytes: 1234,
        max_records: 12,
        max_name_pointers: 6,
        max_txt_strings: 7,
        max_txt_bytes: 456,
        max_rejected_records: 2,
    };
    compatible(
        dns::Limits {
            message,
            evidence: evidence(),
            max_duration: Duration::new(8, 9),
        },
        DnsLimits {
            message,
            max_evidence_frames: 11,
            max_evidence_bytes: 12_288,
            max_undecoded: 3,
            max_duration: Duration::new(8, 9),
        },
    );
}
