// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::registry;

use packetcraftr_core::filter::{Error, Filter, Limits};

fn assert_rejected(cases: &[(&str, &str)]) {
    let registry = registry();
    for (source, expected) in cases {
        let error = match Filter::compile(source, &registry, Limits::default()) {
            Ok(_) => panic!("{source} must not compile"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains(expected),
            "{source}: {error} does not mention {expected}"
        );
    }
}

#[test]
fn occurrence_selectors_reject_every_malformed_spelling() {
    assert_rejected(&[
        ("ipv4.source#2 == 192.0.2.1", "must follow the protocol"),
        ("ipv4#x.source == 192.0.2.1", "is not a number"),
        ("ipv4#0.source == 192.0.2.1", "occurrences start at 1"),
        ("ipv4#-0.source == 192.0.2.1", "is not a number"),
        ("ipv4#-2.source == 192.0.2.1", "is not a number"),
        ("ipv4#LAST.source == 192.0.2.1", "is not a number"),
        ("ipv4#.source == 192.0.2.1", "is not a number"),
        ("ipv4#0", "occurrences start at 1"),
        ("ipv4#-2", "is not a number"),
        ("ipv4#LAST", "is not a number"),
        ("ipv4.source#last == 192.0.2.1", "must follow the protocol"),
        ("frame#last.len > 0", "not a protocol layer"),
        ("udp#-1.stream == 2", "not a protocol layer"),
        ("frame#1.len > 0", "not a protocol layer"),
        ("tcp#1.stream == 2", "not a protocol layer"),
    ]);
}

#[test]
fn malformed_and_misused_ranges_are_typed_errors_with_offsets() {
    let registry = registry();
    for (source, offset) in [
        ("tcp.port in 200..100", 12),
        ("tcp.port in 1..", 12),
        ("tcp.port in ..9", 12),
        ("tcp.port in 1...5", 12),
        ("tcp.port in -5..5", 12),
        ("tcp.port in 1..a", 12),
        ("tcp.port == 200..100", 12),
        ("tcp.port in {1, 5..2}", 16),
        ("ip.src in 192.0.2.9..192.0.2.1", 10),
        ("ip.src in 192.0.2.1..::1", 10),
    ] {
        match Filter::compile(source, &registry, Limits::default()) {
            Err(Error::InvalidRange {
                offset: actual,
                path,
                ..
            }) => {
                assert_eq!(actual, offset, "{source}");
                assert_eq!(path, source.split(' ').next().expect("path"), "{source}");
            }
            other => panic!("{source}: expected InvalidRange, got {other:?}"),
        }
    }
    for source in [
        "tcp.port >= 1..5",
        "tcp.port < 1..5",
        "ip.src > 1.1.1.1..2.2.2.2",
    ] {
        assert!(
            matches!(
                Filter::compile(source, &registry, Limits::default()),
                Err(Error::OrderedRangeComparison { .. })
            ),
            "{source}"
        );
    }
    assert_rejected(&[
        ("tcp.port in a..b", "cannot be compared"),
        ("tcp.port == a..b", "cannot be compared"),
        ("tcp.port >= 1..5", "only `==`, `!=`, and `in`"),
    ]);
}
