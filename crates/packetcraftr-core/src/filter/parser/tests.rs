// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::filter::{MAX_FILTER_NESTING, MAX_FILTER_SET_MEMBERS, MAX_FILTER_TERMS};

#[test]
fn postfix_program_preserves_boolean_precedence_and_records_requirements() {
    let registry = crate::protocol::builtin::registry();
    let compiled = compile(
        "frame.time_epoch >= 0 || tcp.stream == 1 && !udp.stream == 2",
        &registry,
        &Limits::default(),
    )
    .expect("valid mixed-requirement filter compiles");

    assert_eq!(compiled.program.len(), 6);
    assert!(matches!(compiled.program[0], Op::Leaf(_)));
    assert!(matches!(compiled.program[1], Op::Leaf(_)));
    assert!(matches!(compiled.program[2], Op::Leaf(_)));
    assert!(matches!(compiled.program[3], Op::Not));
    assert!(matches!(compiled.program[4], Op::And));
    assert!(matches!(compiled.program[5], Op::Or));
    assert_eq!(
        compiled.requirements,
        Requirements {
            stream_index: true,
            tcp_stream: true,
            udp_stream: true,
            timestamp: true,
        }
    );
}

#[test]
fn configured_parser_limits_fail_at_the_first_excess_item() {
    let registry = crate::protocol::builtin::registry();
    assert!(matches!(
        compile(
            "ipv4",
            &registry,
            &Limits {
                max_bytes: 3,
                ..Limits::default()
            }
        ),
        Err(Error::SizeLimit {
            actual: 4,
            limit: 3
        })
    ));
    assert!(matches!(
        compile(" ", &registry, &Limits::default()),
        Err(Error::Empty)
    ));
    assert!(matches!(
        compile(
            "ipv4",
            &registry,
            &Limits {
                max_nesting: MAX_FILTER_NESTING + 1,
                ..Limits::default()
            }
        ),
        Err(Error::InvalidNestingLimit { .. })
    ));
    assert!(matches!(
        compile(
            "ipv4",
            &registry,
            &Limits {
                max_terms: MAX_FILTER_TERMS + 1,
                ..Limits::default()
            }
        ),
        Err(Error::InvalidTermLimit { .. })
    ));
    assert!(matches!(
        compile(
            "ipv4",
            &registry,
            &Limits {
                max_set_members: MAX_FILTER_SET_MEMBERS + 1,
                ..Limits::default()
            }
        ),
        Err(Error::InvalidSetMemberLimit { .. })
    ));
    assert!(matches!(
        compile(
            "((ipv4))",
            &registry,
            &Limits {
                max_nesting: 1,
                ..Limits::default()
            }
        ),
        Err(Error::NestingLimit { limit: 1 })
    ));
    assert!(matches!(
        compile(
            "ipv4 && tcp",
            &registry,
            &Limits {
                max_terms: 1,
                ..Limits::default()
            }
        ),
        Err(Error::TermLimit { limit: 1 })
    ));
    assert!(matches!(
        compile(
            "tcp.port in {1, 2}",
            &registry,
            &Limits {
                max_set_members: 1,
                ..Limits::default()
            }
        ),
        Err(Error::SetMemberLimit { limit: 1 })
    ));
}

#[test]
fn structural_syntax_errors_identify_the_rejected_construct() {
    let registry = crate::protocol::builtin::registry();
    let cases = [
        ("&& ipv4", "expected a field or `(`"),
        ("ipv4 &&", "ends where a field was expected"),
        ("ipv4)", "unmatched `)`"),
        ("(ipv4", "unmatched `(`"),
        ("ipv4 tcp", "expected `&&`, `||`, or `)`"),
        ("ipv4[0]", "cannot be sliced"),
        ("ipv4 == 1", "names a layer, not a field"),
        ("tcp.port in", "`in` needs a value"),
        ("tcp.port in {}", "set needs at least one member"),
        ("tcp.port in {1", "unterminated set"),
        ("tcp.port in {1 2}", "expected `,` or `}`"),
        ("tcp.port == }", "expected a value"),
    ];

    for (source, expected) in cases {
        let error = match compile(source, &registry, &Limits::default()) {
            Ok(_) => panic!("{source} unexpectedly compiled"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(expected), "{source}: {error}");
    }
}

#[test]
fn incompatible_prefix_and_contains_operations_fail_during_compilation() {
    let registry = crate::protocol::builtin::registry();
    assert!(matches!(
        compile("ipv4.source > 192.0.2.0/24", &registry, &Limits::default()),
        Err(Error::OrderedPrefixComparison { .. })
    ));
    assert!(matches!(
        compile("ipv4.source == 7", &registry, &Limits::default()),
        Err(Error::IncompatibleLiteral { .. })
    ));
    assert!(matches!(
        compile(
            "tcp.source_port contains \"x\"",
            &registry,
            &Limits::default()
        ),
        Err(Error::IncompatibleLiteral { .. })
    ));
    assert!(matches!(
        compile("raw.bytes contains 1", &registry, &Limits::default()),
        Err(Error::IncompatibleLiteral { .. })
    ));
}

#[test]
fn contains_refusals_report_the_operator_offset_field_kind_and_literal() {
    let registry = crate::protocol::builtin::registry();
    let cases = [
        ("raw.bytes contains 1", 10, "raw.bytes", "bytes", "1"),
        (
            "tcp.source_port contains \"x\"",
            16,
            "tcp.source_port",
            "an unsigned number",
            "\"x\"",
        ),
    ];

    for (source, offset, path, kind, literal) in cases {
        let error = match compile(source, &registry, &Limits::default()) {
            Ok(_) => panic!("{source} unexpectedly compiled"),
            Err(error) => error,
        };
        let Error::IncompatibleLiteral {
            offset: actual_offset,
            path: actual_path,
            kind: actual_kind,
            literal: actual_literal,
        } = error
        else {
            panic!("{source}: unexpected error {error}");
        };
        assert_eq!(actual_offset, offset, "{source}");
        assert_eq!(actual_path, path, "{source}");
        assert_eq!(actual_kind, kind, "{source}");
        assert_eq!(actual_literal, literal, "{source}");
    }
}
