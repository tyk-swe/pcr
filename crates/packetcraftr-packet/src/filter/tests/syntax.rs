// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Endpoint, Error, Filter, MAX_FILTER_NESTING, MAX_FILTER_SET_MEMBERS, MAX_FILTER_TERMS, Options,
    Packet, compile, decoded, empty_registry, fixture_registry, matches, sample,
};

#[test]
fn unbalanced_parentheses_are_reported_with_an_offset() {
    assert!(matches!(compile("(frame.len"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("frame.len)"), Err(Error::Syntax { .. })));
}

#[test]
fn a_dangling_operator_is_a_syntax_error() {
    assert!(matches!(compile("frame.len &&"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("&& frame.len"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("frame.len =="), Err(Error::Syntax { .. })));
}

#[test]
fn a_single_ampersand_or_equals_is_rejected_rather_than_guessed() {
    assert!(matches!(
        compile("frame.len & 1"),
        Err(Error::Syntax { .. })
    ));
    assert!(matches!(
        compile("frame.len = 1"),
        Err(Error::Syntax { .. })
    ));
}

#[test]
fn an_unknown_field_names_the_path_that_failed() {
    let error = compile("frame.nonexistent").unwrap_err();
    match error {
        Error::UnknownField { path, .. } => assert_eq!(path, "frame.nonexistent"),
        other => panic!("expected an unknown field, got {other:?}"),
    }
}

#[test]
fn an_unregistered_protocol_is_an_unknown_field() {
    assert!(matches!(compile("tcp"), Err(Error::UnknownField { .. })));
    assert!(matches!(
        compile("tcp.destination_port == 443"),
        Err(Error::UnknownField { .. })
    ));
}

#[test]
fn synthetic_frame_fields_resolve_without_any_registered_protocol() {
    for path in [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.cap_len",
        "frame.interface_id",
        "frame.link_type",
    ] {
        compile(path).unwrap_or_else(|error| panic!("{path} should compile, got {error:?}"));
    }
}

#[test]
fn stream_paths_are_reserved_and_declare_their_requirement() {
    for path in ["tcp.stream", "udp.stream"] {
        let filter = compile(path).expect("stream paths resolve without a registry");
        assert!(
            filter.requirements().stream_index,
            "{path} must declare that it needs a stream index"
        );
    }
    let plain = compile("frame.len").unwrap();
    assert!(!plain.requirements().stream_index);
}

#[test]
fn a_layer_occurrence_must_be_a_positive_number_on_the_protocol() {
    assert!(matches!(compile("frame#0.len"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("frame#x.len"), Err(Error::Syntax { .. })));
    // The selector belongs to the protocol segment, never a later one.
    assert!(matches!(compile("frame.len#2"), Err(Error::Syntax { .. })));
}

#[test]
fn synthetic_fields_have_no_occurrences_to_select() {
    // These are per-frame and per-conversation facts, not layers, so an
    // occurrence on them is a typo rather than a narrower selection.
    assert!(matches!(compile("frame#2.len"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("tcp#2.stream"), Err(Error::Syntax { .. })));
    assert!(matches!(compile("udp#1.stream"), Err(Error::Syntax { .. })));
    // The unqualified spellings still resolve.
    compile("frame.len").expect("frame.len resolves");
    compile("tcp.stream").expect("tcp.stream resolves");
}

#[test]
fn a_literal_that_could_never_match_the_field_is_rejected() {
    let error = compile("frame.len == 10.0.0.1").unwrap_err();
    match error {
        Error::IncompatibleLiteral { path, .. } => assert_eq!(path, "frame.len"),
        other => panic!("expected an incompatible literal, got {other:?}"),
    }
}

#[test]
fn synthetic_fields_cannot_be_sliced() {
    assert!(matches!(
        compile("frame.len[0:2] == 00:01"),
        Err(Error::UnsliceableField { .. })
    ));
}

#[test]
fn contains_is_rejected_where_it_could_never_search() {
    let compile_fixture_result =
        |source: &str| Filter::compile(source, &fixture_registry(), Options::default());

    // A number is not a byte haystack.
    assert!(matches!(
        compile_fixture_result("padding.outside_layer contains 01"),
        Err(Error::IncompatibleLiteral { .. })
    ));
    // A prefix is not a byte needle.
    assert!(matches!(
        compile_fixture_result("raw.bytes contains 10.0.0.0/8"),
        Err(Error::IncompatibleLiteral { .. })
    ));
    // A bare number is an ambiguous needle — decimal or a single byte? — so it
    // is refused rather than guessed at.
    assert!(matches!(
        compile_fixture_result("raw.bytes contains 47"),
        Err(Error::IncompatibleLiteral { .. })
    ));
    // Slicing narrows a field to bytes, so it stays searchable.
    compile_fixture_result("raw.bytes[0:2] contains 47:45").expect("sliced bytes are searchable");
    compile_fixture_result("raw.bytes[0:2] contains \"GE\"")
        .expect("quoted text is an unambiguous needle");
}

#[test]
fn unquoted_text_is_rejected_against_a_field_that_is_never_text() {
    // `frame.len` is a plain number, so a bareword can only be a typo.
    assert!(matches!(
        compile("frame.len == nope"),
        Err(Error::IncompatibleLiteral { .. })
    ));
    assert!(matches!(
        compile("frame.len == auto"),
        Err(Error::IncompatibleLiteral { .. })
    ));
    // A non-derived numeric layer field behaves the same way.
    assert!(matches!(
        Filter::compile(
            "padding.outside_layer == auto",
            &fixture_registry(),
            Options::default()
        ),
        Err(Error::IncompatibleLiteral { .. })
    ));
}

#[test]
fn a_single_byte_slice_compares_against_a_plain_number() {
    let packet = sample();
    // A bare `47` would read as ambiguously decimal or hexadecimal, so a
    // one-byte slice is written as a number instead.
    assert!(matches("raw.bytes[0:1] == 0x47", &packet));
    assert!(matches("raw.bytes[0:1] == 71", &packet));
    assert!(!matches("raw.bytes[0:1] == 0x45", &packet));
    // A multi-byte value has no numeric reading, so it simply does not match.
    assert!(!matches("raw.bytes[0:2] == 71", &packet));
}

#[test]
fn a_set_member_limit_above_the_stable_maximum_is_rejected() {
    let options = Options {
        max_set_members: MAX_FILTER_SET_MEMBERS + 1,
        ..Options::default()
    };
    let error = Filter::compile("frame.len in {1}", &empty_registry(), options).unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidSetMemberLimit {
            value,
            maximum: MAX_FILTER_SET_MEMBERS
        } if value == MAX_FILTER_SET_MEMBERS + 1
    ));
}

#[test]
fn a_term_limit_above_the_stable_maximum_is_rejected() {
    let options = Options {
        max_terms: MAX_FILTER_TERMS + 1,
        ..Options::default()
    };
    let error = Filter::compile("frame.len", &empty_registry(), options).unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidTermLimit {
            value,
            maximum: MAX_FILTER_TERMS
        } if value == MAX_FILTER_TERMS + 1
    ));
}

#[test]
fn a_prefix_can_only_be_tested_for_membership() {
    // A prefix names a set, so ordering one would evaluate false for every
    // packet. That must be reported rather than silently filtering everything.
    for source in [
        "endpoint.source > 10.0.0.0/8",
        "endpoint.source <= 10.0.0.0/8",
        "endpoint.target >= 2001:db8::/32",
    ] {
        let error =
            Filter::compile(source, &fixture_registry(), Options::default()).expect_err(source);
        assert!(
            matches!(error, Error::OrderedPrefixComparison { .. }),
            "{source} should report an ordered prefix, got {error:?}"
        );
    }
    // Membership spellings stay available.
    Filter::compile(
        "endpoint.source == 10.0.0.0/8",
        &fixture_registry(),
        Options::default(),
    )
    .expect("equality against a prefix is containment");
    Filter::compile(
        "endpoint.source in 10.0.0.0/8",
        &fixture_registry(),
        Options::default(),
    )
    .expect("`in` against a prefix is containment");
}

#[test]
fn addresses_match_by_value_and_by_prefix() {
    let mut packet = Packet::new();
    packet.push(Endpoint {
        source: std::net::Ipv4Addr::new(10, 1, 2, 3),
        target: "2001:db8::5".parse().expect("fixture address"),
        label: "edge-router".to_owned(),
    });
    let record = decoded(packet, &[]);

    assert!(matches("endpoint.source == 10.1.2.3", &record));
    assert!(matches("endpoint.source == 10.0.0.0/8", &record));
    assert!(matches("endpoint.source in 10.0.0.0/8", &record));
    assert!(!matches("endpoint.source == 192.168.0.0/16", &record));
    assert!(matches("endpoint.source != 192.168.0.0/16", &record));
    // A /0 prefix contains everything, and a /32 is an exact address.
    assert!(matches("endpoint.source == 0.0.0.0/0", &record));
    assert!(matches("endpoint.source == 10.1.2.3/32", &record));
    assert!(!matches("endpoint.source == 10.1.2.4/32", &record));

    assert!(matches("endpoint.target == 2001:db8::5", &record));
    assert!(matches("endpoint.target in 2001:db8::/32", &record));
    assert!(!matches("endpoint.target in 2001:db9::/32", &record));

    // Addresses order, so a range test works too.
    assert!(matches("endpoint.source > 10.1.2.2", &record));
    assert!(matches("endpoint.source < 10.1.2.4", &record));

    // Text compares and searches.
    assert!(matches("endpoint.label == \"edge-router\"", &record));
    assert!(matches("endpoint.label contains \"router\"", &record));
    assert!(!matches("endpoint.label contains \"switch\"", &record));

    // An address slices to its octets.
    assert!(matches("endpoint.source[0:2] == 0a:01", &record));
}

#[test]
fn a_numeric_field_cannot_be_sliced() {
    // `outside_layer` is unsigned, and a number has no byte projection. The
    // slice must be refused rather than compiling into a filter that silently
    // matches nothing.
    let error = Filter::compile(
        "padding.outside_layer[0:1] == 00",
        &fixture_registry(),
        Options::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnsliceableField { .. }));

    // The same holds for a bit binding, whose value is also a number.
    let error = Filter::compile(
        "pad.layer.low[0:1] == 00",
        &fixture_registry(),
        Options::default(),
    )
    .unwrap_err();
    assert!(matches!(error, Error::UnsliceableField { .. }));

    // A byte field slices normally.
    Filter::compile(
        "padding.bytes[0:1] == aa",
        &fixture_registry(),
        Options::default(),
    )
    .expect("byte fields are sliceable");
}

#[test]
fn a_reversed_byte_slice_is_rejected() {
    let error = Filter::compile(
        "padding.bytes[4:2] == aa",
        &fixture_registry(),
        Options::default(),
    )
    .expect_err("a reversed slice has no meaning");
    assert!(matches!(error, Error::Syntax { .. }), "{error:?}");
}

#[test]
fn unterminated_quotes_and_slices_are_syntax_errors() {
    assert!(matches!(
        compile("frame.len == \"open"),
        Err(Error::Syntax { .. })
    ));
    assert!(matches!(
        compile("frame.len[0:2"),
        Err(Error::Syntax { .. })
    ));
}

#[test]
fn deeply_nested_source_does_not_exhaust_the_parser_stack() {
    // Well within the configured bound, but deep enough that a recursive
    // descent parser would be visible in a stack profile.
    let depth = MAX_FILTER_NESTING;
    let source = format!("{}frame.len{}", "(".repeat(depth), ")".repeat(depth));
    compile(&source).expect("nesting at the limit compiles");

    let too_deep = format!(
        "{}frame.len{}",
        "(".repeat(depth + 1),
        ")".repeat(depth + 1)
    );
    assert!(matches!(
        compile(&too_deep),
        Err(Error::NestingLimit { .. })
    ));
}

// --- evaluation ------------------------------------------------------------
