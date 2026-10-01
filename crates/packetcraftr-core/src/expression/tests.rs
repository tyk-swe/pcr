// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn values(max_nesting: usize) -> value::Parser {
    value::Parser::new(&Limits {
        max_nesting,
        ..Limits::default()
    })
}

#[test]
fn top_level_splitting_ignores_nested_and_quoted_delimiters() {
    assert_eq!(
        syntax::split_top_level_bounded(0, r#"alpha(value="x/y")/beta(values=[1,2])"#, '/', None)
            .unwrap(),
        [(0, r#"alpha(value="x/y")"#), (19, "beta(values=[1,2])")]
    );
    assert_eq!(
        syntax::split_top_level_bounded(10, r#"a="x=y",b=[1,2]"#, ',', None).unwrap(),
        [(10, r#"a="x=y""#), (18, "b=[1,2]")]
    );
    assert!(matches!(
        syntax::split_top_level_bounded(0, "a/b", '/', Some(1)),
        Err(Error::LayerLimit { limit: 1 })
    ));
    assert!(matches!(
        syntax::split_top_level_bounded(0, "a]", '/', None),
        Err(Error::Syntax { offset: 1, .. })
    ));
    assert!(matches!(
        syntax::split_top_level_bounded(10, "a]", '/', None),
        Err(Error::Syntax { offset: 11, .. })
    ));
    assert!(matches!(
        syntax::split_top_level_bounded(0, "a([", '/', None),
        Err(Error::Syntax { offset: 3, .. })
    ));
}

#[test]
fn layer_arguments_reject_duplicates_missing_values_and_unbalanced_delimiters() {
    let (name, fields) = parse_layer(
        0,
        r#"TCP(source_port=1, options=[1, [2, 3]], label="a,b")"#,
        4,
        &mut values(8),
    )
    .unwrap();
    assert_eq!(name, "tcp");
    assert_eq!(fields.len(), 3);

    let duplicate =
        parse_layer(0, "tcp(source_port=1,SOURCE_PORT=2)", 4, &mut values(8)).unwrap_err();
    assert!(matches!(
        duplicate,
        Error::DuplicateField {
            layer: 4,
            ref field
        } if field == "source_port"
    ));

    for (source, expected) in [
        ("", "empty layer"),
        ("(field=1)", "missing protocol name"),
        ("tcp(field=1", "arguments must end"),
        ("tcp(field)", "expected field=value"),
        ("tcp(=1)", "empty field name"),
        ("tcp(field=)", "missing field value"),
        ("tcp(field=[1,2)", "unterminated quote or delimiter"),
    ] {
        let error = parse_layer(0, source, 0, &mut values(8)).expect_err(source);
        assert!(error.to_string().contains(expected), "{source}: {error}");
    }
}

#[test]
fn expression_limits_and_registry_failures_report_the_exact_boundary() {
    let registry = crate::protocol::builtin::registry();

    assert!(matches!(
        parse(" ", &registry, Limits::default()),
        Err(Error::Empty)
    ));
    assert!(matches!(
        parse(
            "ipv4",
            &registry,
            Limits {
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
        parse(
            "ipv4",
            &registry,
            Limits {
                max_nesting: MAX_EXPRESSION_NESTING + 1,
                ..Limits::default()
            }
        ),
        Err(Error::InvalidNestingLimit { .. })
    ));
    assert!(matches!(
        parse(
            "ipv4/udp",
            &registry,
            Limits {
                max_layers: 1,
                ..Limits::default()
            }
        ),
        Err(Error::LayerLimit { limit: 1 })
    ));
    assert!(matches!(
        parse("unknown_fixture", &registry, Limits::default()),
        Err(Error::UnknownProtocol { layer: 0, .. })
    ));
    assert!(matches!(
        parse("ipv4(source=not-an-address)", &registry, Limits::default()),
        Err(Error::Layer { layer: 0, .. })
    ));
}

#[test]
fn the_generated_budget_spans_every_layer_of_an_expression() {
    let registry = crate::protocol::builtin::registry();
    let source = "raw(bytes=zeros(6))/raw(bytes=zeros(6))";
    assert!(
        parse(
            source,
            &registry,
            Limits {
                max_generated_bytes: 12,
                ..Limits::default()
            }
        )
        .is_ok()
    );
    assert!(matches!(
        parse(
            source,
            &registry,
            Limits {
                max_generated_bytes: 11,
                ..Limits::default()
            }
        ),
        Err(Error::GeneratedBytesLimit {
            actual: 12,
            limit: 11
        })
    ));
}
