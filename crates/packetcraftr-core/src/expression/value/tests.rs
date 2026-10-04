// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::Classified;
use crate::expression::parse_value;

use super::*;

fn parser(max_nesting: usize) -> Parser {
    Parser::new(&Limits {
        max_nesting,
        ..Limits::default()
    })
}

#[test]
fn recursive_list_before_descending() {
    assert_eq!(
        parse_value_bounded(0, "[]", 0, &mut parser(1)).unwrap(),
        FieldValue::List(Vec::new())
    );
    assert!(matches!(
        parse_value_bounded(0, "[]", 0, &mut parser(0)),
        Err(Error::NestingLimit { limit: 0 })
    ));
    assert!(matches!(
        parse_value_bounded(0, "[[1]]", 0, &mut parser(1)),
        Err(Error::NestingLimit { limit: 1 })
    ));
    assert!(matches!(
        parse_value_bounded(0, "[1", 0, &mut parser(8)),
        Err(Error::Syntax { .. })
    ));
}

#[test]
fn generated_charged_before_allocation() {
    let limits = |max_generated_bytes| Limits {
        max_generated_bytes,
        ..Limits::default()
    };
    assert!(parse_value("zeros(8)", limits(8)).is_ok());
    for (source, maximum, actual) in [
        ("zeros(9)", 8, 9),
        ("repeat(1,4294967296)", 8, 4_294_967_296),
        ("repeat(1,18446744073709551615)", 8, u64::MAX),
        ("[zeros(5),zeros(4)]", 8, 9),
        ("[repeat(1,8),cyclic(1)]", 8, 9),
        ("zeros(1)", 0, 1),
    ] {
        let error = parse_value(source, limits(maximum)).expect_err(source);
        assert!(
            matches!(error, Error::GeneratedBytesLimit { actual: seen, limit } if seen == actual && limit == maximum),
            "{source}: {error:?}"
        );
        assert_eq!(error.classification().code, "cli.expression_limit");
    }
    // the default budget refuses a request larger than any document value
    assert!(matches!(
        parse_value("zeros(1048577)", Limits::default()),
        Err(Error::GeneratedBytesLimit { .. })
    ));
}
