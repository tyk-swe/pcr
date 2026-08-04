// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    Error, Filter, MAX_FILTER_NESTING, MAX_FILTER_SET_MEMBERS, MAX_FILTER_TERMS, Options, compile,
    empty_registry,
};

#[test]
fn an_empty_filter_is_rejected() {
    assert!(matches!(compile(""), Err(Error::Empty)));
    assert!(matches!(compile("   \t "), Err(Error::Empty)));
}

#[test]
fn source_longer_than_the_byte_limit_is_rejected_before_parsing() {
    let options = Options {
        max_bytes: 8,
        ..Options::default()
    };
    let error =
        Filter::compile("aaaaaaaaaaaaaaaa", &empty_registry(), options.clone()).unwrap_err();
    assert!(matches!(
        error,
        Error::SizeLimit {
            actual: 16,
            limit: 8
        }
    ));

    // The bound is checked before anything scans the source, so oversized
    // whitespace is refused on length rather than examined and called empty.
    let error = Filter::compile("                ", &empty_registry(), options).unwrap_err();
    assert!(matches!(error, Error::SizeLimit { .. }));
}

#[test]
fn nesting_beyond_the_limit_is_rejected() {
    let options = Options {
        max_nesting: 4,
        ..Options::default()
    };
    let source = "(((((frame.len)))))";
    let error = Filter::compile(source, &empty_registry(), options).unwrap_err();
    assert!(matches!(error, Error::NestingLimit { limit: 4 }));
}

#[test]
fn a_nesting_limit_above_the_stable_maximum_is_rejected() {
    let options = Options {
        max_nesting: MAX_FILTER_NESTING + 1,
        ..Options::default()
    };
    let error = Filter::compile("frame.len", &empty_registry(), options).unwrap_err();
    assert!(matches!(error, Error::InvalidNestingLimit { .. }));
}

#[test]
fn more_terms_than_the_limit_are_rejected() {
    let options = Options {
        max_terms: 2,
        ..Options::default()
    };
    let source = "frame.len && frame.cap_len && frame.number";
    let error = Filter::compile(source, &empty_registry(), options).unwrap_err();
    assert!(matches!(error, Error::TermLimit { limit: 2 }));
}

#[test]
fn a_set_larger_than_the_limit_is_rejected() {
    let options = Options {
        max_set_members: 2,
        ..Options::default()
    };
    let source = "frame.len in {1, 2, 3}";
    let error = Filter::compile(source, &empty_registry(), options).unwrap_err();
    assert!(matches!(error, Error::SetMemberLimit { limit: 2 }));
}

#[test]
fn limits_above_the_stable_maxima_are_rejected_as_invalid_options() {
    let terms = Options {
        max_terms: MAX_FILTER_TERMS + 1,
        ..Options::default()
    };
    assert!(matches!(
        Filter::compile("frame.len", &empty_registry(), terms),
        Err(Error::InvalidTermLimit { .. })
    ));

    let members = Options {
        max_set_members: MAX_FILTER_SET_MEMBERS + 1,
        ..Options::default()
    };
    assert!(matches!(
        Filter::compile("frame.len", &empty_registry(), members),
        Err(Error::InvalidSetMemberLimit { .. })
    ));
}
