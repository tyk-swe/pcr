// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

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
