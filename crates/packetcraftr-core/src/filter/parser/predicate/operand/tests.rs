// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::filter::path::{FieldSource, FrameField};

#[test]
fn hex_looking_words_are_rejected_only_where_text_would_silently_become_ascii_bytes() {
    use crate::filter::path::FieldSpec;

    fn field(kinds: &[FieldKind]) -> FieldRef {
        FieldRef {
            source: FieldSource::Frame(FrameField::Number),
            slice: None,
            specs: kinds
                .iter()
                .map(|kind| FieldSpec::synthetic(*kind))
                .collect(),
            path: "fixture".to_owned(),
        }
    }

    fn word(text: &str) -> Vec<Spanned> {
        vec![Spanned {
            token: Token::Word(text.to_owned()),
            offset: 7,
        }]
    }

    for kinds in [
        &[FieldKind::Bytes][..],
        &[FieldKind::Mac],
        &[FieldKind::Bytes, FieldKind::Mac],
    ] {
        for malformed in ["c000", "c0:0"] {
            assert!(
                matches!(
                    parse_literal(&field(kinds), &word(malformed), 0, 0),
                    Err(Error::UnquotedByteWord {
                        offset: 7,
                        ref path,
                        ref literal,
                    }) if path == "fixture" && literal == malformed
                ),
                "{kinds:?} {malformed}"
            );
        }
        assert!(parse_literal(&field(kinds), &word("GET"), 0, 0).is_ok());
    }
    for kinds in [
        &[][..],
        &[FieldKind::Text],
        &[FieldKind::Bytes, FieldKind::Text],
        &[FieldKind::List],
    ] {
        for malformed in ["c000", "c0:0"] {
            assert!(
                matches!(
                    parse_literal(&field(kinds), &word(malformed), 0, 0),
                    Ok((Literal::Text(ref text), 1)) if text == malformed
                ),
                "{kinds:?} {malformed}"
            );
        }
    }
}
