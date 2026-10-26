// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::super::prepare::ResolvedField;
use super::super::rng::SplitMix64;
use super::{ValueLimit, bounded_value_size, mutation_value, random_value};
use crate::field::{self, Path};
use crate::fuzz::{Limits, MAX_VALUE_NESTING, Strategy, Target};
use crate::layer::Raw;

fn limits_with_field_bytes(max_field_bytes: usize) -> Limits {
    Limits {
        max_field_bytes,
        ..Limits::default()
    }
}

#[test]
fn random_text_and_bytes_stay_within_max_field_bytes() {
    let original_bytes = field::Value::Bytes(Bytes::from_static(&[1, 2, 3]));
    let original_text = field::Value::Text("seed".to_owned());
    for seed in 0..64_u64 {
        for (kind, original) in [
            (field::Kind::Bytes, &original_bytes),
            (field::Kind::Text, &original_text),
        ] {
            let value = random_value(
                kind,
                original,
                &mut SplitMix64::new(seed),
                limits_with_field_bytes(16),
            );
            let length = match &value {
                field::Value::Bytes(bytes) => bytes.len(),
                field::Value::Text(text) => text.len(),
                other => panic!("expected bytes or text, got {other:?}"),
            };
            assert!(length <= 16, "seed {seed} produced {length} bytes");
            assert_eq!(
                value,
                random_value(
                    kind,
                    original,
                    &mut SplitMix64::new(seed),
                    limits_with_field_bytes(16),
                )
            );
        }
    }
    assert_eq!(
        random_value(
            field::Kind::Bytes,
            &original_bytes,
            &mut SplitMix64::new(1),
            limits_with_field_bytes(0),
        ),
        field::Value::Bytes(Bytes::new())
    );
    assert_eq!(
        random_value(
            field::Kind::Text,
            &original_text,
            &mut SplitMix64::new(1),
            limits_with_field_bytes(0),
        ),
        field::Value::Text(String::new())
    );
}

#[test]
fn bit_flip_changes_exactly_one_bit_within_max_field_bytes() {
    let original_bytes = Bytes::from((0_u8..12).collect::<Vec<_>>());
    let original = field::Value::Bytes(original_bytes.clone());
    let layer = Raw::new(original_bytes.clone());
    let field = ResolvedField {
        target: Target {
            layer: 0,
            field: "bytes".to_owned(),
        },
        path: Path::top_level("bytes"),
        protocol: "raw".to_owned(),
        kind: field::Kind::Bytes,
        is_derived: false,
    };
    for seed in 0..32_u64 {
        for max_field_bytes in [5, 64] {
            let limits = limits_with_field_bytes(max_field_bytes);
            let value = mutation_value(
                Strategy::BitFlip,
                &field,
                &layer,
                &original,
                seed,
                0,
                limits,
            );
            assert_eq!(
                value,
                mutation_value(
                    Strategy::BitFlip,
                    &field,
                    &layer,
                    &original,
                    seed,
                    0,
                    limits,
                )
            );
            let field::Value::Bytes(mutated) = &value else {
                panic!("expected bytes, got {value:?}");
            };
            let kept = original_bytes.len().min(max_field_bytes);
            assert_eq!(mutated.len(), kept);
            let differing_bits = mutated
                .iter()
                .zip(&original_bytes[..kept])
                .map(|(mutated, original)| (mutated ^ original).count_ones())
                .sum::<u32>();
            assert_eq!(differing_bits, 1, "seed {seed}");
        }
    }
}

#[test]
fn bounded_value_size_rejects_values_past_byte_item_and_nesting_limits() {
    let bytes = field::Value::Bytes(Bytes::from(vec![0; 4]));
    assert_eq!(bounded_value_size(&bytes, 4, 8), Ok(4));
    assert_eq!(bounded_value_size(&bytes, 3, 8), Err(ValueLimit::Bytes));

    let list = field::Value::List(vec![
        field::Value::Bool(true),
        field::Value::Bool(false),
        field::Value::Bool(true),
    ]);
    assert!(bounded_value_size(&list, usize::MAX, 3).is_ok());
    assert_eq!(
        bounded_value_size(&list, usize::MAX, 2),
        Err(ValueLimit::Items { items: 3 })
    );

    let nested = |depth: usize| {
        let mut value = field::Value::Bool(true);
        for _ in 0..depth {
            value = field::Value::List(vec![value]);
        }
        value
    };
    assert!(bounded_value_size(&nested(MAX_VALUE_NESTING / 2), 1_000_000, 8).is_ok());
    assert_eq!(
        bounded_value_size(&nested(MAX_VALUE_NESTING + 2), 1_000_000, 8),
        Err(ValueLimit::Nesting)
    );
}
