// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic field-value mutation strategies and shrinking.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::field::{FieldKind, FieldValue};
use bytes::Bytes;

use super::MAX_VALUE_NESTING;
use super::prepare::ResolvedField;
use super::request::{Limits, Strategy};
use super::rng::SplitMix64;

pub(super) fn mutation_value(
    strategy: Strategy,
    field: &ResolvedField,
    original: &FieldValue,
    seed: u64,
    round: u64,
    limits: Limits,
) -> FieldValue {
    let mut random = SplitMix64::new(seed ^ round.rotate_left(17));
    match strategy {
        Strategy::Boundary => boundary_value(field.kind, original, seed, round, limits),
        Strategy::Random => random_value(field.kind, original, &mut random, limits),
        Strategy::BitFlip => bit_flip_value(original, &mut random, limits.max_field_bytes),
        Strategy::Malformed => malformed_value(field.kind, original, &mut random, round, limits),
    }
}

#[expect(
    clippy::indexing_slicing,
    reason = "`index_from` reduces the selector below the length of the table it indexes"
)]
fn boundary_value(
    kind: FieldKind,
    original: &FieldValue,
    seed: u64,
    round: u64,
    limits: Limits,
) -> FieldValue {
    let selector = seed.wrapping_add(round);
    match kind {
        FieldKind::Bool => FieldValue::Bool(!original.as_bool().unwrap_or(false)),
        FieldKind::Unsigned => {
            const VALUES: &[u64] = &[
                0,
                1,
                u8::MAX as u64,
                u16::MAX as u64,
                u32::MAX as u64,
                u64::MAX,
            ];
            FieldValue::Unsigned(VALUES[index_from(selector, VALUES.len())])
        }
        FieldKind::Signed => {
            const VALUES: &[i64] = &[0, 1, -1, i8::MIN as i64, i8::MAX as i64, i64::MIN, i64::MAX];
            FieldValue::Signed(VALUES[index_from(selector, VALUES.len())])
        }
        FieldKind::Text => {
            let values = [
                String::new(),
                "A".to_owned(),
                "\u{1b}[31mcontrol\u{1b}[0m".to_owned(),
                "x".repeat(limits.max_field_bytes.min(256)),
            ];
            FieldValue::Text(values[index_from(selector, values.len())].clone())
        }
        FieldKind::Bytes => {
            let lengths = [0, 1, limits.max_field_bytes.min(64), limits.max_field_bytes];
            let length = lengths[index_from(selector, lengths.len())];
            // The fill byte reads a selector bit the length index does not, so
            // every (length, fill) pair is reachable rather than half of them.
            let fill = if selector & 0b100 == 0 { 0x00 } else { 0xff };
            FieldValue::Bytes(Bytes::from(vec![fill; length]))
        }
        FieldKind::Ipv4 => {
            const VALUES: &[Ipv4Addr] = &[
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::BROADCAST,
                Ipv4Addr::new(192, 0, 2, 1),
            ];
            FieldValue::Ipv4(VALUES[index_from(selector, VALUES.len())])
        }
        FieldKind::Ipv6 => {
            let values = [
                Ipv6Addr::UNSPECIFIED,
                Ipv6Addr::LOCALHOST,
                "2001:db8::1".parse().expect("constant IPv6 address"),
                Ipv6Addr::from(u128::MAX),
            ];
            FieldValue::Ipv6(values[index_from(selector, values.len())])
        }
        FieldKind::Mac => {
            let values = [[0; 6], [0xff; 6], [0x02, 0, 0, 0, 0, 1]];
            FieldValue::Mac(values[index_from(selector, values.len())])
        }
        FieldKind::List => match original {
            FieldValue::List(values) if selector & 1 == 1 => {
                let candidate = FieldValue::List(values.first().cloned().into_iter().collect());
                if bounded_value_size(&candidate, limits.max_field_bytes, limits.max_list_items)
                    .is_some()
                {
                    candidate
                } else {
                    FieldValue::List(Vec::new())
                }
            }
            _ => FieldValue::List(Vec::new()),
        },
    }
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "each arm reinterprets or narrows uniformly random bits to fill the requested field \
              width, so discarding the surplus bits is the generator's purpose"
)]
pub(super) fn random_value(
    kind: FieldKind,
    original: &FieldValue,
    random: &mut SplitMix64,
    limits: Limits,
) -> FieldValue {
    match kind {
        FieldKind::Bool => FieldValue::Bool(random.next_u64() & 1 != 0),
        FieldKind::Unsigned => FieldValue::Unsigned(random.next_u64()),
        FieldKind::Signed => FieldValue::Signed(random.next_u64() as i64),
        FieldKind::Text => {
            let length = bounded_length(random, limits.max_field_bytes.min(256));
            let mut value = String::with_capacity(length);
            for _ in 0..length {
                #[expect(
                    clippy::arithmetic_side_effects,
                    reason = "the printable offset is below 95, so `b' ' + offset` stays under u8::MAX"
                )]
                let character = match random.next_u64() % 20 {
                    0 => '\u{1b}',
                    1 => '\n',
                    _ => char::from(b' ' + (random.next_u64() % 95) as u8),
                };
                value.push(character);
            }
            FieldValue::Text(value)
        }
        FieldKind::Bytes => {
            let length = bounded_length(random, limits.max_field_bytes);
            FieldValue::Bytes(Bytes::from(random.bytes(length)))
        }
        FieldKind::Ipv4 => FieldValue::Ipv4(Ipv4Addr::from(random.next_u64() as u32)),
        FieldKind::Ipv6 => {
            let value = (u128::from(random.next_u64()) << 64) | u128::from(random.next_u64());
            FieldValue::Ipv6(Ipv6Addr::from(value))
        }
        FieldKind::Mac => {
            let mut value = [0_u8; 6];
            value.copy_from_slice(&random.bytes(6));
            FieldValue::Mac(value)
        }
        FieldKind::List => match original {
            FieldValue::List(values) if !values.is_empty() => {
                let count = bounded_length(random, limits.max_list_items.min(values.len()));
                let mut output = Vec::with_capacity(count);
                let mut bytes = 0_usize;
                for _ in 0..count {
                    #[expect(
                        clippy::indexing_slicing,
                        reason = "`index_below` reduces below `values.len()`, which the guard proves non-zero"
                    )]
                    let value = &values[index_below(random, values.len())];
                    let remaining = limits
                        .max_field_bytes
                        .saturating_sub(bytes)
                        .saturating_sub(1);
                    let Some(value_bytes) =
                        bounded_value_size(value, remaining, limits.max_list_items)
                    else {
                        break;
                    };
                    let Some(next_bytes) = bytes
                        .checked_add(1)
                        .and_then(|total| total.checked_add(value_bytes))
                    else {
                        break;
                    };
                    if next_bytes > limits.max_field_bytes {
                        break;
                    }
                    output.push(value.clone());
                    bytes = next_bytes;
                }
                FieldValue::List(output)
            }
            _ => FieldValue::List(Vec::new()),
        },
    }
}

/// Measures one reflected value against the bytes a budget still allows.
///
/// Returns [`None`] when the value does not fit, holds more list items than
/// `max_list_items`, or nests deeper than [`MAX_VALUE_NESTING`].
pub(super) fn bounded_value_size(
    value: &FieldValue,
    remaining: usize,
    max_list_items: usize,
) -> Option<usize> {
    bounded_size_at(value, remaining, max_list_items, 0)
}

fn bounded_size_at(
    value: &FieldValue,
    remaining: usize,
    max_list_items: usize,
    depth: usize,
) -> Option<usize> {
    if depth > MAX_VALUE_NESTING {
        return None;
    }
    let size = match value {
        FieldValue::Bool(_) => 1,
        FieldValue::Unsigned(_) | FieldValue::Signed(_) => 8,
        FieldValue::Text(value) => value.len(),
        FieldValue::Bytes(value) => value.len(),
        FieldValue::Ipv4(_) => 4,
        FieldValue::Ipv6(_) => 16,
        FieldValue::Mac(_) => 6,
        FieldValue::List(values) => {
            if values.len() > max_list_items {
                return None;
            }
            // Charge every list node even when it contains an otherwise
            // zero-byte nested list. This bounds structural cloning as well
            // as scalar and byte payload retention.
            let mut total = values.len();
            if total > remaining {
                return None;
            }
            for value in values {
                let value_size = bounded_size_at(
                    value,
                    remaining.saturating_sub(total),
                    max_list_items,
                    depth.checked_add(1)?,
                )?;
                total = total.checked_add(value_size)?;
                if total > remaining {
                    return None;
                }
            }
            total
        }
    };
    (size <= remaining).then_some(size)
}

fn bit_flip_value(original: &FieldValue, random: &mut SplitMix64, maximum: usize) -> FieldValue {
    let FieldValue::Bytes(bytes) = original else {
        return original.clone();
    };
    if bytes.is_empty() {
        return FieldValue::Bytes(Bytes::from_static(&[1]));
    }
    if bytes.len() > maximum {
        if maximum == 0 {
            // A zero field budget leaves no byte to flip, so the bounded
            // prefix is empty and the mutation reduces to the empty value.
            return FieldValue::Bytes(Bytes::new());
        }
        // Replacing an oversized value with a bounded prefix keeps allocation
        // within the mutation budget and makes the reduction explicit.
        #[expect(
            clippy::indexing_slicing,
            reason = "the branch is entered only when `bytes.len() > maximum`"
        )]
        let mut value = bytes[..maximum].to_vec();
        let index = index_below(random, value.len());
        #[expect(
            clippy::indexing_slicing,
            reason = "`index_below` reduces below `value.len()`"
        )]
        {
            value[index] ^= 1 << (random.next_u64() % 8);
        }
        return FieldValue::Bytes(Bytes::from(value));
    }
    let mut value = bytes.to_vec();
    let index = index_below(random, value.len());
    #[expect(
        clippy::indexing_slicing,
        reason = "`index_below` reduces below `value.len()`, which the emptiness check above proves non-zero"
    )]
    {
        value[index] ^= 1 << (random.next_u64() % 8);
    }
    FieldValue::Bytes(Bytes::from(value))
}

fn malformed_value(
    kind: FieldKind,
    original: &FieldValue,
    random: &mut SplitMix64,
    round: u64,
    limits: Limits,
) -> FieldValue {
    if kind == FieldKind::Unsigned {
        if limits.max_field_bytes == 0 {
            // No field budget leaves no room for a reflective type change, so
            // the malformed value stays inside the numeric domain.
            return FieldValue::Unsigned(random.next_u64() & u16::MAX as u64);
        }
        if round & 1 == 0 {
            return FieldValue::Unsigned(random.next_u64() & u16::MAX as u64);
        }
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "`index_below` returns at most 3 here, so the increment cannot overflow"
        )]
        let length = 1 + index_below(random, limits.max_field_bytes.min(4));
        return FieldValue::Bytes(Bytes::from(random.bytes(length)));
    }
    random_value(kind, original, random, limits)
}

fn bounded_length(random: &mut SplitMix64, maximum: usize) -> usize {
    if maximum == 0 {
        0
    } else {
        index_below(random, maximum.saturating_add(1))
    }
}

/// Reduce an arbitrary 64-bit word into `0..exclusive_maximum`.
///
/// Every selector in this module indexes a slice this way, so the one narrowing
/// conversion the reduction needs lives here rather than at each call site.
///
/// A zero bound has no valid index; validated [`Limits`] never produce one,
/// and the reduction yields `0` rather than dividing by zero if one arrives.
///
/// [`Limits`]: Limits
pub(super) fn index_from(word: u64, exclusive_maximum: usize) -> usize {
    debug_assert!(exclusive_maximum != 0);
    let Some(remainder) = word.checked_rem(exclusive_maximum as u64) else {
        return 0;
    };
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the remainder is below exclusive_maximum, which is a usize"
    )]
    let index = remainder as usize;
    index
}

fn index_below(random: &mut SplitMix64, exclusive_maximum: usize) -> usize {
    index_from(random.next_u64(), exclusive_maximum)
}

pub(super) fn shrink_values(value: &FieldValue, maximum: usize) -> Vec<FieldValue> {
    let mut values = Vec::new();
    let mut push = |candidate: FieldValue| {
        if values.len() < maximum && &candidate != value && !values.contains(&candidate) {
            values.push(candidate);
        }
    };
    match value {
        FieldValue::Bool(_) => push(FieldValue::Bool(false)),
        FieldValue::Unsigned(value) => {
            push(FieldValue::Unsigned(0));
            if *value > 1 {
                push(FieldValue::Unsigned(1));
                push(FieldValue::Unsigned(*value / 2));
            }
        }
        FieldValue::Signed(value) => {
            push(FieldValue::Signed(0));
            if value.unsigned_abs() > 1 {
                push(FieldValue::Signed(value.signum()));
                push(FieldValue::Signed(*value / 2));
            }
        }
        FieldValue::Text(value) => {
            push(FieldValue::Text(String::new()));
            if value.len() > 1 {
                push(FieldValue::Text(
                    value.chars().take(value.chars().count() / 2).collect(),
                ));
            }
        }
        FieldValue::Bytes(value) => {
            push(FieldValue::Bytes(Bytes::new()));
            if value.len() > 1
                && let Some(shrunk) = crate::byte_slice::checked_slice(value, 0, value.len() / 2)
            {
                push(FieldValue::Bytes(shrunk));
            }
            if !value.is_empty() {
                push(FieldValue::Bytes(Bytes::from(vec![0; value.len()])))
            }
        }
        FieldValue::Ipv4(_) => push(FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED)),
        FieldValue::Ipv6(_) => push(FieldValue::Ipv6(Ipv6Addr::UNSPECIFIED)),
        FieldValue::Mac(_) => push(FieldValue::Mac([0; 6])),
        FieldValue::List(value) => {
            push(FieldValue::List(Vec::new()));
            if value.len() > 1 {
                #[expect(
                    clippy::indexing_slicing,
                    reason = "`value.len() / 2` is below `value.len()`, which the guard proves is above 1"
                )]
                {
                    push(FieldValue::List(value[..value.len() / 2].to_vec()));
                }
            }
        }
    }
    values
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;
    use crate::fuzz::request::Target;

    fn resolved(kind: FieldKind) -> ResolvedField {
        ResolvedField {
            target: Target {
                layer: 0,
                field: "fixture".to_owned(),
            },
            protocol: "fixture".to_owned(),
            kind,
            is_derived: false,
        }
    }

    fn limits(max_field_bytes: usize, max_list_items: usize) -> Limits {
        Limits {
            max_field_bytes,
            max_list_items,
            ..Limits::default()
        }
    }

    #[test]
    fn boundary_mutations_cycle_through_stable_numeric_extremes() {
        let unsigned = resolved(FieldKind::Unsigned);
        let signed = resolved(FieldKind::Signed);
        let expected_unsigned = [
            0,
            1,
            u8::MAX as u64,
            u16::MAX as u64,
            u32::MAX as u64,
            u64::MAX,
        ];
        let expected_signed = [0, 1, -1, i8::MIN as i64, i8::MAX as i64, i64::MIN, i64::MAX];

        for (round, expected) in expected_unsigned.into_iter().enumerate() {
            assert_eq!(
                mutation_value(
                    Strategy::Boundary,
                    &unsigned,
                    &FieldValue::Unsigned(42),
                    0,
                    round as u64,
                    limits(32, 4),
                ),
                FieldValue::Unsigned(expected)
            );
        }
        for (round, expected) in expected_signed.into_iter().enumerate() {
            assert_eq!(
                mutation_value(
                    Strategy::Boundary,
                    &signed,
                    &FieldValue::Signed(42),
                    0,
                    round as u64,
                    limits(32, 4),
                ),
                FieldValue::Signed(expected)
            );
        }
    }

    #[test]
    fn every_boundary_kind_is_deterministic_and_respects_field_budgets() {
        let cases = [
            (FieldKind::Bool, FieldValue::Bool(true)),
            (FieldKind::Text, FieldValue::Text("original".to_owned())),
            (
                FieldKind::Bytes,
                FieldValue::Bytes(Bytes::from_static(b"original")),
            ),
            (
                FieldKind::Ipv4,
                FieldValue::Ipv4(Ipv4Addr::new(198, 51, 100, 9)),
            ),
            (FieldKind::Ipv6, FieldValue::Ipv6(Ipv6Addr::LOCALHOST)),
            (FieldKind::Mac, FieldValue::Mac([1, 2, 3, 4, 5, 6])),
            (
                FieldKind::List,
                FieldValue::List(vec![FieldValue::Bool(true)]),
            ),
        ];
        let limits = limits(16, 2);

        for (kind, original) in cases {
            for round in 0..4 {
                let first = mutation_value(
                    Strategy::Boundary,
                    &resolved(kind),
                    &original,
                    19,
                    round,
                    limits,
                );
                let repeated = mutation_value(
                    Strategy::Boundary,
                    &resolved(kind),
                    &original,
                    19,
                    round,
                    limits,
                );
                assert_eq!(first, repeated, "{kind:?} round {round}");
                assert!(
                    bounded_value_size(&first, limits.max_field_bytes, limits.max_list_items)
                        .is_some(),
                    "{kind:?} round {round}: {first:?}"
                );
            }
        }
    }

    #[test]
    fn random_mutations_are_reproducible_and_bounded_for_every_field_kind() {
        let originals = [
            (FieldKind::Bool, FieldValue::Bool(false)),
            (FieldKind::Unsigned, FieldValue::Unsigned(7)),
            (FieldKind::Signed, FieldValue::Signed(-7)),
            (FieldKind::Text, FieldValue::Text("text".to_owned())),
            (
                FieldKind::Bytes,
                FieldValue::Bytes(Bytes::from_static(b"bytes")),
            ),
            (FieldKind::Ipv4, FieldValue::Ipv4(Ipv4Addr::LOCALHOST)),
            (FieldKind::Ipv6, FieldValue::Ipv6(Ipv6Addr::LOCALHOST)),
            (FieldKind::Mac, FieldValue::Mac([0; 6])),
            (
                FieldKind::List,
                FieldValue::List(vec![
                    FieldValue::Text("a".to_owned()),
                    FieldValue::Bytes(Bytes::from_static(b"bc")),
                ]),
            ),
        ];
        let limits = limits(32, 3);

        for (kind, original) in originals {
            let first = mutation_value(
                Strategy::Random,
                &resolved(kind),
                &original,
                0xfeed_beef,
                17,
                limits,
            );
            let repeated = mutation_value(
                Strategy::Random,
                &resolved(kind),
                &original,
                0xfeed_beef,
                17,
                limits,
            );
            assert_eq!(first, repeated, "{kind:?}");
            assert!(
                bounded_value_size(&first, limits.max_field_bytes, limits.max_list_items).is_some(),
                "{kind:?}: {first:?}"
            );
        }
    }

    #[test]
    fn bit_flip_and_malformed_strategies_preserve_their_bounded_contracts() {
        let bytes = resolved(FieldKind::Bytes);
        assert_eq!(
            mutation_value(
                Strategy::BitFlip,
                &bytes,
                &FieldValue::Bytes(Bytes::new()),
                1,
                0,
                limits(4, 2),
            ),
            FieldValue::Bytes(Bytes::from_static(&[1]))
        );

        let original = [0xaa; 8];
        let FieldValue::Bytes(flipped) = mutation_value(
            Strategy::BitFlip,
            &bytes,
            &FieldValue::Bytes(Bytes::copy_from_slice(&original)),
            2,
            0,
            limits(4, 2),
        ) else {
            panic!("byte mutation must remain bytes")
        };
        assert_eq!(flipped.len(), 4);
        assert_eq!(
            flipped
                .iter()
                .zip(&original)
                .map(|(mutated, original)| (mutated ^ original).count_ones())
                .sum::<u32>(),
            1
        );

        let unsigned = resolved(FieldKind::Unsigned);
        assert!(matches!(
            mutation_value(
                Strategy::Malformed,
                &unsigned,
                &FieldValue::Unsigned(1),
                3,
                0,
                limits(4, 2),
            ),
            FieldValue::Unsigned(0..=65_535)
        ));
        let FieldValue::Bytes(malformed) = mutation_value(
            Strategy::Malformed,
            &unsigned,
            &FieldValue::Unsigned(1),
            3,
            1,
            limits(4, 2),
        ) else {
            panic!("odd malformed round must change the reflective type")
        };
        assert!((1..=4).contains(&malformed.len()));
    }

    #[test]
    fn a_zero_field_budget_leaves_bit_flip_and_malformed_mutations_bounded() {
        let bytes = resolved(FieldKind::Bytes);
        assert_eq!(
            mutation_value(
                Strategy::BitFlip,
                &bytes,
                &FieldValue::Bytes(Bytes::from_static(b"abc")),
                5,
                0,
                limits(0, 2),
            ),
            FieldValue::Bytes(Bytes::new())
        );

        let unsigned = resolved(FieldKind::Unsigned);
        for round in 0..4 {
            assert!(
                matches!(
                    mutation_value(
                        Strategy::Malformed,
                        &unsigned,
                        &FieldValue::Unsigned(1),
                        5,
                        round,
                        limits(0, 2),
                    ),
                    FieldValue::Unsigned(0..=65_535)
                ),
                "round {round}"
            );
        }

        assert_eq!(
            mutation_value(
                Strategy::Random,
                &bytes,
                &FieldValue::Bytes(Bytes::from_static(b"abc")),
                5,
                0,
                limits(0, 2),
            ),
            FieldValue::Bytes(Bytes::new())
        );
    }

    #[test]
    fn bounded_size_counts_list_structure_and_rejects_depth_and_item_overflow() {
        let nested = FieldValue::List(vec![
            FieldValue::List(Vec::new()),
            FieldValue::Text("ab".to_owned()),
        ]);
        assert_eq!(bounded_value_size(&nested, 4, 2), Some(4));
        assert_eq!(bounded_value_size(&nested, 3, 2), None);
        assert_eq!(bounded_value_size(&nested, 16, 1), None);
        assert_eq!(
            bounded_value_size(&FieldValue::Ipv6(Ipv6Addr::LOCALHOST), 15, 2),
            None
        );

        let mut too_deep = FieldValue::Bool(false);
        for _ in 0..=MAX_VALUE_NESTING {
            too_deep = FieldValue::List(vec![too_deep]);
        }
        assert_eq!(bounded_value_size(&too_deep, 1_000, 1), None);
    }

    #[test]
    fn shrinking_is_stable_unique_unicode_safe_and_honors_the_step_limit() {
        assert_eq!(
            shrink_values(&FieldValue::Unsigned(10), 8),
            [
                FieldValue::Unsigned(0),
                FieldValue::Unsigned(1),
                FieldValue::Unsigned(5),
            ]
        );
        assert_eq!(
            shrink_values(&FieldValue::Signed(-10), 8),
            [
                FieldValue::Signed(0),
                FieldValue::Signed(-1),
                FieldValue::Signed(-5),
            ]
        );
        assert_eq!(
            shrink_values(&FieldValue::Text("éé".to_owned()), 8),
            [
                FieldValue::Text(String::new()),
                FieldValue::Text("é".to_owned()),
            ]
        );
        assert_eq!(
            shrink_values(&FieldValue::Bytes(Bytes::from_static(&[1, 2, 3, 4])), 8),
            [
                FieldValue::Bytes(Bytes::new()),
                FieldValue::Bytes(Bytes::from_static(&[1, 2])),
                FieldValue::Bytes(Bytes::from_static(&[0, 0, 0, 0])),
            ]
        );
        assert_eq!(
            shrink_values(&FieldValue::Unsigned(10), 1),
            [FieldValue::Unsigned(0)]
        );
        assert!(shrink_values(&FieldValue::Bool(false), 8).is_empty());
    }

    #[test]
    fn address_mac_and_list_shrinks_converge_on_canonical_empty_values() {
        assert_eq!(
            shrink_values(&FieldValue::Ipv4(Ipv4Addr::BROADCAST), 2),
            [FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED)]
        );
        assert_eq!(
            shrink_values(&FieldValue::Ipv6(Ipv6Addr::LOCALHOST), 2),
            [FieldValue::Ipv6(Ipv6Addr::UNSPECIFIED)]
        );
        assert_eq!(
            shrink_values(&FieldValue::Mac([1; 6]), 2),
            [FieldValue::Mac([0; 6])]
        );
        assert_eq!(
            shrink_values(
                &FieldValue::List(vec![FieldValue::Unsigned(1), FieldValue::Unsigned(2)]),
                2,
            ),
            [
                FieldValue::List(Vec::new()),
                FieldValue::List(vec![FieldValue::Unsigned(1)]),
            ]
        );
    }
}
