// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic field-value mutation strategies and shrinking.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use packetcraftr_packet::field::{FieldKind, FieldValue};

use super::super::engine::ResolvedField;
use super::super::execution::SplitMix64;
use super::super::model::{FuzzLimits, FuzzStrategy};

pub(super) fn mutation_value(
    strategy: FuzzStrategy,
    field: &ResolvedField,
    original: &FieldValue,
    seed: u64,
    round: u64,
    limits: FuzzLimits,
) -> FieldValue {
    let mut random = SplitMix64::new(seed ^ round.rotate_left(17));
    match strategy {
        FuzzStrategy::Boundary => boundary_value(field.kind, original, seed, round, limits),
        FuzzStrategy::Random => random_value(field.kind, original, &mut random, limits),
        FuzzStrategy::BitFlip => bit_flip_value(original, &mut random, limits.max_field_bytes),
        FuzzStrategy::Malformed => {
            malformed_value(field.kind, original, &mut random, round, limits)
        }
    }
}

fn boundary_value(
    kind: FieldKind,
    original: &FieldValue,
    seed: u64,
    round: u64,
    limits: FuzzLimits,
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
            FieldValue::Bytes(Bytes::from(vec![
                if selector & 1 == 0 { 0 } else { 0xff };
                length
            ]))
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
                if bounded_value_size(&candidate, limits.max_field_bytes, limits.max_list_items, 0)
                    .is_some()
                {
                    candidate
                } else {
                    FieldValue::List(Vec::new())
                }
            }
            _ => FieldValue::List(Vec::new()),
        },
        _ => original.clone(),
    }
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "each arm reinterprets or narrows uniformly random bits to fill the requested field \
              width, so discarding the surplus bits is the generator's purpose"
)]
pub(in crate::fuzz) fn random_value(
    kind: FieldKind,
    original: &FieldValue,
    random: &mut SplitMix64,
    limits: FuzzLimits,
) -> FieldValue {
    match kind {
        FieldKind::Bool => FieldValue::Bool(random.next_u64() & 1 != 0),
        FieldKind::Unsigned => FieldValue::Unsigned(random.next_u64()),
        FieldKind::Signed => FieldValue::Signed(random.next_u64() as i64),
        FieldKind::Text => {
            let length = bounded_length(random, limits.max_field_bytes.min(256));
            let mut value = String::with_capacity(length);
            for _ in 0..length {
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
                    let value = &values[index_below(random, values.len())];
                    let remaining = limits
                        .max_field_bytes
                        .saturating_sub(bytes)
                        .saturating_sub(1);
                    let Some(value_bytes) =
                        bounded_value_size(value, remaining, limits.max_list_items, 0)
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
        _ => original.clone(),
    }
}

pub(in crate::fuzz) fn bounded_value_size(
    value: &FieldValue,
    remaining: usize,
    max_list_items: usize,
    depth: usize,
) -> Option<usize> {
    if depth > 64 {
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
                let value_size = bounded_value_size(
                    value,
                    remaining.saturating_sub(total),
                    max_list_items,
                    depth + 1,
                )?;
                total = total.checked_add(value_size)?;
                if total > remaining {
                    return None;
                }
            }
            total
        }
        _ => return None,
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
        // Replacing an oversized value with a bounded prefix keeps allocation
        // within the mutation budget and makes the reduction explicit.
        let mut value = bytes[..maximum].to_vec();
        let index = index_below(random, value.len());
        value[index] ^= 1 << (random.next_u64() % 8);
        return FieldValue::Bytes(Bytes::from(value));
    }
    let mut value = bytes.to_vec();
    let index = index_below(random, value.len());
    value[index] ^= 1 << (random.next_u64() % 8);
    FieldValue::Bytes(Bytes::from(value))
}

fn malformed_value(
    kind: FieldKind,
    original: &FieldValue,
    random: &mut SplitMix64,
    round: u64,
    limits: FuzzLimits,
) -> FieldValue {
    if kind == FieldKind::Unsigned {
        if round & 1 == 0 {
            return FieldValue::Unsigned(random.next_u64() & u16::MAX as u64);
        }
        let length = 1 + index_below(random, limits.max_field_bytes.min(4));
        return FieldValue::Bytes(Bytes::from(random.bytes(length)));
    }
    random_value(kind, original, random, limits)
}

fn bounded_length(random: &mut SplitMix64, maximum: usize) -> usize {
    if maximum == 0 {
        0
    } else {
        index_below(random, maximum + 1)
    }
}

/// Reduce an arbitrary 64-bit word into `0..exclusive_maximum`.
///
/// Every selector in this module indexes a slice this way, so the one narrowing
/// conversion the reduction needs lives here rather than at each call site.
pub(super) fn index_from(word: u64, exclusive_maximum: usize) -> usize {
    debug_assert!(exclusive_maximum != 0);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the remainder is below exclusive_maximum, which is already a usize"
    )]
    let index = (word % exclusive_maximum as u64) as usize;
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
            if value.len() > 1 {
                push(FieldValue::Bytes(value.slice(..value.len() / 2)));
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
                push(FieldValue::List(value[..value.len() / 2].to_vec()));
            }
        }
        _ => {}
    }
    values
}
