// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::field::{FieldKind, FieldValue, Path};
use crate::layer::Layer;
use bytes::Bytes;

use super::MAX_VALUE_NESTING;
use super::prepare::ResolvedField;
use super::request::{Limits, Strategy};
use super::rng::SplitMix64;

pub(super) fn mutation_value(
    strategy: Strategy,
    field: &ResolvedField,
    layer: &dyn Layer,
    original: &FieldValue,
    seed: u64,
    round: u64,
    limits: Limits,
) -> FieldValue {
    let mut random = SplitMix64::new(seed ^ round.rotate_left(17));
    match strategy {
        Strategy::Boundary => boundary_value(field, layer, original, seed, round, limits),
        Strategy::Random => random_value(field.kind, original, &mut random, limits),
        Strategy::BitFlip => bit_flip_value(original, &mut random, limits.max_field_bytes),
        Strategy::Malformed => malformed_value(field.kind, original, &mut random, round, limits),
    }
}

fn boundary_value(
    field: &ResolvedField,
    layer: &dyn Layer,
    original: &FieldValue,
    seed: u64,
    round: u64,
    limits: Limits,
) -> FieldValue {
    let selector = seed.wrapping_add(round);
    match field.kind {
        FieldKind::Bool => FieldValue::Bool(!original.as_bool().unwrap_or(false)),
        FieldKind::Unsigned => {
            const FALLBACK: &[u64] = &[
                0,
                1,
                u8::MAX as u64,
                u16::MAX as u64,
                u32::MAX as u64,
                u64::MAX,
            ];
            let values = width_boundaries(layer, &field.path, limits);
            let values = values.as_deref().unwrap_or(FALLBACK);
            FieldValue::Unsigned(values[index_from(selector, values.len())])
        }
        FieldKind::Signed => {
            const VALUES: &[i64] = &[0, 1, -1, i8::MIN as i64, i8::MAX as i64, i64::MIN, i64::MAX];
            FieldValue::Signed(VALUES[index_from(selector, VALUES.len())])
        }
        FieldKind::Text => {
            let mut values = vec![
                String::new(),
                "A".to_owned(),
                "\u{1b}[31mcontrol\u{1b}[0m".to_owned(),
                "x".repeat(limits.max_field_bytes.min(256)),
            ];
            values.retain(|value| value.len() <= limits.max_field_bytes);
            // the empty string always remains, so `values` is never empty
            FieldValue::Text(values.swap_remove(index_from(selector, values.len())))
        }
        FieldKind::Bytes => {
            let lengths = [0, 1, limits.max_field_bytes.min(64), limits.max_field_bytes];
            let length = lengths[index_from(selector, lengths.len())];
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
        FieldKind::Object => FieldValue::Object(Default::default()),
        FieldKind::List => match original {
            FieldValue::List(values) if selector & 1 == 1 => {
                let candidate = FieldValue::List(values.first().cloned().into_iter().collect());
                if bounded_value_size(&candidate, limits.max_field_bytes, limits.max_list_items)
                    .is_ok()
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

/// The most set attempts spent discovering one field's accepted maximum. Zero,
/// `u64::MAX`, six for the bit width and one above the power of two take at
/// most nine; the value bisection inside the rejected width gets the rest. A
/// limit that is not a power of two and needs more than the budget reports no
/// maximum, and the caller falls back to fixed extremes.
const MAX_WIDTH_PROBES: usize = 64;

/// Boundary values for an unsigned field, derived from the largest value the
/// layer accepts: zero, one, the half-range value, one below the maximum, the
/// maximum, and one above it. The value above the maximum is kept as
/// rejected-input evidence. `None` means the width could not be discovered, so
/// the caller falls back to fixed extremes.
///
/// Probing only ever writes to a clone of `layer` and spends at most
/// [`MAX_WIDTH_PROBES`] set attempts.
fn width_boundaries(layer: &dyn Layer, path: &Path, limits: Limits) -> Option<Vec<u64>> {
    // Every probe is an unsigned value, which the field budget has to admit.
    bounded_value_size(
        &FieldValue::Unsigned(u64::MAX),
        limits.max_field_bytes,
        limits.max_list_items,
    )
    .ok()?;
    let mut prober = WidthProber {
        layer: layer.clone_box(),
        path,
        attempts: 0,
    };
    let maximum = prober.accepted_maximum()?;
    let width = u64::BITS - maximum.leading_zeros();
    let mut values = vec![0, 1, maximum, maximum.saturating_sub(1)];
    if width > 1 {
        values.push(1 << (width - 1));
    }
    if let Some(above) = maximum.checked_add(1) {
        values.push(above);
    }
    values.sort_unstable();
    values.dedup();
    Some(values)
}

struct WidthProber<'a> {
    layer: Box<dyn Layer>,
    path: &'a Path,
    attempts: usize,
}

impl WidthProber<'_> {
    /// `None` once the attempt budget is spent.
    fn accepts(&mut self, value: u64) -> Option<bool> {
        if self.attempts >= MAX_WIDTH_PROBES {
            return None;
        }
        self.attempts += 1;
        Some(
            self.layer
                .set_field_path(self.path, FieldValue::Unsigned(value))
                .is_ok(),
        )
    }

    /// Assumes the accepted values are `0..=maximum`. Bisects the bit width
    /// first, then the value inside the rejected width, so a field bounded
    /// below a power of two still reports its exact maximum while attempts
    /// last. A field that refuses zero has no usable range, and a spent budget
    /// yields no maximum rather than a lower bound mistaken for one.
    fn accepted_maximum(&mut self) -> Option<u64> {
        if !self.accepts(0)? {
            return None;
        }
        if self.accepts(u64::MAX)? {
            return Some(u64::MAX);
        }
        let (mut accepted_bits, mut rejected_bits) = (0_u32, u64::BITS);
        while rejected_bits - accepted_bits > 1 {
            let middle = accepted_bits + (rejected_bits - accepted_bits) / 2;
            if self.accepts(width_mask(middle))? {
                accepted_bits = middle;
            } else {
                rejected_bits = middle;
            }
        }
        let mut accepted = width_mask(accepted_bits);
        let mut rejected = width_mask(rejected_bits);
        // a power-of-two limit is rejected by the very next value
        if rejected - accepted > 1 {
            // `accepted` is below `rejected`, so `accepted + 1` cannot overflow
            if !self.accepts(accepted + 1)? {
                return Some(accepted);
            }
            accepted += 1;
        }
        while rejected - accepted > 1 {
            let middle = accepted + (rejected - accepted) / 2;
            if self.accepts(middle)? {
                accepted = middle;
            } else {
                rejected = middle;
            }
        }
        Some(accepted)
    }
}

/// The largest value that fits in `bits` bits; `bits` is at most 64.
fn width_mask(bits: u32) -> u64 {
    u64::MAX.checked_shr(u64::BITS - bits).unwrap_or(0)
}

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
                // the printable offset is below 95, so `b' ' + offset` stays under u8::MAX
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
        FieldKind::Object => FieldValue::Object(Default::default()),
        FieldKind::List => match original {
            FieldValue::List(values) if !values.is_empty() => {
                let count = bounded_length(random, limits.max_list_items.min(values.len()));
                let mut output = Vec::with_capacity(count);
                let mut bytes = 0_usize;
                for _ in 0..count {
                    // `index_below` reduces below `values.len()`, which the guard proves non-zero
                    let value = &values[index_below(random, values.len())];
                    let remaining = limits
                        .max_field_bytes
                        .saturating_sub(bytes)
                        .saturating_sub(1);
                    let Ok(value_bytes) =
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ValueLimit {
    Bytes,
    Items { items: usize },
    Nesting,
}

pub(super) fn bounded_value_size(
    value: &FieldValue,
    remaining: usize,
    max_list_items: usize,
) -> Result<usize, ValueLimit> {
    bounded_size_at(value, remaining, max_list_items, 0)
}

fn bounded_size_at(
    value: &FieldValue,
    remaining: usize,
    max_list_items: usize,
    depth: usize,
) -> Result<usize, ValueLimit> {
    if depth > MAX_VALUE_NESTING {
        return Err(ValueLimit::Nesting);
    }
    let size = match value {
        FieldValue::Bool(_) => 1,
        FieldValue::Unsigned(_) | FieldValue::Signed(_) => 8,
        FieldValue::Text(value) => value.len(),
        FieldValue::Bytes(value) => value.len(),
        FieldValue::Ipv4(_) => 4,
        FieldValue::Ipv6(_) => 16,
        FieldValue::Mac(_) => 6,
        FieldValue::Object(values) => {
            if values.len() > max_list_items {
                return Err(ValueLimit::Items {
                    items: values.len(),
                });
            }
            let mut total = values.len();
            for (name, value) in values {
                total = total.checked_add(name.len()).ok_or(ValueLimit::Bytes)?;
                if total > remaining {
                    return Err(ValueLimit::Bytes);
                }
                total = total
                    .checked_add(bounded_size_at(
                        value,
                        remaining - total,
                        max_list_items,
                        depth.checked_add(1).ok_or(ValueLimit::Nesting)?,
                    )?)
                    .ok_or(ValueLimit::Bytes)?;
            }
            total
        }
        FieldValue::List(values) => {
            if values.len() > max_list_items {
                return Err(ValueLimit::Items {
                    items: values.len(),
                });
            }
            // Charge every list node, even a zero-byte nested list, to bound structural cloning.
            let mut total = values.len();
            if total > remaining {
                return Err(ValueLimit::Bytes);
            }
            for value in values {
                let value_size = bounded_size_at(
                    value,
                    remaining.saturating_sub(total),
                    max_list_items,
                    depth.checked_add(1).ok_or(ValueLimit::Nesting)?,
                )?;
                total = total.checked_add(value_size).ok_or(ValueLimit::Bytes)?;
                if total > remaining {
                    return Err(ValueLimit::Bytes);
                }
            }
            total
        }
    };
    if size <= remaining {
        Ok(size)
    } else {
        Err(ValueLimit::Bytes)
    }
}

fn bit_flip_value(original: &FieldValue, random: &mut SplitMix64, maximum: usize) -> FieldValue {
    let FieldValue::Bytes(bytes) = original else {
        return original.clone();
    };
    if bytes.is_empty() {
        return FieldValue::Bytes(Bytes::from_static(&[1]));
    }
    let kept = bytes.len().min(maximum);
    if kept == 0 {
        return FieldValue::Bytes(Bytes::new());
    }
    let mut value = bytes[..kept].to_vec();
    let index = index_below(random, kept);
    value[index] ^= 1 << (random.next_u64() % 8);
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
        if limits.max_field_bytes == 0 || round & 1 == 0 {
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
        index_below(random, maximum.saturating_add(1))
    }
}

/// A zero bound yields `0` rather than dividing by zero.
pub(super) fn index_from(word: u64, exclusive_maximum: usize) -> usize {
    debug_assert!(exclusive_maximum != 0);
    let Some(remainder) = word.checked_rem(exclusive_maximum as u64) else {
        return 0;
    };
    remainder as usize
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
                push(FieldValue::Bytes(Bytes::from(vec![0; value.len()])));
            }
        }
        FieldValue::Ipv4(_) => push(FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED)),
        FieldValue::Ipv6(_) => push(FieldValue::Ipv6(Ipv6Addr::UNSPECIFIED)),
        FieldValue::Mac(_) => push(FieldValue::Mac([0; 6])),
        FieldValue::Object(_) => push(FieldValue::Object(Default::default())),
        FieldValue::List(value) => {
            push(FieldValue::List(Vec::new()));
            if value.len() > 1 {
                push(FieldValue::List(value[..value.len() / 2].to_vec()));
            }
        }
    }
    values
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::fuzz::request::Target;
    use crate::layer::Raw;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn resolved(kind: FieldKind) -> ResolvedField {
        ResolvedField {
            target: Target {
                layer: 0,
                field: "fixture".to_owned(),
            },
            path: "fixture".parse().expect("fixture path"),
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
    fn width_probing_is_bounded_and_never_touches_the_case_layer() {
        let attempts = Arc::new(AtomicUsize::new(0));
        for maximum in [
            0,
            1,
            100,
            0x1fff,
            (1 << 40) + 12_345,
            (1 << 54) + 5,
            (1 << 62) - 1,
            (1 << 63) - 1,
            u64::MAX,
        ] {
            attempts.store(0, Ordering::SeqCst);
            let layer = TestWord {
                maximum,
                attempts: Arc::clone(&attempts),
                value: 7,
            };
            let path = "word".parse().expect("field path");
            let mut expected = vec![0, 1, maximum, maximum.saturating_sub(1)];
            let width = u64::BITS - maximum.leading_zeros();
            if width > 1 {
                expected.push(1 << (width - 1));
            }
            expected.extend(maximum.checked_add(1));
            expected.sort_unstable();
            expected.dedup();
            assert_eq!(
                width_boundaries(&layer, &path, limits(32, 4)),
                Some(expected),
                "maximum {maximum}"
            );
            let used = attempts.load(Ordering::SeqCst);
            assert!(
                (1..=MAX_WIDTH_PROBES).contains(&used),
                "maximum {maximum} used {used} attempts"
            );
            assert_eq!(layer.value, 7, "the case layer must stay untouched");
        }
    }

    #[derive(Clone, Debug)]
    struct TestWord {
        maximum: u64,
        attempts: Arc<AtomicUsize>,
        value: u64,
    }

    impl Default for TestWord {
        fn default() -> Self {
            Self {
                maximum: u64::MAX,
                attempts: Arc::default(),
                value: 0,
            }
        }
    }

    impl Layer for TestWord {
        fn schema(&self) -> &'static crate::layer::Schema {
            static SCHEMA: crate::layer::Schema = crate::layer::Schema {
                protocol: crate::layer::Id::new("test_word"),
                name: "Test word",
                fields: &[crate::layer::FieldSchema {
                    name: "word",
                    aliases: &[],
                    kind: FieldKind::Unsigned,
                    derived: false,
                    required: false,
                    description: "A counted unsigned word",
                    children: &[],
                }],
            };
            &SCHEMA
        }

        fn clone_box(&self) -> Box<dyn Layer> {
            Box::new(self.clone())
        }

        fn field(&self, name: &str) -> Option<FieldValue> {
            (name == "word").then_some(FieldValue::Unsigned(self.value))
        }

        fn set_field(&mut self, name: &str, value: FieldValue) -> Result<(), crate::field::Error> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            match (name, value) {
                ("word", FieldValue::Unsigned(value)) if value <= self.maximum => {
                    self.value = value;
                    Ok(())
                }
                _ => Err(crate::field::Error::OutOfRange {
                    protocol: self.schema().protocol,
                    field: name.to_owned(),
                }),
            }
        }
    }

    #[test]
    fn a_zero_field_budget_leaves_bit_flip_and_malformed_mutations_bounded() {
        let bytes = resolved(FieldKind::Bytes);
        assert_eq!(
            mutation_value(
                Strategy::BitFlip,
                &bytes,
                &Raw::default(),
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
                        &Raw::default(),
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
                &Raw::default(),
                &FieldValue::Bytes(Bytes::from_static(b"abc")),
                5,
                0,
                limits(0, 2),
            ),
            FieldValue::Bytes(Bytes::new())
        );
    }
}
