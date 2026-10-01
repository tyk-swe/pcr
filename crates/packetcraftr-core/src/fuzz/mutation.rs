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
    use crate::protocol::network::Ipv4;
    use crate::protocol::transport::Udp;
    use crate::protocol::tunnel::Mpls;
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
    fn boundary_mutations_fall_back_to_stable_numeric_extremes_for_an_unprobeable_field() {
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
                    &Raw::default(),
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
                    &Raw::default(),
                    &FieldValue::Signed(42),
                    0,
                    round as u64,
                    limits(32, 4),
                ),
                FieldValue::Signed(expected)
            );
        }
    }

    fn boundary_values(layer: &dyn Layer, field: &str, limits: Limits) -> Vec<u64> {
        let mut target = resolved(FieldKind::Unsigned);
        target.path = field.parse().expect("field path");
        let original = layer.field(field).expect("reflected field");
        let mut values = Vec::new();
        // the first full cycle visits every candidate, whatever their number
        for round in 0..16 {
            let FieldValue::Unsigned(value) = mutation_value(
                Strategy::Boundary,
                &target,
                layer,
                &original,
                0,
                round,
                limits,
            ) else {
                panic!("boundary values of an unsigned field stay unsigned");
            };
            if !values.contains(&value) {
                values.push(value);
            }
        }
        values.sort_unstable();
        values
    }

    #[test]
    fn boundary_values_follow_each_fields_accepted_width() {
        let ipv4 = Ipv4::default();
        assert_eq!(
            boundary_values(&ipv4, "fragment_offset", limits(32, 4)),
            [0, 1, 0x1000, 0x1ffe, 0x1fff, 0x2000]
        );
        assert_eq!(
            boundary_values(&ipv4, "ttl", limits(32, 4)),
            [0, 1, 0x80, 0xfe, 0xff, 0x100]
        );
        assert_eq!(
            boundary_values(&Udp::default(), "source_port", limits(32, 4)),
            [0, 1, 0x8000, 0xfffe, 0xffff, 0x1_0000]
        );
        assert_eq!(
            boundary_values(&Mpls::default(), "traffic_class", limits(32, 4)),
            [0, 1, 4, 6, 7, 8]
        );
    }

    #[test]
    fn a_full_width_field_has_no_value_above_its_maximum() {
        assert_eq!(
            boundary_values(&TestWord::default(), "word", limits(32, 4)),
            [0, 1, 1 << 63, u64::MAX - 1, u64::MAX]
        );
    }

    #[test]
    fn a_limit_below_a_power_of_two_is_found_exactly() {
        let layer = TestWord {
            maximum: 100,
            ..TestWord::default()
        };
        assert_eq!(
            boundary_values(&layer, "word", limits(32, 4)),
            [0, 1, 64, 99, 100, 101]
        );
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

    #[test]
    fn a_limit_needing_more_than_the_probe_budget_reports_no_boundaries() {
        // 2 + 6 + 1 probes, then 62 value bisections: more than 64 attempts
        let attempts = Arc::new(AtomicUsize::new(0));
        for maximum in [(1_u64 << 57) + 5, (1 << 62) + 5, (1 << 63) + 7] {
            attempts.store(0, Ordering::SeqCst);
            let layer = TestWord {
                maximum,
                attempts: Arc::clone(&attempts),
                value: 7,
            };
            let path = "word".parse().expect("field path");
            assert_eq!(
                width_boundaries(&layer, &path, limits(32, 4)),
                None,
                "maximum {maximum}"
            );
            assert_eq!(attempts.load(Ordering::SeqCst), MAX_WIDTH_PROBES);
        }
    }

    #[test]
    fn a_spent_probe_budget_reports_no_maximum_instead_of_a_lower_bound() {
        let path = "word".parse().expect("field path");
        for left in [1, 10, 40, 60] {
            let mut prober = WidthProber {
                layer: Box::new(TestWord {
                    maximum: (1 << 62) + 5,
                    ..TestWord::default()
                }),
                path: &path,
                attempts: MAX_WIDTH_PROBES - left,
            };
            assert_eq!(prober.accepted_maximum(), None, "{left} attempts left");
        }
    }

    #[test]
    fn a_field_budget_below_one_word_skips_probing() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let layer = TestWord {
            attempts: Arc::clone(&attempts),
            ..TestWord::default()
        };
        let values = boundary_values(&layer, "word", limits(4, 4));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert!(values.contains(&u64::from(u32::MAX)));
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
                    &Raw::default(),
                    &original,
                    19,
                    round,
                    limits,
                );
                let repeated = mutation_value(
                    Strategy::Boundary,
                    &resolved(kind),
                    &Raw::default(),
                    &original,
                    19,
                    round,
                    limits,
                );
                assert_eq!(first, repeated, "{kind:?} round {round}");
                assert!(
                    bounded_value_size(&first, limits.max_field_bytes, limits.max_list_items)
                        .is_ok(),
                    "{kind:?} round {round}: {first:?}"
                );
            }
        }
    }

    #[test]
    fn boundary_text_candidates_drop_values_over_the_field_ceiling() {
        let text = resolved(FieldKind::Text);
        let original = FieldValue::Text("original".to_owned());
        let candidates = |limits: Limits, count: u64| {
            (0..count)
                .map(|round| {
                    mutation_value(
                        Strategy::Boundary,
                        &text,
                        &Raw::default(),
                        &original,
                        0,
                        round,
                        limits,
                    )
                })
                .collect::<Vec<_>>()
        };
        let texts = |values: &[&str]| {
            values
                .iter()
                .map(|value| FieldValue::Text((*value).to_owned()))
                .collect::<Vec<_>>()
        };
        let control = "\u{1b}[31mcontrol\u{1b}[0m";

        assert_eq!(
            candidates(Limits::default(), 4),
            texts(&["", "A", control, &"x".repeat(256)])
        );
        assert_eq!(
            candidates(limits(16, 2), 4),
            texts(&["", "A", control, &"x".repeat(16)])
        );
        assert_eq!(
            candidates(limits(15, 2), 3),
            texts(&["", "A", &"x".repeat(15)])
        );
        assert_eq!(candidates(limits(1, 2), 3), texts(&["", "A", "x"]));
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
                &Raw::default(),
                &original,
                0xfeed_beef,
                17,
                limits,
            );
            let repeated = mutation_value(
                Strategy::Random,
                &resolved(kind),
                &Raw::default(),
                &original,
                0xfeed_beef,
                17,
                limits,
            );
            assert_eq!(first, repeated, "{kind:?}");
            assert!(
                bounded_value_size(&first, limits.max_field_bytes, limits.max_list_items).is_ok(),
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
                &Raw::default(),
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
            &Raw::default(),
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
                &Raw::default(),
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
            &Raw::default(),
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

    #[test]
    fn bounded_size_counts_list_structure_and_names_the_limit_it_exceeds() {
        let nested = FieldValue::List(vec![
            FieldValue::List(Vec::new()),
            FieldValue::Text("ab".to_owned()),
        ]);
        assert_eq!(bounded_value_size(&nested, 4, 2), Ok(4));
        assert_eq!(bounded_value_size(&nested, 3, 2), Err(ValueLimit::Bytes));
        assert_eq!(
            bounded_value_size(&nested, 16, 1),
            Err(ValueLimit::Items { items: 2 })
        );
        assert_eq!(
            bounded_value_size(&FieldValue::Ipv6(Ipv6Addr::LOCALHOST), 15, 2),
            Err(ValueLimit::Bytes)
        );

        let object = FieldValue::Object(
            [
                ("a".to_owned(), FieldValue::Bool(true)),
                ("b".to_owned(), FieldValue::Bool(true)),
                ("c".to_owned(), FieldValue::Bool(true)),
            ]
            .into(),
        );
        assert_eq!(
            bounded_value_size(&object, 16, 2),
            Err(ValueLimit::Items { items: 3 })
        );
        assert_eq!(bounded_value_size(&object, 5, 3), Err(ValueLimit::Bytes));

        let mut too_deep = FieldValue::Bool(false);
        for _ in 0..=MAX_VALUE_NESTING {
            too_deep = FieldValue::List(vec![too_deep]);
        }
        assert_eq!(
            bounded_value_size(&too_deep, 1_000, 1),
            Err(ValueLimit::Nesting)
        );
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
