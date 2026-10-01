// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Cow;
use std::cmp::Ordering;

use memchr::memmem::Finder;

use super::lexer::CompareOperator;
use super::literal::{Literal, Range};
use crate::field::FieldValue;

pub(super) fn matches(value: &FieldValue, operator: CompareOperator, literal: &Literal) -> bool {
    if let Some(contained) = containment(value, literal) {
        // Prefix literals describe a set, so only membership is meaningful.
        return match operator {
            CompareOperator::Equal => contained,
            CompareOperator::NotEqual => !contained,
            _ => false,
        };
    }
    if let FieldValue::List(values) = value {
        return values
            .iter()
            .any(|element| matches(element, operator, literal));
    }
    let Some(ordering) = compare(value, literal) else {
        return false;
    };
    match operator {
        CompareOperator::Equal => ordering == Ordering::Equal,
        CompareOperator::NotEqual => ordering != Ordering::Equal,
        CompareOperator::Greater => ordering == Ordering::Greater,
        CompareOperator::GreaterOrEqual => ordering != Ordering::Less,
        CompareOperator::Less => ordering == Ordering::Less,
        CompareOperator::LessOrEqual => ordering != Ordering::Greater,
    }
}

fn containment(value: &FieldValue, literal: &Literal) -> Option<bool> {
    match (value, literal) {
        (FieldValue::Ipv4(address), Literal::Ipv4Net(network, prefix)) => {
            let mask = prefix_mask_u32(*prefix);
            Some(u32::from(*address) & mask == u32::from(*network) & mask)
        }
        (FieldValue::Ipv6(address), Literal::Ipv6Net(network, prefix)) => {
            let mask = prefix_mask_u128(*prefix);
            Some(u128::from(*address) & mask == u128::from(*network) & mask)
        }
        (_, Literal::Range(range)) => in_range(value, range),
        _ => None,
    }
}

/// None when the value is not of the range's kind, so `!=` rejects it as it does a prefix.
fn in_range(value: &FieldValue, range: &Range) -> Option<bool> {
    match (value, range) {
        (FieldValue::Unsigned(value), Range::Unsigned(low, high)) => {
            Some((*low..=*high).contains(value))
        }
        (FieldValue::Signed(value), Range::Unsigned(low, high)) => {
            Some(u64::try_from(*value).is_ok_and(|value| (*low..=*high).contains(&value)))
        }
        (FieldValue::Ipv4(value), Range::Ipv4(low, high)) => Some((*low..=*high).contains(value)),
        (FieldValue::Ipv6(value), Range::Ipv6(low, high)) => Some((*low..=*high).contains(value)),
        _ => None,
    }
}

fn prefix_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << u32::BITS.saturating_sub(u32::from(prefix))
    }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << u128::BITS.saturating_sub(u32::from(prefix))
    }
}

fn compare(value: &FieldValue, literal: &Literal) -> Option<Ordering> {
    match (value, literal) {
        (FieldValue::Bool(left), Literal::Bool(right)) => Some(left.cmp(right)),
        (FieldValue::Bool(left), Literal::Unsigned(right)) => Some(u64::from(*left).cmp(right)),
        (FieldValue::Unsigned(left), Literal::Unsigned(right)) => Some(left.cmp(right)),
        (FieldValue::Unsigned(left), Literal::Signed(right)) => {
            Some(i128::from(*left).cmp(&i128::from(*right)))
        }
        (FieldValue::Signed(left), Literal::Signed(right)) => Some(left.cmp(right)),
        (FieldValue::Signed(left), Literal::Unsigned(right)) => {
            Some(i128::from(*left).cmp(&i128::from(*right)))
        }
        (FieldValue::Text(left), Literal::Text(right)) => Some(left.as_str().cmp(right.as_str())),
        (FieldValue::Bytes(left), Literal::Bytes(right)) => Some(left.as_ref().cmp(right.as_ref())),
        (FieldValue::Bytes(left), Literal::Mac(right)) => Some(left.as_ref().cmp(right.as_slice())),
        (FieldValue::Bytes(left), Literal::Text(right)) => {
            Some(left.as_ref().cmp(right.as_bytes()))
        }
        (FieldValue::Bytes(left), Literal::Unsigned(right)) => match left.as_ref() {
            [only] => Some(u64::from(*only).cmp(right)),
            _ => None,
        },
        (FieldValue::Mac(left), Literal::Mac(right)) => Some(left.cmp(right)),
        (FieldValue::Mac(left), Literal::Bytes(right)) => Some(left.as_slice().cmp(right.as_ref())),
        (FieldValue::Ipv4(left), Literal::Ipv4(right)) => Some(left.cmp(right)),
        (FieldValue::Ipv6(left), Literal::Ipv6(right)) => Some(left.cmp(right)),
        _ => None,
    }
}

/// Tests `value & mask` against `expected`; only unsigned values have bits to mask.
pub(super) fn masked(
    value: &FieldValue,
    mask: u64,
    operator: CompareOperator,
    expected: u64,
) -> bool {
    match value {
        FieldValue::Unsigned(value) => matches(
            &FieldValue::Unsigned(value & mask),
            operator,
            &Literal::Unsigned(expected),
        ),
        _ => false,
    }
}

/// How `startswith`, `endswith`, `icontains`, and `iequals` read the haystack.
///
/// Folding is ASCII-only: `A..=Z` compare as `a..=z` and every other byte compares exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TextMode {
    Prefix,
    Suffix,
    ContainsFold,
    EqualsFold,
}

#[derive(Clone, Debug)]
pub(super) struct Needle {
    // The searcher's precomputed table is large, so it lives boxed.
    finder: Box<Finder<'static>>,
}

impl Needle {
    pub(super) fn new(literal: Literal) -> Result<Self, Literal> {
        match needle_bytes(&literal) {
            Some(bytes) => Ok(Self::from_bytes(bytes)),
            None => Err(literal),
        }
    }

    /// The needle for a text operator, lowered once if the operator folds case.
    pub(super) fn for_mode(literal: Literal, mode: TextMode) -> Result<Self, Literal> {
        let Some(bytes) = needle_bytes(&literal) else {
            return Err(literal);
        };
        Ok(match mode {
            TextMode::ContainsFold | TextMode::EqualsFold => {
                Self::from_bytes(&bytes.to_ascii_lowercase())
            }
            TextMode::Prefix | TextMode::Suffix => Self::from_bytes(bytes),
        })
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            finder: Box::new(Finder::new(bytes).into_owned()),
        }
    }

    fn bytes(&self) -> &[u8] {
        self.finder.needle()
    }

    fn find(&self, haystack: &[u8]) -> bool {
        self.bytes().is_empty() || self.finder.find(haystack).is_some()
    }
}

fn needle_bytes(literal: &Literal) -> Option<&[u8]> {
    match literal {
        Literal::Bytes(bytes) => Some(bytes.as_ref()),
        Literal::Text(text) => Some(text.as_bytes()),
        Literal::Mac(mac) => Some(mac.as_slice()),
        _ => None,
    }
}

fn haystack_bytes(value: &FieldValue) -> Option<&[u8]> {
    match value {
        FieldValue::Bytes(bytes) => Some(bytes.as_ref()),
        FieldValue::Text(text) => Some(text.as_bytes()),
        FieldValue::Mac(mac) => Some(mac.as_slice()),
        _ => None,
    }
}

pub(super) fn contains(value: &FieldValue, needle: &Needle) -> bool {
    if let FieldValue::List(values) = value {
        return values.iter().any(|element| contains(element, needle));
    }
    haystack_bytes(value).is_some_and(|haystack| needle.find(haystack))
}

/// Lists match when any element does. Folded searches lower the haystack once, so the cost stays linear.
pub(super) fn text_match(value: &FieldValue, needle: &Needle, mode: TextMode) -> bool {
    if let FieldValue::List(values) = value {
        return values
            .iter()
            .any(|element| text_match(element, needle, mode));
    }
    let Some(haystack) = haystack_bytes(value) else {
        return false;
    };
    match mode {
        TextMode::Prefix => haystack.starts_with(needle.bytes()),
        TextMode::Suffix => haystack.ends_with(needle.bytes()),
        TextMode::EqualsFold => haystack.eq_ignore_ascii_case(needle.bytes()),
        TextMode::ContainsFold => {
            if haystack.len() < needle.bytes().len() {
                return false;
            }
            let folded = if haystack.iter().any(u8::is_ascii_uppercase) {
                Cow::Owned(haystack.to_ascii_lowercase())
            } else {
                Cow::Borrowed(haystack)
            };
            needle.find(&folded)
        }
    }
}
