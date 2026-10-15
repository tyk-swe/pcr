// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Cow;
use std::cmp::Ordering;

use memchr::memmem::Finder;

use super::lexer::CompareOperator;
use super::literal::{Literal, Range};
use crate::field;

pub(super) fn matches(value: &field::Value, operator: CompareOperator, literal: &Literal) -> bool {
    if let Some(contained) = containment(value, literal) {
        // Prefix literals describe a set, so only membership is meaningful.
        return match operator {
            CompareOperator::Equal => contained,
            CompareOperator::NotEqual => !contained,
            _ => false,
        };
    }
    if let field::Value::List(values) = value {
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

fn containment(value: &field::Value, literal: &Literal) -> Option<bool> {
    match (value, literal) {
        (field::Value::Ipv4(address), Literal::Ipv4Net(network, prefix)) => {
            let mask = prefix_mask_u32(*prefix);
            Some(u32::from(*address) & mask == u32::from(*network) & mask)
        }
        (field::Value::Ipv6(address), Literal::Ipv6Net(network, prefix)) => {
            let mask = prefix_mask_u128(*prefix);
            Some(u128::from(*address) & mask == u128::from(*network) & mask)
        }
        (_, Literal::Range(range)) => in_range(value, range),
        _ => None,
    }
}

/// None when the value is not of the range's kind, so `!=` rejects it as it does a prefix.
fn in_range(value: &field::Value, range: &Range) -> Option<bool> {
    match (value, range) {
        (field::Value::Unsigned(value), Range::Unsigned(low, high)) => {
            Some((*low..=*high).contains(value))
        }
        (field::Value::Signed(value), Range::Unsigned(low, high)) => {
            Some(u64::try_from(*value).is_ok_and(|value| (*low..=*high).contains(&value)))
        }
        (field::Value::Ipv4(value), Range::Ipv4(low, high)) => Some((*low..=*high).contains(value)),
        (field::Value::Ipv6(value), Range::Ipv6(low, high)) => Some((*low..=*high).contains(value)),
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

fn compare(value: &field::Value, literal: &Literal) -> Option<Ordering> {
    match (value, literal) {
        (field::Value::Bool(left), Literal::Bool(right)) => Some(left.cmp(right)),
        (field::Value::Bool(left), Literal::Unsigned(right)) => Some(u64::from(*left).cmp(right)),
        (field::Value::Unsigned(left), Literal::Unsigned(right)) => Some(left.cmp(right)),
        (field::Value::Unsigned(left), Literal::Signed(right)) => {
            Some(i128::from(*left).cmp(&i128::from(*right)))
        }
        (field::Value::Signed(left), Literal::Signed(right)) => Some(left.cmp(right)),
        (field::Value::Signed(left), Literal::Unsigned(right)) => {
            Some(i128::from(*left).cmp(&i128::from(*right)))
        }
        (field::Value::Text(left), Literal::Text(right)) => Some(left.as_str().cmp(right.as_str())),
        (field::Value::Bytes(left), Literal::Bytes(right)) => {
            Some(left.as_ref().cmp(right.as_ref()))
        }
        (field::Value::Bytes(left), Literal::Mac(right)) => {
            Some(left.as_ref().cmp(right.as_slice()))
        }
        (field::Value::Bytes(left), Literal::Text(right)) => {
            Some(left.as_ref().cmp(right.as_bytes()))
        }
        (field::Value::Bytes(left), Literal::Unsigned(right)) => match left.as_ref() {
            [only] => Some(u64::from(*only).cmp(right)),
            _ => None,
        },
        (field::Value::Mac(left), Literal::Mac(right)) => Some(left.cmp(right)),
        (field::Value::Mac(left), Literal::Bytes(right)) => {
            Some(left.as_slice().cmp(right.as_ref()))
        }
        (field::Value::Ipv4(left), Literal::Ipv4(right)) => Some(left.cmp(right)),
        (field::Value::Ipv6(left), Literal::Ipv6(right)) => Some(left.cmp(right)),
        _ => None,
    }
}

/// Tests `value & mask` against `expected`; only unsigned values have bits to mask.
pub(super) fn masked(
    value: &field::Value,
    mask: u64,
    operator: CompareOperator,
    expected: u64,
) -> bool {
    match value {
        field::Value::Unsigned(value) => matches(
            &field::Value::Unsigned(value & mask),
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

fn haystack_bytes(value: &field::Value) -> Option<&[u8]> {
    match value {
        field::Value::Bytes(bytes) => Some(bytes.as_ref()),
        field::Value::Text(text) => Some(text.as_bytes()),
        field::Value::Mac(mac) => Some(mac.as_slice()),
        _ => None,
    }
}

pub(super) fn contains(value: &field::Value, needle: &Needle) -> bool {
    if let field::Value::List(values) = value {
        return values.iter().any(|element| contains(element, needle));
    }
    haystack_bytes(value).is_some_and(|haystack| needle.find(haystack))
}

/// Lists match when any element does. Folded searches lower the haystack once, so the cost stays linear.
pub(super) fn text_match(value: &field::Value, needle: &Needle, mode: TextMode) -> bool {
    if let field::Value::List(values) = value {
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
