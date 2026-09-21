// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;

use memchr::memmem::Finder;

use super::lexer::CompareOperator;
use super::literal::Literal;
use crate::field::FieldValue;

/// Whether a single field value satisfies `value <operator> literal`.
///
/// Values whose type cannot be compared with the literal simply do not match;
/// the compile-time compatibility check is what reports genuine mistakes.
pub(super) fn matches(value: &FieldValue, operator: CompareOperator, literal: &Literal) -> bool {
    if let Some(contained) = containment(value, literal) {
        // Prefix literals describe a set, so only membership is meaningful.
        return match operator {
            CompareOperator::Equal => contained,
            CompareOperator::NotEqual => !contained,
            _ => false,
        };
    }
    // Lists match when any element matches.
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

/// Tests prefix membership, or reports [`None`] when the literal is not a prefix.
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
        // A one-byte field may compare to a plain number.
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

/// A `contains` needle with its substring searcher already built.
///
/// Compiling the [`Finder`] once, alongside the literal at filter-compile
/// time, makes the per-frame scan a linear-time `memmem` search instead of
/// a naive sliding-window compare per candidate value.
#[derive(Clone, Debug)]
pub(super) struct Needle {
    // The searcher's precomputed table is large, so it lives boxed rather
    // than inflating every `Predicate` variant.
    finder: Box<Finder<'static>>,
}

impl Needle {
    /// Builds the searcher over the literal's bytes, or returns the literal
    /// unchanged when it is not a byte sequence. `check_searchable` rejects
    /// such needles first, so a returned literal stays reportable rather than
    /// silently unreachable.
    pub(super) fn new(literal: Literal) -> Result<Self, Literal> {
        let bytes: &[u8] = match &literal {
            Literal::Bytes(bytes) => bytes.as_ref(),
            Literal::Text(text) => text.as_bytes(),
            Literal::Mac(mac) => mac.as_slice(),
            _ => return Err(literal),
        };
        Ok(Self {
            finder: Box::new(Finder::new(bytes).into_owned()),
        })
    }

    /// Whether `haystack` contains the needle.
    fn find(&self, haystack: &[u8]) -> bool {
        // An empty needle is contained by every haystack.
        self.finder.needle().is_empty() || self.finder.find(haystack).is_some()
    }
}

pub(super) fn contains(value: &FieldValue, needle: &Needle) -> bool {
    if let FieldValue::List(values) = value {
        return values.iter().any(|element| contains(element, needle));
    }
    let haystack: &[u8] = match value {
        FieldValue::Bytes(bytes) => bytes.as_ref(),
        FieldValue::Text(text) => text.as_bytes(),
        FieldValue::Mac(mac) => mac.as_slice(),
        _ => return false,
    };
    needle.find(haystack)
}
