// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime comparison, prefix-membership, and byte-containment semantics.

use std::cmp::Ordering;

use super::super::field::FieldValue;
use super::lexer::CompareOperator;
use super::literal::Literal;

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
    // A list matches when any element does, mirroring how repeated layers and
    // multi-field paths behave elsewhere in the grammar.
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
        u32::MAX << (u32::BITS - u32::from(prefix))
    }
}

fn prefix_mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (u128::BITS - u32::from(prefix))
    }
}

/// Orders a field value against a literal of a comparable type.
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
        // A one-byte field compares against a plain number, so a single byte
        // can be written without an ambiguous bare hex pair.
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

/// Whether a field value contains the literal as a subsequence.
pub(super) fn contains(value: &FieldValue, needle: &Literal) -> bool {
    if let FieldValue::List(values) = value {
        return values.iter().any(|element| contains(element, needle));
    }
    let haystack: &[u8] = match value {
        FieldValue::Bytes(bytes) => bytes.as_ref(),
        FieldValue::Text(text) => text.as_bytes(),
        FieldValue::Mac(mac) => mac.as_slice(),
        _ => return false,
    };
    let needle: &[u8] = match needle {
        Literal::Bytes(bytes) => bytes.as_ref(),
        Literal::Text(text) => text.as_bytes(),
        Literal::Mac(mac) => mac.as_slice(),
        _ => return false,
    };
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::Bytes;

    use super::{contains, matches};
    use crate::field::FieldValue;
    use crate::filter::lexer::CompareOperator;
    use crate::filter::literal::Literal;

    #[test]
    fn comparison_supports_ordering_lists_prefixes_and_incompatible_values() {
        assert!(matches(
            &FieldValue::Unsigned(2),
            CompareOperator::Greater,
            &Literal::Signed(1)
        ));
        assert!(matches(
            &FieldValue::Signed(-1),
            CompareOperator::Less,
            &Literal::Unsigned(0)
        ));
        assert!(matches(
            &FieldValue::Bool(true),
            CompareOperator::Equal,
            &Literal::Unsigned(1)
        ));
        assert!(matches(
            &FieldValue::Ipv4("192.0.2.5".parse().unwrap()),
            CompareOperator::Equal,
            &Literal::Ipv4Net("192.0.2.0".parse().unwrap(), 24)
        ));
        assert!(matches(
            &FieldValue::Ipv6("2001:db8::5".parse().unwrap()),
            CompareOperator::NotEqual,
            &Literal::Ipv6Net("2001:db9::".parse().unwrap(), 32)
        ));
        assert!(!matches(
            &FieldValue::Ipv4(Ipv4Addr::LOCALHOST),
            CompareOperator::Greater,
            &Literal::Ipv4Net(Ipv4Addr::UNSPECIFIED, 0)
        ));
        assert!(matches(
            &FieldValue::List(vec![FieldValue::Unsigned(1), FieldValue::Unsigned(2)]),
            CompareOperator::GreaterOrEqual,
            &Literal::Unsigned(2)
        ));
        assert!(!matches(
            &FieldValue::Text("text".to_owned()),
            CompareOperator::Equal,
            &Literal::Bool(true)
        ));
    }

    #[test]
    fn byte_comparison_covers_bytes_text_mac_and_single_byte_numbers() {
        assert!(matches(
            &FieldValue::Bytes(Bytes::from_static(b"abc")),
            CompareOperator::Equal,
            &Literal::Text("abc".to_owned())
        ));
        assert!(matches(
            &FieldValue::Bytes(Bytes::from_static(&[1])),
            CompareOperator::Equal,
            &Literal::Unsigned(1)
        ));
        assert!(!matches(
            &FieldValue::Bytes(Bytes::from_static(&[1, 2])),
            CompareOperator::Equal,
            &Literal::Unsigned(1)
        ));
        assert!(matches(
            &FieldValue::Mac([0, 1, 2, 3, 4, 5]),
            CompareOperator::Equal,
            &Literal::Bytes(Bytes::from_static(&[0, 1, 2, 3, 4, 5]))
        ));
    }

    #[test]
    fn contains_supports_all_value_kinds_lists_and_empty_needles() {
        assert!(contains(
            &FieldValue::Bytes(Bytes::from_static(b"abcdef")),
            &Literal::Bytes(Bytes::from_static(b"cde"))
        ));
        assert!(contains(
            &FieldValue::Text("abcdef".to_owned()),
            &Literal::Text("".to_owned())
        ));
        assert!(contains(
            &FieldValue::Mac([0, 1, 2, 3, 4, 5]),
            &Literal::Bytes(Bytes::from_static(&[2, 3]))
        ));
        assert!(contains(
            &FieldValue::List(vec![
                FieldValue::Text("first".to_owned()),
                FieldValue::Text("second".to_owned()),
            ]),
            &Literal::Text("cond".to_owned())
        ));
        assert!(!contains(
            &FieldValue::Unsigned(1),
            &Literal::Text("1".to_owned())
        ));
        assert!(!contains(
            &FieldValue::Text("text".to_owned()),
            &Literal::Unsigned(1)
        ));
    }
}
