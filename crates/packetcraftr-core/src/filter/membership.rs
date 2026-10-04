// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `in { .. }` sets, indexed so a large set costs lookups rather than a scan.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::comparison;
use super::lexer::CompareOperator;
use super::literal::Literal;
use crate::field::FieldValue;

/// Members of a set. An exact literal is indexed under every value kind that
/// [`comparison::matches`] lets equal it; prefixes and ranges, and every
/// member of a small set, are tested in order.
#[derive(Clone, Debug, Default)]
pub(super) struct MemberSet {
    index: Option<Box<Index>>,
    scanned: Vec<Literal>,
}

#[derive(Clone, Debug, Default)]
struct Index {
    bools: [bool; 2],
    unsigned: HashSet<u64>,
    signed: HashSet<i64>,
    text: HashSet<String>,
    /// Bytes, text, and MAC literals, which a bytes value equals byte for byte.
    bytes: HashSet<Vec<u8>>,
    /// MAC literals and six-byte bytes literals, which a MAC value equals.
    macs: HashSet<[u8; 6]>,
    ipv4: HashSet<Ipv4Addr>,
    ipv6: HashSet<Ipv6Addr>,
}

impl MemberSet {
    /// Below this size a scan costs no more than hashing.
    const INDEXED_MINIMUM: usize = 8;

    pub(super) fn new(members: Vec<Literal>) -> Self {
        if members.len() < Self::INDEXED_MINIMUM {
            return Self {
                index: None,
                scanned: members,
            };
        }
        let mut set = Index::default();
        let mut scanned = Vec::new();
        for member in members {
            match member {
                Literal::Bool(value) => set.bools[usize::from(value)] = true,
                Literal::Unsigned(value) => {
                    set.unsigned.insert(value);
                }
                Literal::Signed(value) => {
                    set.signed.insert(value);
                }
                Literal::Text(value) => {
                    set.bytes.insert(value.as_bytes().to_vec());
                    set.text.insert(value);
                }
                Literal::Bytes(value) => {
                    if let Ok(mac) = <[u8; 6]>::try_from(value.as_ref()) {
                        set.macs.insert(mac);
                    }
                    set.bytes.insert(value.to_vec());
                }
                Literal::Mac(value) => {
                    set.macs.insert(value);
                    set.bytes.insert(value.to_vec());
                }
                Literal::Ipv4(value) => {
                    set.ipv4.insert(value);
                }
                Literal::Ipv6(value) => {
                    set.ipv6.insert(value);
                }
                Literal::Ipv4Net(..) | Literal::Ipv6Net(..) | Literal::Range(_) => {
                    scanned.push(member);
                }
            }
        }
        Self {
            index: Some(Box::new(set)),
            scanned,
        }
    }

    /// Whether `value == member` holds for some member.
    pub(super) fn contains(&self, value: &FieldValue) -> bool {
        if let FieldValue::List(values) = value {
            return values.iter().any(|value| self.contains(value));
        }
        let indexed = self
            .index
            .as_ref()
            .is_some_and(|index| index.contains(value));
        indexed
            || self
                .scanned
                .iter()
                .any(|member| comparison::matches(value, CompareOperator::Equal, member))
    }
}

impl Index {
    fn contains(&self, value: &FieldValue) -> bool {
        match value {
            FieldValue::Bool(value) => {
                self.bools[usize::from(*value)] || self.unsigned.contains(&u64::from(*value))
            }
            FieldValue::Unsigned(value) => {
                self.unsigned.contains(value)
                    || i64::try_from(*value).is_ok_and(|value| self.signed.contains(&value))
            }
            FieldValue::Signed(value) => {
                self.signed.contains(value)
                    || u64::try_from(*value).is_ok_and(|value| self.unsigned.contains(&value))
            }
            FieldValue::Text(value) => self.text.contains(value),
            FieldValue::Bytes(value) => {
                self.bytes.contains(value.as_ref())
                    || matches!(value.as_ref(), [only] if self.unsigned.contains(&u64::from(*only)))
            }
            FieldValue::Mac(value) => self.macs.contains(value),
            FieldValue::Ipv4(value) => self.ipv4.contains(value),
            FieldValue::Ipv6(value) => self.ipv6.contains(value),
            FieldValue::List(_) | FieldValue::Object(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::filter::literal::Range;

    fn literals() -> Vec<Literal> {
        vec![
            Literal::Bool(true),
            Literal::Unsigned(0),
            Literal::Unsigned(7),
            Literal::Unsigned(u64::MAX),
            Literal::Signed(-3),
            Literal::Signed(9),
            Literal::Text("ab".to_owned()),
            Literal::Bytes(Bytes::from_static(b"cd")),
            Literal::Bytes(Bytes::from_static(&[1, 2, 3, 4, 5, 6])),
            Literal::Mac([0xa, 0xb, 0xc, 0xd, 0xe, 0xf]),
            Literal::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            Literal::Ipv6(Ipv6Addr::LOCALHOST),
            Literal::Ipv4Net(Ipv4Addr::new(198, 51, 100, 0), 24),
            Literal::Ipv6Net("2001:db8::".parse().unwrap(), 32),
            Literal::Range(Range::Unsigned(100, 200)),
            Literal::Range(Range::Ipv4(
                Ipv4Addr::new(203, 0, 113, 10),
                Ipv4Addr::new(203, 0, 113, 20),
            )),
        ]
    }

    fn values() -> Vec<FieldValue> {
        let scalars = vec![
            FieldValue::Bool(true),
            FieldValue::Bool(false),
            FieldValue::Unsigned(0),
            FieldValue::Unsigned(1),
            FieldValue::Unsigned(9),
            FieldValue::Unsigned(150),
            FieldValue::Unsigned(u64::MAX),
            FieldValue::Signed(-3),
            FieldValue::Signed(7),
            FieldValue::Signed(150),
            FieldValue::Signed(-1),
            FieldValue::Text("ab".to_owned()),
            FieldValue::Text("cd".to_owned()),
            FieldValue::Bytes(Bytes::from_static(b"ab")),
            FieldValue::Bytes(Bytes::from_static(b"cd")),
            FieldValue::Bytes(Bytes::from_static(&[7])),
            FieldValue::Bytes(Bytes::from_static(&[0xa, 0xb, 0xc, 0xd, 0xe, 0xf])),
            FieldValue::Mac([1, 2, 3, 4, 5, 6]),
            FieldValue::Mac([0xa, 0xb, 0xc, 0xd, 0xe, 0xf]),
            FieldValue::Mac([0; 6]),
            FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            FieldValue::Ipv4(Ipv4Addr::new(198, 51, 100, 7)),
            FieldValue::Ipv4(Ipv4Addr::new(203, 0, 113, 15)),
            FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 2)),
            FieldValue::Ipv6(Ipv6Addr::LOCALHOST),
            FieldValue::Ipv6("2001:db8::5".parse().unwrap()),
            FieldValue::Ipv6(Ipv6Addr::UNSPECIFIED),
            FieldValue::Object(Default::default()),
        ];
        let mut values = scalars.clone();
        values.push(FieldValue::List(Vec::new()));
        values.push(FieldValue::List(vec![
            FieldValue::Unsigned(1),
            FieldValue::Ipv4(Ipv4Addr::new(203, 0, 113, 15)),
        ]));
        values.extend(
            scalars
                .into_iter()
                .map(|value| FieldValue::List(vec![value])),
        );
        values
    }

    #[test]
    fn indexed_sets_agree_with_scanning_every_member() {
        let all = literals();
        // Every prefix and suffix of the member list, so each kind is indexed
        // alone and alongside the others.
        let subsets = (0..=all.len())
            .map(|end| all[..end].to_vec())
            .chain((0..all.len()).map(|start| all[start..].to_vec()));
        for members in subsets {
            let set = MemberSet::new(members.clone());
            for value in values() {
                let scanned = members
                    .iter()
                    .any(|member| comparison::matches(&value, CompareOperator::Equal, member));
                assert_eq!(set.contains(&value), scanned, "{value:?} in {members:?}");
            }
        }
    }
}
