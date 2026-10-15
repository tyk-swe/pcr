// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `in { .. }` sets, indexed so a large set costs lookups rather than a scan.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::comparison;
use super::lexer::CompareOperator;
use super::literal::Literal;
use crate::field;

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
    pub(super) fn contains(&self, value: &field::Value) -> bool {
        if let field::Value::List(values) = value {
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
    fn contains(&self, value: &field::Value) -> bool {
        match value {
            field::Value::Bool(value) => {
                self.bools[usize::from(*value)] || self.unsigned.contains(&u64::from(*value))
            }
            field::Value::Unsigned(value) => {
                self.unsigned.contains(value)
                    || i64::try_from(*value).is_ok_and(|value| self.signed.contains(&value))
            }
            field::Value::Signed(value) => {
                self.signed.contains(value)
                    || u64::try_from(*value).is_ok_and(|value| self.unsigned.contains(&value))
            }
            field::Value::Text(value) => self.text.contains(value),
            field::Value::Bytes(value) => {
                self.bytes.contains(value.as_ref())
                    || matches!(value.as_ref(), [only] if self.unsigned.contains(&u64::from(*only)))
            }
            field::Value::Mac(value) => self.macs.contains(value),
            field::Value::Ipv4(value) => self.ipv4.contains(value),
            field::Value::Ipv6(value) => self.ipv6.contains(value),
            field::Value::List(_) | field::Value::Object(_) => false,
        }
    }
}
