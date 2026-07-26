// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::super::layer::ProtocolId;

/// A comparison spelled by a display filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Operator {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
}

impl Operator {
    pub(super) const fn is_ordering(self) -> bool {
        matches!(
            self,
            Self::Less | Self::LessOrEqual | Self::Greater | Self::GreaterOrEqual
        )
    }
}

/// A literal resolved against the field kind it will be compared with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Operand {
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Text(String),
    Bytes(Bytes),
    Ipv4(Ipv4Addr),
    /// An IPv4 prefix. Equality against a prefix means containment.
    Ipv4Prefix {
        network: u32,
        mask: u32,
    },
    Ipv6(Ipv6Addr),
    Ipv6Prefix {
        network: u128,
        mask: u128,
    },
    Mac([u8; 6]),
}

/// One compiled predicate.
///
/// Protocol names are resolved to canonical identifiers and field names to
/// `'static` schema names at compile time, so evaluation performs no lookup
/// that can fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Node {
    Presence {
        protocol: ProtocolId,
    },
    Compare {
        protocol: ProtocolId,
        field: &'static str,
        operator: Operator,
        operand: Operand,
    },
    Not(Box<Node>),
    And(Box<Node>, Box<Node>),
    Or(Box<Node>, Box<Node>),
}
