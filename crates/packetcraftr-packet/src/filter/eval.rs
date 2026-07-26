// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::cmp::Ordering;

use super::super::Packet;
use super::super::field::FieldValue;
use super::ast::{Node, Operand, Operator};

impl Node {
    /// Evaluates this predicate against a decoded packet.
    ///
    /// A comparison matches when **any** layer of the named protocol satisfies
    /// it. A packet with two TCP layers therefore satisfies `tcp.dport != 443`
    /// whenever either layer has a different port, which is not the same
    /// statement as `!(tcp.dport == 443)`.
    pub(super) fn evaluate(&self, packet: &Packet) -> bool {
        match self {
            Self::Presence { protocol } => {
                packet.iter().any(|layer| layer.protocol_id() == protocol)
            }
            Self::Compare {
                protocol,
                field,
                operator,
                operand,
            } => packet
                .iter()
                .filter(|layer| layer.protocol_id() == protocol)
                .filter_map(|layer| layer.field(field))
                .any(|value| matches_value(&value, *operator, operand)),
            Self::Not(inner) => !inner.evaluate(packet),
            Self::And(left, right) => left.evaluate(packet) && right.evaluate(packet),
            Self::Or(left, right) => left.evaluate(packet) || right.evaluate(packet),
        }
    }
}

fn matches_value(value: &FieldValue, operator: Operator, operand: &Operand) -> bool {
    match (value, operand) {
        (FieldValue::Bool(value), Operand::Bool(operand)) => equality(operator, value == operand),
        (FieldValue::Unsigned(value), Operand::Unsigned(operand)) => {
            ordering(operator, value.cmp(operand))
        }
        (FieldValue::Signed(value), Operand::Signed(operand)) => {
            ordering(operator, value.cmp(operand))
        }
        (FieldValue::Text(value), Operand::Text(operand)) => equality(operator, value == operand),
        (FieldValue::Bytes(value), Operand::Bytes(operand)) => equality(operator, value == operand),
        (FieldValue::Ipv4(value), Operand::Ipv4(operand)) => equality(operator, value == operand),
        (FieldValue::Ipv4(value), Operand::Ipv4Prefix { network, mask }) => {
            equality(operator, u32::from(*value) & mask == *network)
        }
        (FieldValue::Ipv6(value), Operand::Ipv6(operand)) => equality(operator, value == operand),
        (FieldValue::Ipv6(value), Operand::Ipv6Prefix { network, mask }) => {
            equality(operator, u128::from(*value) & mask == *network)
        }
        (FieldValue::Mac(value), Operand::Mac(operand)) => equality(operator, value == operand),
        // The compiler pairs every operand with the field kind the schema
        // declares. A layer that reports a different kind at runtime does not
        // satisfy the comparison.
        _ => false,
    }
}

const fn equality(operator: Operator, equal: bool) -> bool {
    match operator {
        Operator::Equal => equal,
        Operator::NotEqual => !equal,
        // Ordering operators are rejected for these kinds at compile time.
        _ => false,
    }
}

const fn ordering(operator: Operator, ordering: Ordering) -> bool {
    match operator {
        Operator::Equal => ordering.is_eq(),
        Operator::NotEqual => !ordering.is_eq(),
        Operator::Less => ordering.is_lt(),
        Operator::LessOrEqual => ordering.is_le(),
        Operator::Greater => ordering.is_gt(),
        Operator::GreaterOrEqual => ordering.is_ge(),
    }
}
