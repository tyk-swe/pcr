// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::layer::ProtocolId;
use super::lexer::CompareOperator;
use super::literal::Literal;
use super::path::FieldRef;

/// One test against a single packet.
#[derive(Clone, Debug)]
pub(super) enum Predicate {
    /// A bare protocol name: does the packet carry such a layer at all?
    LayerPresent {
        protocol: ProtocolId,
        occurrence: Option<usize>,
    },
    /// A bare field path. For a flag this reads the flag's value; for every
    /// other field it asks whether the packet exposes a value at all.
    Bare {
        field: FieldRef,
        flag: bool,
    },
    Compare {
        field: FieldRef,
        operator: CompareOperator,
        value: Literal,
    },
    Membership {
        field: FieldRef,
        values: Vec<Literal>,
    },
    Contains {
        field: FieldRef,
        needle: Literal,
    },
}

/// One instruction of a compiled filter.
///
/// Filters compile to postfix order rather than a tree. Evaluation is then a
/// flat pass over a vector with a small boolean stack, which keeps it
/// non-recursive by construction — the same property the dissector relies on
/// so that untrusted input cannot drive stack depth.
#[derive(Clone, Debug)]
pub(super) enum Op {
    Leaf(Predicate),
    Not,
    And,
    Or,
}
