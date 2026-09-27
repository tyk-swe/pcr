// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::comparison::Needle;
use super::lexer::CompareOperator;
use super::literal::Literal;
use super::path::FieldRef;

#[derive(Clone, Debug)]
pub(super) enum Predicate {
    LayerPresent {
        protocol: crate::layer::Id,
        occurrence: Option<usize>,
    },
    /// A bare field path: a flag reads its value; any other field tests for a value.
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
        needle: Needle,
    },
}

/// Postfix order keeps evaluation non-recursive, so untrusted input cannot drive stack depth.
#[derive(Clone, Debug)]
pub(super) enum Op {
    Leaf(Predicate),
    Not,
    And,
    Or,
}
