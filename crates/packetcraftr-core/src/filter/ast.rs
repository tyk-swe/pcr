// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::comparison::{Needle, TextMode};
use super::lexer::CompareOperator;
use super::literal::Literal;
use super::membership::MemberSet;
use super::path::{FieldRef, Occurrence};

/// What `len(..)` and `count(..)` measure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Measure {
    /// The byte length of a bytes, text, MAC, or address value; a list reads per element.
    Len,
    /// The number of elements in a list.
    Count,
}

#[derive(Clone, Debug)]
pub(super) enum Predicate {
    LayerPresent {
        protocol: crate::layer::Id,
        occurrence: Option<Occurrence>,
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
        values: MemberSet,
    },
    Contains {
        field: FieldRef,
        needle: Needle,
    },
    /// `startswith`, `endswith`, `icontains`, and `iequals`, which share `Contains`'s shape.
    TextMatch {
        field: FieldRef,
        needle: Needle,
        mode: TextMode,
    },
    /// `len(field)` or `count(field)` compared to an unsigned `value`.
    Measure {
        field: FieldRef,
        measure: Measure,
        operator: CompareOperator,
        value: u64,
    },
    /// `field & mask` compared to `value`; the bare form tests `!= 0`.
    Masked {
        field: FieldRef,
        mask: u64,
        operator: CompareOperator,
        value: u64,
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
