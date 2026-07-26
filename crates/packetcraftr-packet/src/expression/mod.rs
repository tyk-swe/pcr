// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Compact packet expressions.

mod parser;

pub use parser::{
    DEFAULT_MAX_EXPRESSION_BYTES, ExpressionError as Error, ExpressionOptions as Options,
    MAX_EXPRESSION_NESTING, decode_hex, parse_packet_expression as parse,
};
