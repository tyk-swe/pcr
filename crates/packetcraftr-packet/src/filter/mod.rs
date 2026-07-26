// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded display filters evaluated against decoded packets.
//!
//! A filter is a field expression over the reflective vocabulary a registry
//! already exposes, so it covers external codecs without changes:
//!
//! ```text
//! ipv4.source == 192.0.2.0/24 && tcp.destination_port == 443
//! dns && !(udp.source_port < 1024)
//! ```
//!
//! Compilation resolves every protocol and field name against the registry and
//! every literal against the field's declared kind, so an unknown name or an
//! impossible comparison is reported before any packet is read. Evaluation
//! cannot fail: a compiled filter either matches a packet or does not.

mod ast;
mod engine;
mod error;
mod eval;
mod lexer;
mod parser;
#[cfg(test)]
mod tests;

pub use ast::Operator;
pub use engine::{DEFAULT_MAX_FILTER_BYTES, Filter, FilterOptions as Options, MAX_FILTER_NESTING};
pub use error::FilterError as Error;

#[doc(hidden)]
pub use engine::FilterOptions;
#[doc(hidden)]
pub use error::FilterError;
