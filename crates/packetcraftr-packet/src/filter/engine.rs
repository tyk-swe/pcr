// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::Packet;
use super::super::registry::ProtocolRegistry;
use super::ast::Node;
use super::error::FilterError;
use super::{lexer, parser};

/// Largest filter source accepted by default.
pub const DEFAULT_MAX_FILTER_BYTES: usize = 64 * 1024;
/// Absolute grouping depth accepted by the filter parser.
pub const MAX_FILTER_NESTING: usize = 64;

/// Resource bounds applied while compiling a display filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterOptions {
    pub max_bytes: usize,
    pub max_nesting: usize,
}

impl Default for FilterOptions {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_FILTER_BYTES,
            max_nesting: MAX_FILTER_NESTING,
        }
    }
}

/// A compiled display filter.
#[derive(Clone, Debug)]
pub struct Filter {
    source: String,
    root: Node,
}

impl Filter {
    /// Compiles `source` against `registry`.
    ///
    /// Every protocol name, field name, operator, and literal is resolved
    /// here, so a filter that compiles cannot fail while frames are streaming.
    pub fn compile(
        source: &str,
        registry: &ProtocolRegistry,
        options: FilterOptions,
    ) -> Result<Self, FilterError> {
        if source.trim().is_empty() {
            return Err(FilterError::Empty);
        }
        if source.len() > options.max_bytes {
            return Err(FilterError::SizeLimit {
                actual: source.len(),
                limit: options.max_bytes,
            });
        }
        if options.max_nesting > MAX_FILTER_NESTING {
            return Err(FilterError::InvalidNestingLimit {
                value: options.max_nesting,
                maximum: MAX_FILTER_NESTING,
            });
        }
        let tokens = lexer::tokenize(source)?;
        let root = parser::Compiler::new(&tokens, registry, options.max_nesting, source.len())
            .compile()?;
        Ok(Self {
            source: source.to_owned(),
            root,
        })
    }

    /// Whether `packet` satisfies this filter.
    ///
    /// A comparison matches when any layer of the named protocol satisfies it,
    /// so `tcp.destination_port == 443` holds for a packet carrying two TCP
    /// layers if either one uses that port. Consequently `tcp.dport != 443`
    /// and `!(tcp.dport == 443)` are different statements about such a packet.
    pub fn matches(&self, packet: &Packet) -> bool {
        self.root.evaluate(packet)
    }

    /// The exact text this filter was compiled from.
    pub fn source(&self) -> &str {
        &self.source
    }
}
