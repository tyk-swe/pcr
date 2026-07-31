// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::registry::ProtocolRegistry;
use super::ast::Op;
use super::error::FilterError;
use super::eval::{self, Context};
use super::parser::{self, FilterOptions, Requirements};

/// A compiled display filter.
///
/// Compilation resolves every field path against the registry, so a filter
/// that names an unknown protocol or field fails once, up front, instead of
/// quietly matching no packets. Evaluation afterwards is infallible.
#[derive(Clone, Debug)]
pub struct Filter {
    program: Vec<Op>,
    requirements: Requirements,
}

impl Filter {
    /// Compiles a display filter against a protocol registry.
    pub fn compile(
        source: &str,
        registry: &ProtocolRegistry,
        options: FilterOptions,
    ) -> Result<Self, FilterError> {
        let compiled = parser::compile(source, registry, &options)?;
        Ok(Self {
            program: compiled.program,
            requirements: compiled.requirements,
        })
    }

    /// What this filter needs from its caller beyond the dissected packet.
    ///
    /// Callers check this before reading any input so a filter that depends on
    /// a conversation index is rejected where none is maintained, rather than
    /// evaluating to false on every packet.
    pub fn requirements(&self) -> Requirements {
        self.requirements
    }

    /// Whether one packet satisfies this filter.
    pub fn matches(&self, context: &Context<'_>) -> bool {
        eval::evaluate(&self.program, context)
    }
}
