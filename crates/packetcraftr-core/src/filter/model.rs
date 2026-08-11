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
/// quietly matching no packets. Evaluation diagnoses unavailable frame facts.
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
    /// Callers can inspect this before evaluation to prepare exactly the TCP
    /// and UDP conversation indexes the filter reads. Timestamp availability
    /// is also checked by [`matches`](Self::matches) for every frame.
    pub fn requirements(&self) -> Requirements {
        self.requirements
    }

    /// Whether one packet satisfies this filter.
    pub fn matches(&self, context: &Context<'_>) -> Result<bool, FilterError> {
        if self.requirements.timestamp && context.decoded.frame.timestamp.is_none() {
            return Err(FilterError::TimestampUnavailable);
        }
        Ok(eval::evaluate(&self.program, context))
    }
}
