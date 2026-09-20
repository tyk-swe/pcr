// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::Error;
use super::eval::Context;
use super::parser::{self, Options, Requirements};
use super::plan::Plan;
use crate::registry::Registry;

/// A compiled display filter.
///
/// Compilation resolves every field path against the registry, so a filter
/// that names an unknown protocol or field fails once, up front, instead of
/// quietly matching no packets. Evaluation diagnoses unavailable frame facts.
#[derive(Clone, Debug)]
pub struct Filter {
    plan: Plan,
    requirements: Requirements,
}

impl Filter {
    /// Compiles a display filter against a protocol registry.
    pub fn compile(source: &str, registry: &Registry, options: Options) -> Result<Self, Error> {
        let compiled = parser::compile(source, registry, &options)?;
        Ok(Self {
            plan: Plan::compile(compiled.program),
            requirements: compiled.requirements,
        })
    }

    /// Compiles a single field equality for declarations that accept one literal.
    pub(crate) fn compile_equality(
        field: &str,
        value: &str,
        registry: &Registry,
    ) -> Result<Self, Error> {
        let filter = Self::compile(&format!("{field} == {value}"), registry, Options::default())?;
        let tokens = super::lexer::tokenize(value)?;
        if !matches!(
            tokens.as_slice(),
            [super::lexer::Spanned {
                token: super::lexer::Token::Word(_) | super::lexer::Token::Text(_),
                ..
            }]
        ) {
            return Err(Error::Syntax {
                offset: field.len() + 4,
                message: "expected a single literal".to_owned(),
            });
        }
        Ok(filter)
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
    pub fn matches(&self, context: &Context<'_>) -> Result<bool, Error> {
        if self.requirements.timestamp && context.decoded.frame.timestamp.is_none() {
            return Err(Error::TimestampUnavailable);
        }
        Ok(self.plan.evaluate(context))
    }
}
