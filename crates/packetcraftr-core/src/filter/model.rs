// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::Error;
use super::eval::Context;
use super::plan::Plan;
use super::{Limits, Requirements, parser};
use crate::registry::Registry;

#[derive(Clone, Debug)]
pub struct Filter {
    plan: Plan,
    requirements: Requirements,
}

impl Filter {
    pub fn compile(source: &str, registry: &Registry, limits: Limits) -> Result<Self, Error> {
        let compiled = parser::compile(source, registry, &limits)?;
        Ok(Self {
            plan: Plan::compile(compiled.program),
            requirements: compiled.requirements,
        })
    }

    pub(crate) fn compile_equality(
        field: &str,
        value: &str,
        registry: &Registry,
    ) -> Result<Self, Error> {
        let filter = Self::compile(&format!("{field} == {value}"), registry, Limits::default())?;
        let tokens = super::lexer::tokenize(value)?;
        if !matches!(
            tokens.as_slice(),
            [super::lexer::Spanned {
                token: super::lexer::Token::Word(_)
                    | super::lexer::Token::Text(_)
                    | super::lexer::Token::ByteString(_),
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

    pub fn requirements(&self) -> Requirements {
        self.requirements
    }

    pub fn matches(&self, context: &Context<'_>) -> Result<bool, Error> {
        if self.requirements.timestamp && context.decoded.frame.timestamp.is_none() {
            return Err(Error::TimestampUnavailable);
        }
        Ok(self.plan.evaluate(context))
    }
}
