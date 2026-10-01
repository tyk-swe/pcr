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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_takes_one_literal_of_any_spelling_and_nothing_longer() {
        let registry = crate::protocol::builtin::registry();
        for (field, value) in [
            ("tcp.dstport", "80"),
            ("tcp.dstport", "1..5"),
            ("ip.src", "192.0.2.1..192.0.2.9"),
            ("http.method", "\"GET\""),
            ("raw.bytes", "\"GET\""),
            ("raw.bytes", "b\"\\x16\\x03\""),
        ] {
            Filter::compile_equality(field, value, &registry)
                .unwrap_or_else(|error| panic!("{field}={value} must compile: {error}"));
        }
        for (field, value) in [
            ("raw.bytes", "80 && ip"),
            ("tcp.dstport", "1 & 1"),
            ("tcp.dstport", "1..5 7"),
            ("raw.bytes", "b\"a\" \"b\""),
        ] {
            assert!(
                matches!(
                    Filter::compile_equality(field, value, &registry),
                    Err(Error::Syntax { .. })
                ),
                "{field}={value}"
            );
        }
    }
}
