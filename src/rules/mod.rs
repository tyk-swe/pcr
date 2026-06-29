// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

mod action;
pub mod condition;
mod config;
mod diagnostic;
mod engine;
mod error;
mod executor;
pub mod model;
mod rule;
pub mod send;
pub mod template;
mod yaml;

pub use config::RuleExecutorConfig;
pub use diagnostic::{
    RuleDiagnostic, RuleDiagnosticSeverity, RuleLoadOptions, RuleLoadReport,
    RULE_PARSE_UNKNOWN_FIELD,
};
pub use engine::RuleEngine;
pub use error::{MatcherError, RuleActionError, RuleError};

pub(crate) use executor::{validate_rule_send_request, BoundedExecutor, ExecutorError};
pub use model::PacketContext;
