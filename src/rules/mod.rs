// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(dead_code)]

mod action;
pub(crate) mod condition;
mod config;
mod diagnostic;
mod engine;
mod error;
mod executor;
pub(crate) mod model;
mod rule;
pub(crate) mod send;
pub(crate) mod template;
mod yaml;

pub(crate) use config::RuleExecutorConfig;
#[cfg(feature = "daemon")]
pub(crate) use diagnostic::{RuleLoadOptions, RuleLoadReport};
pub(crate) use engine::RuleEngine;
pub(crate) use error::{RuleActionError, RuleError};

pub(crate) use executor::{validate_rule_send_request, BoundedExecutor, ExecutorError};
pub(crate) use model::PacketContext;
