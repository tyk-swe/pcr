// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Error as AnyhowError;
use thiserror::Error;

/// Result type for engine operations
pub type EngineResult<T> = std::result::Result<T, EngineError>;

/// Errors that can occur during engine operations
#[derive(Error, Debug)]
pub enum EngineError {
    #[error("failed to initialize rule engine: {0}")]
    RuleEngineInit(#[source] AnyhowError),

    #[error("failed to initialize rule send executor: {0}")]
    RuleSendExecutorInit(#[source] AnyhowError),

    #[error("failed to load rules from {path}: {source}")]
    RuleLoad {
        path: String,
        #[source]
        source: anyhow::Error,
    },

    #[error("failed to build packet specification: {0}")]
    PacketSpecBuild(#[source] AnyhowError),

    #[error("failed to generate preflight summary: {0}")]
    PreflightSummary(#[source] AnyhowError),

    #[error("insufficient privileges for raw socket operations: {0}")]
    InsufficientPrivileges(#[source] AnyhowError),

    #[error("failed to plan transmission: {0}")]
    TransmissionPlan(#[source] AnyhowError),

    #[error("transmission execution failed: {0}")]
    TransmissionExecution(#[source] AnyhowError),

    #[error("listener operation failed: {0}")]
    Listener(#[source] AnyhowError),

    #[error("daemon operation failed: {0}")]
    Daemon(#[source] AnyhowError),

    #[error("interactive shell failed: {0}")]
    Interactive(#[source] AnyhowError),

    #[error("traceroute operation failed: {0}")]
    Traceroute(#[source] AnyhowError),

    #[error("scan operation failed: {0}")]
    Scan(#[source] AnyhowError),

    #[error("tokio runtime construction failed: {0}")]
    RuntimeConstruction(#[source] AnyhowError),
}

impl EngineError {
    pub fn rule_engine_init<S: Into<String>>(msg: S) -> Self {
        Self::RuleEngineInit(AnyhowError::msg(msg.into()))
    }

    pub fn rule_send_executor_init<S: Into<String>>(msg: S) -> Self {
        Self::RuleSendExecutorInit(AnyhowError::msg(msg.into()))
    }

    pub fn rule_load<S: Into<String>>(path: S, source: anyhow::Error) -> Self {
        Self::RuleLoad {
            path: path.into(),
            source,
        }
    }

    pub fn preflight_summary<S: Into<String>>(msg: S) -> Self {
        Self::PreflightSummary(AnyhowError::msg(msg.into()))
    }

    pub fn insufficient_privileges<S: Into<String>>(msg: S) -> Self {
        Self::InsufficientPrivileges(AnyhowError::msg(msg.into()))
    }

    pub fn transmission_plan<S: Into<String>>(msg: S) -> Self {
        Self::TransmissionPlan(AnyhowError::msg(msg.into()))
    }

    pub fn transmission_execution<S: Into<String>>(msg: S) -> Self {
        Self::TransmissionExecution(AnyhowError::msg(msg.into()))
    }

    pub fn daemon<S: Into<String>>(msg: S) -> Self {
        Self::Daemon(AnyhowError::msg(msg.into()))
    }

    pub fn interactive<S: Into<String>>(msg: S) -> Self {
        Self::Interactive(AnyhowError::msg(msg.into()))
    }

    pub fn traceroute<S: Into<String>>(msg: S) -> Self {
        Self::Traceroute(AnyhowError::msg(msg.into()))
    }

    pub fn scan<S: Into<String>>(msg: S) -> Self {
        Self::Scan(AnyhowError::msg(msg.into()))
    }

    pub fn runtime_construction<S: Into<String>>(msg: S) -> Self {
        Self::RuntimeConstruction(AnyhowError::msg(msg.into()))
    }
}

// Note: Conversion from EngineError to anyhow::Error is provided automatically
// via thiserror's #[error] attribute and anyhow's blanket From implementation
