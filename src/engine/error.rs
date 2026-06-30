// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Error as AnyhowError;
use thiserror::Error;

/// Result type for engine operations
pub(crate) type EngineResult<T> = std::result::Result<T, EngineError>;

/// Errors that can occur during engine operations
#[derive(Error, Debug)]
pub(crate) enum EngineError {
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

    #[cfg(feature = "traceroute")]
    #[error("traceroute operation failed: {0}")]
    Traceroute(#[source] AnyhowError),

    #[cfg(feature = "scan")]
    #[error("scan operation failed: {0}")]
    Scan(#[source] AnyhowError),
}

impl EngineError {
    pub(crate) fn rule_load<S: Into<String>>(path: S, source: anyhow::Error) -> Self {
        Self::RuleLoad {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn transmission_plan<S: Into<String>>(msg: S) -> Self {
        Self::TransmissionPlan(AnyhowError::msg(msg.into()))
    }
}

// Note: Conversion from EngineError to anyhow::Error is provided automatically
// via thiserror's #[error] attribute and anyhow's blanket From implementation
