// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Error as AnyhowError;
use thiserror::Error;

/// Result type for engine operations
pub(crate) type EngineResult<T> = std::result::Result<T, EngineError>;

/// Errors that can occur during engine operations
#[derive(Error, Debug)]
pub(crate) enum EngineError {
    #[error("failed to initialize rule engine")]
    RuleEngineInit(#[source] AnyhowError),

    #[error("failed to initialize rule send executor")]
    RuleSendExecutorInit(#[source] AnyhowError),

    #[error("failed to load rules from {path}")]
    RuleLoad {
        path: String,
        #[source]
        source: anyhow::Error,
    },

    #[error("failed to build packet specification")]
    PacketSpecBuild(#[source] AnyhowError),

    #[error("failed to generate preflight summary")]
    PreflightSummary(#[source] AnyhowError),

    #[error("insufficient privileges for raw socket operations")]
    InsufficientPrivileges(#[source] AnyhowError),

    #[error("failed to plan transmission")]
    TransmissionPlan(#[source] AnyhowError),

    #[error("transmission execution failed")]
    TransmissionExecution(#[source] AnyhowError),

    #[error("DNS operation failed")]
    Dns(#[source] AnyhowError),

    #[error("listener operation failed")]
    Listener(#[source] AnyhowError),

    #[cfg(feature = "daemon")]
    #[error("daemon operation failed")]
    Daemon(#[source] AnyhowError),

    #[cfg(feature = "traceroute")]
    #[error("traceroute operation failed")]
    Traceroute(#[source] AnyhowError),

    #[cfg(feature = "scan")]
    #[error("scan operation failed")]
    Scan(#[source] AnyhowError),

    #[cfg(feature = "fuzz")]
    #[error("fuzz operation failed")]
    Fuzz(#[source] AnyhowError),
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

    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::RuleEngineInit(_) => "rule_engine_init",
            Self::RuleSendExecutorInit(_) => "rule_send_executor_init",
            Self::RuleLoad { .. } => "rule_load",
            Self::PacketSpecBuild(_) => "packet_spec_build",
            Self::PreflightSummary(_) => "preflight_summary",
            Self::InsufficientPrivileges(_) => "insufficient_privileges",
            Self::TransmissionPlan(_) => "transmission_plan",
            Self::TransmissionExecution(_) => "transmission_execution",
            Self::Dns(_) => "dns",
            Self::Listener(_) => "listener",
            #[cfg(feature = "daemon")]
            Self::Daemon(_) => "daemon",
            #[cfg(feature = "traceroute")]
            Self::Traceroute(_) => "traceroute",
            #[cfg(feature = "scan")]
            Self::Scan(_) => "scan",
            #[cfg(feature = "fuzz")]
            Self::Fuzz(_) => "fuzz",
        }
    }
}

// Note: Conversion from EngineError to anyhow::Error is provided automatically
// via thiserror's #[error] attribute and anyhow's blanket From implementation
