// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use thiserror::Error;

/// Format a standardized error context message following "operation failed: context".
///
/// Keeping this helper centralises the wording and makes it harder to regress on the
/// agreed format when we add new error contexts across the codebase.
pub(crate) fn operation_failed(operation: &str, details: impl fmt::Display) -> String {
    format!("{operation} failed: {details}")
}

#[derive(Debug, Error)]
pub(crate) enum UtilError {
    #[error("filesystem error for '{path}'")]
    Filesystem {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("failed to parse {format} from '{path}'")]
    ParseFile {
        path: String,
        format: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
    #[error(transparent)]
    Privilege(#[from] crate::util::privileges::PrivilegeError),
    #[cfg(feature = "metrics")]
    #[error(transparent)]
    Telemetry(#[from] crate::util::telemetry::TelemetryError),
    #[error(transparent)]
    Logging(#[from] crate::util::logging::LoggingInitError),
    #[error(transparent)]
    Network(#[from] crate::util::net::ResolveHostnameError),
}
