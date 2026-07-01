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

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn operation_failed_uses_standard_context_format() {
        assert_eq!(
            operation_failed("open socket", "permission denied"),
            "open socket failed: permission denied"
        );
    }

    #[test]
    fn filesystem_error_displays_path_and_preserves_source() {
        let err = UtilError::Filesystem {
            path: "/tmp/missing".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        };

        assert_eq!(err.to_string(), "filesystem error for '/tmp/missing'");
        assert_eq!(err.source().unwrap().to_string(), "missing");
    }

    #[test]
    fn parse_file_error_displays_format_and_path() {
        let err = UtilError::ParseFile {
            path: "rules.yml".to_string(),
            format: "YAML".to_string(),
            source: Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad")),
        };

        assert_eq!(err.to_string(), "failed to parse YAML from 'rules.yml'");
        assert_eq!(err.source().unwrap().to_string(), "bad");
    }
}
