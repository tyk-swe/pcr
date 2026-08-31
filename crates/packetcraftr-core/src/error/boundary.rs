// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use super::{Classification, Classified, Coordinate, Kind};

/// Classified failure propagated across a workflow authorization or execution seam.
#[derive(Debug)]
pub struct BoundaryError {
    message: String,
    classification: Box<Classification>,
    context: Option<Coordinate>,
    causes: Vec<String>,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl BoundaryError {
    /// Builds a boundary error from a message and its classification.
    #[must_use]
    pub fn new(
        message: impl Into<String>,
        classification: Classification,
        causes: Vec<String>,
    ) -> Self {
        Self {
            message: message.into(),
            classification: Box::new(classification),
            context: None,
            causes,
            source: None,
        }
    }

    /// Erases an owned classified error, retaining it in the source chain.
    pub fn from_error<E>(error: E) -> Self
    where
        E: Classified + Error + Send + Sync + 'static,
    {
        let message = error.to_string();
        let classification = error.classification();
        let context = error.context();
        let causes = error.causes();
        Self {
            message,
            classification: Box::new(classification),
            context,
            causes,
            source: Some(Box::new(error)),
        }
    }

    /// Builds a boundary error that reports its own message while retaining
    /// an unrelated source error.
    pub fn with_source<E>(
        message: impl Into<String>,
        classification: Classification,
        causes: Vec<String>,
        source: E,
    ) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            message: message.into(),
            classification: Box::new(classification),
            context: None,
            causes,
            source: Some(Box::new(source)),
        }
    }

    /// Attaches the stable domain coordinate of a boundary failure.
    #[must_use]
    pub fn with_context(mut self, context: Option<Coordinate>) -> Self {
        self.context = context;
        self
    }

    /// Reports a broken executor contract as an internal invariant failure.
    #[must_use]
    pub fn internal_execution(
        message: impl Into<String>,
        code: &'static str,
        remediation: &'static str,
    ) -> Self {
        Self::execution_error(message, code, Kind::Internal, remediation)
    }

    /// Reports invalid executor input as a caller validation failure.
    #[must_use]
    pub fn execution_validation(
        message: impl Into<String>,
        code: &'static str,
        remediation: &'static str,
    ) -> Self {
        Self::execution_error(message, code, Kind::Cli, remediation)
    }

    fn execution_error(
        message: impl Into<String>,
        code: &'static str,
        kind: Kind,
        remediation: &'static str,
    ) -> Self {
        Self::new(
            message,
            Classification::new(code, kind, Some(remediation)),
            Vec::new(),
        )
    }
}

impl fmt::Display for BoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for BoundaryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

impl Classified for BoundaryError {
    fn classification(&self) -> Classification {
        *self.classification
    }

    fn context(&self) -> Option<Coordinate> {
        self.context
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}
