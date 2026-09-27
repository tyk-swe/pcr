// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use super::{Classification, Classified, Coordinate, Kind};

/// Boxed classification: this rides in every workflow error, whose `Err` size clippy bounds.
#[derive(Debug)]
pub struct BoundaryError {
    message: String,
    classification: Box<Classification>,
    context: Option<Coordinate>,
    causes: Vec<String>,
    source: Option<super::Source>,
}

impl BoundaryError {
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
            source: Some(super::Source::new(error)),
        }
    }

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
            source: Some(super::Source::new(source)),
        }
    }

    #[must_use]
    pub fn as_causes(&self) -> Vec<String> {
        std::iter::once(self.message.clone())
            .chain(self.causes.iter().cloned())
            .collect()
    }

    #[must_use]
    pub fn with_context(mut self, context: Option<Coordinate>) -> Self {
        self.context = context;
        self
    }

    #[must_use]
    pub fn internal_execution(
        message: impl Into<String>,
        code: &'static str,
        remediation: &'static str,
    ) -> Self {
        Self::execution_error(message, code, Kind::Internal, remediation)
    }

    #[must_use]
    pub fn execution_validation(
        message: impl Into<String>,
        code: &'static str,
        remediation: &'static str,
    ) -> Self {
        Self::execution_error(message, code, Kind::Usage, remediation)
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
