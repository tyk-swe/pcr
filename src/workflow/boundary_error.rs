// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use crate::error::{Classification, Classified, Kind};

/// Classified failure propagated across a workflow authorization or execution seam.
#[derive(Clone)]
pub struct BoundaryError {
    message: String,
    classification: Classification,
    causes: Vec<String>,
    source: Option<Arc<dyn Error + Send + Sync>>,
}

impl BoundaryError {
    pub fn new(
        message: impl Into<String>,
        classification: Classification,
        causes: Vec<String>,
    ) -> Self {
        Self {
            message: message.into(),
            classification,
            causes,
            source: None,
        }
    }

    pub fn classified(error: &(impl Classified + fmt::Display)) -> Self {
        Self::new(error.to_string(), error.classification(), error.causes())
    }

    pub(crate) fn from_error<E>(error: E) -> Self
    where
        E: Classified + Error + Send + Sync + 'static,
    {
        let message = error.to_string();
        let classification = error.classification();
        let causes = error.causes();
        Self::with_source(message, classification, causes, error)
    }

    pub(crate) fn with_source<E>(
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
            classification,
            causes,
            source: Some(Arc::new(source)),
        }
    }

    pub(super) fn internal_execution(
        message: impl Into<String>,
        code: &'static str,
        remediation: &'static str,
    ) -> Self {
        Self::execution_error(message, code, Kind::Internal, remediation)
    }

    pub(super) fn execution_validation(
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

impl fmt::Debug for BoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundaryError")
            .field("message", &self.message)
            .field("classification", &self.classification)
            .field("causes", &self.causes)
            .finish()
    }
}

impl PartialEq for BoundaryError {
    fn eq(&self, other: &Self) -> bool {
        self.message == other.message
            && self.classification == other.classification
            && self.causes == other.causes
    }
}

impl Eq for BoundaryError {}

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
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Category;

    #[derive(Debug)]
    struct TestError;

    impl fmt::Display for TestError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("boundary failed")
        }
    }

    impl Error for TestError {}

    impl Classified for TestError {
        fn classification(&self) -> Classification {
            Classification::new("test.boundary", Kind::Io, None)
        }

        fn causes(&self) -> Vec<String> {
            vec!["underlying failure".to_owned()]
        }
    }

    #[test]
    fn owned_classified_error_is_retained_as_source() {
        let boundary = BoundaryError::from_error(TestError);

        assert!(
            boundary
                .source()
                .unwrap()
                .downcast_ref::<TestError>()
                .is_some()
        );
    }

    #[test]
    fn source_does_not_affect_equality_or_debug_contract() {
        let sourced = BoundaryError::from_error(TestError);
        let source_free = BoundaryError::new(
            "boundary failed",
            Classification::new("test.boundary", Kind::Io, None),
            vec!["underlying failure".to_owned()],
        );

        assert_eq!(sourced, source_free);
        assert_eq!(
            format!("{sourced:?}"),
            "BoundaryError { message: \"boundary failed\", classification: Classification { code: \"test.boundary\", kind: Io, category: Io, remediation: None }, causes: [\"underlying failure\"] }"
        );
    }

    #[test]
    fn invalid_executor_contracts_are_internal_invariants() {
        let error = BoundaryError::internal_execution(
            "executor returned inconsistent evidence",
            "internal.test_executor",
            "repair the executor contract",
        );
        let classification = error.classification();

        assert_eq!(classification.code, "internal.test_executor");
        assert_eq!(classification.kind, Kind::Internal);
        assert_eq!(classification.category, Category::Invariant);
        assert_eq!(
            classification.remediation,
            Some("repair the executor contract")
        );
    }

    #[test]
    fn invalid_executor_inputs_remain_validation_errors() {
        let error = BoundaryError::execution_validation(
            "executor received an invalid batch",
            "cli.test_executor",
            "repair the batch",
        );
        let classification = error.classification();

        assert_eq!(classification.code, "cli.test_executor");
        assert_eq!(classification.kind, Kind::Cli);
        assert_eq!(classification.category, Category::Validation);
        assert_eq!(classification.remediation, Some("repair the batch"));
    }
}
