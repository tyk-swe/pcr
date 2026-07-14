// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use crate::error::{Classification, Classified, Kind};

/// Classified failure propagated across a workflow authorization or execution seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryError {
    message: String,
    classification: Classification,
    causes: Vec<String>,
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
        }
    }

    pub fn classified(error: &(impl Classified + fmt::Display)) -> Self {
        Self::new(error.to_string(), error.classification(), error.causes())
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

impl fmt::Display for BoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for BoundaryError {}

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
