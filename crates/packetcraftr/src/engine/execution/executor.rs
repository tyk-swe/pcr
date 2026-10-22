// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::BoundaryError;

#[derive(Clone, Copy)]
pub(crate) struct ExecutorFault {
    code: &'static str,
    remediation: &'static str,
}

impl ExecutorFault {
    pub(crate) const fn new(code: &'static str, remediation: &'static str) -> Self {
        Self { code, remediation }
    }

    pub(crate) fn invalid(self, message: impl Into<String>) -> BoundaryError {
        BoundaryError::execution_validation(message, self.code, self.remediation)
    }

    pub(crate) fn internal(self, message: impl Into<String>) -> BoundaryError {
        BoundaryError::internal_execution(message, self.code, self.remediation)
    }
}

pub(crate) trait Step {
    type Evidence;
}

pub(crate) trait Executor<S: Step> {
    fn execute(&mut self, step: &S) -> Result<S::Evidence, BoundaryError>;
}
