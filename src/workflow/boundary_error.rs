// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use crate::error::{Classification, Classified};

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
