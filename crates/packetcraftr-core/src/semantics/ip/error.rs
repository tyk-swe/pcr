// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;
use std::fmt;

use super::super::ProtocolId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticError {
    message: String,
}

impl SemanticError {
    pub(super) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub(super) fn field(protocol: &ProtocolId, field: &str, reason: impl fmt::Display) -> Self {
        Self::new(format!("field {field} on layer {protocol} {reason}"))
    }
}

impl fmt::Display for SemanticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for SemanticError {}
