// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

impl Error {
    pub(super) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    pub(super) fn field(
        protocol: &crate::layer::Id,
        field: &str,
        reason: impl std::fmt::Display,
    ) -> Self {
        Self::new(format!("field {field} on layer {protocol} {reason}"))
    }
}
