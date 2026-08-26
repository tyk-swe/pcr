// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use super::super::layer::FieldError;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("layer index {index} is outside packet length {len}")]
    IndexOutOfBounds { index: usize, len: usize },
    #[error(
        "cannot remove layer {index}: padding coverage ends at that layer and no successor can preserve the boundary"
    )]
    PaddingBoundaryRemoval { index: usize },
    #[error(transparent)]
    Field(#[from] FieldError),
}
