// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Reflective field schemas and values.

mod value;

pub use super::layer::model::{FieldError as Error, FieldSchema as Schema};
pub use value::{FieldKind as Kind, FieldValue as Value, WireValue as Wire};
#[doc(hidden)]
pub use value::{FieldKind, FieldValue, WireValue};
