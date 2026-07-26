// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Reflective field schemas and values.

mod value;

pub use super::layer::{FieldError as Error, FieldSchema as Schema};
pub use value::{FieldKind as Kind, FieldValue as Value, WireValue as Wire};
pub use value::{FieldKind, FieldValue, WireValue};
