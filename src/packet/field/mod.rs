//! Reflective field schemas and values.

mod value;

pub use super::layer::model::{FieldError as Error, FieldSchema as Schema};
pub use value::{FieldKind as Kind, FieldValue as Value, WireValue as Wire};
pub(crate) use value::{FieldKind, FieldValue, WireValue};
