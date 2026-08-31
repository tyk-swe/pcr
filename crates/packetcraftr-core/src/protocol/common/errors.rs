// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared codec error and protocol-identifier constructors.

use crate::layer::{FieldError, Layer, Malformed};

pub(crate) fn protocol(name: &str) -> crate::layer::Id {
    crate::layer::Id::new(name)
}

pub(crate) fn binding_protocol(layer: &dyn Layer) -> &crate::layer::Id {
    layer
        .as_any()
        .downcast_ref::<Malformed>()
        .and_then(|layer| layer.intended_protocol.as_ref())
        .unwrap_or_else(|| layer.protocol_id())
}

/// Whether a child layer only preserves opaque bytes, so a parent that would
/// otherwise reject a typed payload accepts it.
pub(crate) fn child_is_opaque(child: &dyn Layer) -> bool {
    crate::protocol::BuiltinProtocol::of(child)
        .is_some_and(crate::protocol::BuiltinProtocol::preserves_opaque_bytes)
}

/// Borrows the concrete layer a codec encodes, or reports the mismatch as
/// [`crate::codec::Error::WrongLayer`].
pub(crate) fn typed_layer<'a, L: Layer + 'static>(
    name: &str,
    layer: &'a dyn Layer,
) -> Result<&'a L, crate::codec::Error> {
    layer
        .as_any()
        .downcast_ref::<L>()
        .ok_or_else(|| wrong_layer(name, layer))
}

fn wrong_layer(expected: &str, actual: &dyn Layer) -> crate::codec::Error {
    crate::codec::Error::WrongLayer {
        expected: protocol(expected),
        actual: actual.protocol_id().clone(),
    }
}

pub(crate) fn truncated(name: &str, needed: usize, available: usize) -> crate::codec::Error {
    crate::codec::Error::Truncated {
        protocol: protocol(name),
        needed,
        available,
    }
}

pub(crate) fn invalid(name: &str, message: impl Into<String>) -> crate::codec::Error {
    crate::codec::Error::Invalid {
        protocol: protocol(name),
        message: message.into(),
    }
}

pub(crate) fn wrong_type(
    schema: &'static crate::layer::Schema,
    field: &str,
    expected: &'static str,
) -> FieldError {
    FieldError::WrongType {
        protocol: schema.protocol.clone(),
        field: field.to_owned(),
        expected,
    }
}

pub(crate) fn out_of_range(schema: &'static crate::layer::Schema, field: &str) -> FieldError {
    FieldError::OutOfRange {
        protocol: schema.protocol.clone(),
        field: field.to_owned(),
    }
}

pub(crate) fn read_only(
    schema: &'static crate::layer::Schema,
    field: &str,
) -> Result<(), FieldError> {
    Err(FieldError::ReadOnly {
        protocol: schema.protocol.clone(),
        field: field.to_owned(),
    })
}
