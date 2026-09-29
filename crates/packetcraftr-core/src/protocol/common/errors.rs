// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::field;
use crate::layer::{Layer, Malformed};
use crate::protocol::BuiltinProtocol;

pub(crate) const fn protocol(name: &'static str) -> crate::layer::Id {
    crate::layer::Id::new(name)
}

pub(crate) fn binding_protocol(layer: &dyn Layer) -> &str {
    layer
        .downcast_ref::<Malformed>()
        .and_then(|layer| layer.intended_protocol.as_deref())
        .unwrap_or_else(|| layer.protocol_id().as_str())
}

pub(crate) fn binds_as(layer: &dyn Layer, protocol: BuiltinProtocol) -> bool {
    match layer
        .downcast_ref::<Malformed>()
        .and_then(|layer| layer.intended_protocol.as_deref())
    {
        Some(intended) => BuiltinProtocol::from_name(intended) == Some(protocol),
        None => protocol.identifies(layer),
    }
}

pub(crate) fn child_is_opaque(child: &dyn Layer) -> bool {
    crate::protocol::BuiltinProtocol::of(child)
        .is_some_and(crate::protocol::BuiltinProtocol::preserves_opaque_bytes)
}

pub(crate) fn typed_layer<'a, L: Layer + 'static>(
    name: &'static str,
    layer: &'a dyn Layer,
) -> Result<&'a L, crate::codec::Error> {
    layer
        .downcast_ref::<L>()
        .ok_or_else(|| crate::codec::Error::wrong_layer(protocol(name), layer))
}

pub(crate) fn truncated(
    name: &'static str,
    needed: usize,
    available: usize,
) -> crate::codec::Error {
    crate::codec::Error::Truncated {
        protocol: protocol(name),
        needed,
        available,
    }
}

pub(crate) fn invalid(name: &'static str, message: impl Into<String>) -> crate::codec::Error {
    crate::codec::Error::invalid(protocol(name), message)
}

pub(crate) fn unsupported(name: &'static str, message: impl Into<String>) -> crate::codec::Error {
    crate::codec::Error::unsupported(protocol(name), message)
}

pub(crate) fn rejected(
    name: &'static str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> crate::codec::Error {
    crate::codec::Error::rejected(protocol(name), source)
}

pub(crate) fn wrong_type(
    schema: &'static crate::layer::Schema,
    field: &str,
    expected: &'static str,
) -> field::Error {
    field::Error::WrongType {
        protocol: schema.protocol,
        field: field.to_owned(),
        expected,
    }
}

pub(crate) fn out_of_range(schema: &'static crate::layer::Schema, field: &str) -> field::Error {
    field::Error::OutOfRange {
        protocol: schema.protocol,
        field: field.to_owned(),
    }
}

pub(crate) fn read_only(
    schema: &'static crate::layer::Schema,
    field: &str,
) -> Result<(), field::Error> {
    Err(field::Error::ReadOnly {
        protocol: schema.protocol,
        field: field.to_owned(),
    })
}
