// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared codec error and protocol-identifier constructors.

use packetcraftr_packet::{
    codec::CodecError,
    layer::{FieldError, Layer, LayerSchema, ProtocolId},
};

pub(crate) fn protocol(name: &str) -> ProtocolId {
    ProtocolId::new(name).expect("trusted native protocol identity must be valid")
}

pub(crate) fn wrong_layer(expected: &str, actual: &dyn Layer) -> CodecError {
    CodecError::WrongLayer {
        expected: protocol(expected),
        actual: actual.protocol_id().clone(),
    }
}

pub(crate) fn truncated(name: &str, needed: usize, available: usize) -> CodecError {
    CodecError::Truncated {
        protocol: protocol(name),
        needed,
        available,
    }
}

pub(crate) fn invalid(name: &str, message: impl Into<String>) -> CodecError {
    CodecError::Invalid {
        protocol: protocol(name),
        message: message.into(),
    }
}

pub(crate) fn wrong_type(schema: &LayerSchema, field: &str, expected: &'static str) -> FieldError {
    FieldError::WrongType {
        protocol: schema.protocol.clone(),
        field: field.to_owned(),
        expected,
    }
}

pub(crate) fn out_of_range(schema: &LayerSchema, field: &str) -> FieldError {
    FieldError::OutOfRange {
        protocol: schema.protocol.clone(),
        field: field.to_owned(),
    }
}
