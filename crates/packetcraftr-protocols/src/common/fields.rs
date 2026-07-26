// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Field resolution, layer construction, and declared-value expectations.

use std::fmt;

use packetcraftr_packet::{
    build::BuildMode,
    codec::{CodecError, NativeLayerEncodeContext},
    diagnostic::Diagnostic,
    field::WireValue,
    layer::Layer,
};

use super::errors::invalid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValueExpectation<T> {
    Required(T),
    Suggested(T),
}

impl<T: Copy> ValueExpectation<T> {
    fn value(self) -> T {
        match self {
            Self::Required(value) | Self::Suggested(value) => value,
        }
    }
}

pub(crate) fn resolve_u8(
    name: &str,
    field: &str,
    value: &WireValue<u8>,
    expectation: ValueExpectation<u8>,
    mode: BuildMode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(u8, WireValue<u8>), CodecError> {
    let expected = expectation.value();
    match value {
        WireValue::Auto => Ok((expected, WireValue::Exact(expected))),
        WireValue::Exact(actual) => {
            validate_dependent(name, field, *actual, expectation, mode, diagnostics)?;
            Ok((*actual, value.clone()))
        }
        WireValue::Raw(bytes) => {
            if mode == BuildMode::Strict {
                return Err(invalid(
                    name,
                    format!("raw {field} requires permissive build mode"),
                ));
            }
            if bytes.len() != 1 {
                return Err(invalid(
                    name,
                    format!("raw {field} must contain exactly one byte"),
                ));
            }
            diagnostics.push(
                Diagnostic::warning(
                    "build.raw_dependent_field",
                    format!("emitting raw {field} value"),
                )
                .at_field(field),
            );
            Ok((bytes[0], value.clone()))
        }
    }
}

pub(crate) fn resolve_u16(
    name: &str,
    field: &str,
    value: &WireValue<u16>,
    expectation: ValueExpectation<u16>,
    mode: BuildMode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(u16, WireValue<u16>), CodecError> {
    let expected = expectation.value();
    match value {
        WireValue::Auto => Ok((expected, WireValue::Exact(expected))),
        WireValue::Exact(actual) => {
            validate_dependent(name, field, *actual, expectation, mode, diagnostics)?;
            Ok((*actual, value.clone()))
        }
        WireValue::Raw(bytes) => {
            if mode == BuildMode::Strict {
                return Err(invalid(
                    name,
                    format!("raw {field} requires permissive build mode"),
                ));
            }
            if bytes.len() != 2 {
                return Err(invalid(
                    name,
                    format!("raw {field} must contain exactly two bytes"),
                ));
            }
            diagnostics.push(
                Diagnostic::warning(
                    "build.raw_dependent_field",
                    format!("emitting raw {field} value"),
                )
                .at_field(field),
            );
            Ok((u16::from_be_bytes([bytes[0], bytes[1]]), value.clone()))
        }
    }
}

pub(crate) fn validate_dependent<T>(
    name: &str,
    field: &str,
    actual: T,
    expectation: ValueExpectation<T>,
    mode: BuildMode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), CodecError>
where
    T: Copy + fmt::Display + PartialEq,
{
    let ValueExpectation::Required(expected) = expectation else {
        return Ok(());
    };
    if actual == expected {
        return Ok(());
    }
    let message = format!("{field} is {actual}, expected {expected}");
    if mode == BuildMode::Strict {
        return Err(invalid(name, message));
    }
    diagnostics
        .push(Diagnostic::warning("build.inconsistent_dependent_field", message).at_field(field));
    Ok(())
}

pub(crate) fn expected_discriminator<T>(
    _parent: &str,
    context: &NativeLayerEncodeContext<'_>,
    fallback: T,
) -> ValueExpectation<T>
where
    T: Copy + TryFrom<u64>,
{
    let Some(child) = context.child_protocol else {
        return ValueExpectation::Suggested(fallback);
    };
    if child.as_str() == "raw" {
        let expected = context
            .canonical_child_discriminator
            .and_then(|value| T::try_from(value.0).ok())
            .unwrap_or(fallback);
        return ValueExpectation::Suggested(expected);
    }
    context
        .canonical_child_discriminator
        .and_then(|value| T::try_from(value.0).ok())
        .map_or(
            ValueExpectation::Suggested(fallback),
            ValueExpectation::Required,
        )
}

pub(crate) fn make_layer<L>(
    mut layer: L,
    fields: &packetcraftr_packet::layer::ValidatedFieldSet,
) -> Result<Box<dyn Layer>, CodecError>
where
    L: Layer + 'static,
{
    for (field, value) in fields.iter() {
        layer.set_field_by_id(&field.id, value.clone())?;
    }
    Ok(Box::new(layer))
}
