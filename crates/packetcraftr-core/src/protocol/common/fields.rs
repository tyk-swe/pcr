// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Field resolution, layer construction, and declared-value expectations.

use std::collections::BTreeMap;
use std::fmt;

use crate::{
    codec::LayerEncodeContext,
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::Layer,
    registry::Discriminator,
};

use super::errors::{binding_protocol, invalid};

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
    mode: crate::build::Mode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(u8, WireValue<u8>), crate::codec::Error> {
    resolve_fixed(
        name,
        field,
        value,
        expectation,
        mode,
        diagnostics,
        |[value]| value,
    )
}

pub(crate) fn resolve_u16(
    name: &str,
    field: &str,
    value: &WireValue<u16>,
    expectation: ValueExpectation<u16>,
    mode: crate::build::Mode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(u16, WireValue<u16>), crate::codec::Error> {
    resolve_fixed(
        name,
        field,
        value,
        expectation,
        mode,
        diagnostics,
        u16::from_be_bytes,
    )
}

pub(crate) fn resolve_fixed<T, const N: usize>(
    name: &str,
    field: &str,
    value: &WireValue<T>,
    expectation: ValueExpectation<T>,
    mode: crate::build::Mode,
    diagnostics: &mut Vec<Diagnostic>,
    decode_raw: impl FnOnce([u8; N]) -> T,
) -> Result<(T, WireValue<T>), crate::codec::Error>
where
    T: Copy + fmt::Display + PartialEq,
{
    let expected = expectation.value();
    match value {
        WireValue::Auto => Ok((expected, WireValue::Exact(expected))),
        WireValue::Exact(actual) => {
            validate_dependent(name, field, *actual, expectation, mode, diagnostics)?;
            Ok((*actual, value.clone()))
        }
        WireValue::Raw(bytes) => {
            if mode == crate::build::Mode::Strict {
                return Err(invalid(
                    name,
                    format!("raw {field} requires permissive build mode"),
                ));
            }
            let raw_size = match N {
                1 => "one byte",
                2 => "two bytes",
                4 => "four bytes",
                _ => "the fixed field width",
            };
            let raw = bytes.as_ref().try_into().map_err(|_| {
                invalid(name, format!("raw {field} must contain exactly {raw_size}"))
            })?;
            diagnostics.push(
                Diagnostic::warning(
                    "build.raw_dependent_field",
                    format!("emitting raw {field} value"),
                )
                .at_field(field),
            );
            Ok((decode_raw(raw), value.clone()))
        }
    }
}

fn validate_dependent<T>(
    name: &str,
    field: &str,
    actual: T,
    expectation: ValueExpectation<T>,
    mode: crate::build::Mode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), crate::codec::Error>
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
    if mode == crate::build::Mode::Strict {
        return Err(invalid(name, message));
    }
    diagnostics
        .push(Diagnostic::warning("build.inconsistent_dependent_field", message).at_field(field));
    Ok(())
}

/// Like [`expected_discriminator`], but honours an exact value that already
/// selects the child on dissection. Some children are registered under more
/// than one discriminator — MPLS under both its unicast and multicast
/// EtherTypes — and any alias that forward-resolves to the same child is
/// consistent, not a mismatch with the reverse lookup's preferred one.
pub(crate) fn expected_discriminator_for_value<T>(
    parent: &str,
    context: &LayerEncodeContext<'_>,
    fallback: T,
    value: &WireValue<T>,
) -> ValueExpectation<T>
where
    T: Copy + TryFrom<u64> + Into<u64>,
{
    if let WireValue::Exact(exact) = value
        && let Some(child) = context.child
        && child.protocol_id().as_str() != "raw"
        && context
            .registry
            .child_for(parent, Discriminator((*exact).into()))
            .is_some_and(|selected| selected == binding_protocol(child))
    {
        return ValueExpectation::Required(*exact);
    }
    expected_discriminator(parent, context, fallback)
}

pub(crate) fn expected_discriminator<T>(
    parent: &str,
    context: &LayerEncodeContext<'_>,
    fallback: T,
) -> ValueExpectation<T>
where
    T: Copy + TryFrom<u64>,
{
    let Some(child) = context.child else {
        return ValueExpectation::Suggested(fallback);
    };
    if child.protocol_id().as_str() == "raw" {
        let expected = context
            .registry
            .discriminator_for(parent, child.protocol_id().as_str())
            .and_then(|value| T::try_from(value.0).ok())
            .unwrap_or(fallback);
        return ValueExpectation::Suggested(expected);
    }
    context
        .registry
        .discriminator_for(parent, binding_protocol(child).as_str())
        .and_then(|value| T::try_from(value.0).ok())
        .map_or(
            ValueExpectation::Suggested(fallback),
            ValueExpectation::Required,
        )
}

pub(crate) fn make_layer<L>(
    mut layer: L,
    fields: &BTreeMap<String, FieldValue>,
) -> Result<Box<dyn Layer>, crate::codec::Error>
where
    L: Layer + 'static,
{
    for (name, value) in fields {
        layer.set_field(name, value.clone())?;
    }
    Ok(Box::new(layer))
}

pub(crate) fn aliased_fields(
    name: &str,
    fields: &BTreeMap<String, FieldValue>,
    aliases: &[(&str, &str)],
) -> Result<BTreeMap<String, FieldValue>, crate::codec::Error> {
    let mut normalized = fields.clone();
    for (alias, canonical) in aliases {
        let Some(value) = normalized.remove(*alias) else {
            continue;
        };
        if normalized.insert((*canonical).to_string(), value).is_some() {
            return Err(invalid(
                name,
                format!("both {alias} and {canonical} were supplied"),
            ));
        }
    }
    Ok(normalized)
}
