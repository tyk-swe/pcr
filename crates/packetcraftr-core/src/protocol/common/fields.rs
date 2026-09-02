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

use crate::protocol::BuiltinProtocol;

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
    name: &'static str,
    field: &'static str,
    value: &WireValue<u8>,
    expectation: ValueExpectation<u8>,
    mode: crate::codec::Mode,
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
    name: &'static str,
    field: &'static str,
    value: &WireValue<u16>,
    expectation: ValueExpectation<u16>,
    mode: crate::codec::Mode,
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
    name: &'static str,
    field: &'static str,
    value: &WireValue<T>,
    expectation: ValueExpectation<T>,
    mode: crate::codec::Mode,
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
            if mode == crate::codec::Mode::Strict {
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
    name: &'static str,
    field: &'static str,
    actual: T,
    expectation: ValueExpectation<T>,
    mode: crate::codec::Mode,
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
    if mode == crate::codec::Mode::Strict {
        return Err(invalid(name, message));
    }
    diagnostics
        .push(Diagnostic::warning("build.inconsistent_dependent_field", message).at_field(field));
    Ok(())
}

/// The discriminator this parent must (or should) carry for the child it
/// actually holds.
///
/// An explicit `value` that already selects this child is honoured as-is:
/// several protocols are registered under more than one discriminator —
/// MPLS's two EtherTypes, PPPoE's two stages, ERSPAN's two GRE protocol
/// types — and only one of them is the reverse binding's winner.
pub(crate) fn expected_discriminator<T>(
    parent: &str,
    context: &LayerEncodeContext<'_>,
    fallback: T,
    value: &WireValue<T>,
) -> ValueExpectation<T>
where
    T: Copy + TryFrom<u64> + Into<u64>,
{
    let Some(child) = context.child else {
        return ValueExpectation::Suggested(fallback);
    };
    let child_is_raw = BuiltinProtocol::of(child) == Some(BuiltinProtocol::Raw);
    if let WireValue::Exact(exact) = value
        && !child_is_raw
        && context
            .registry
            .child_for(parent, Discriminator((*exact).into()))
            .is_some_and(|selected| selected.as_str() == binding_protocol(child))
    {
        return ValueExpectation::Required(*exact);
    }
    if child_is_raw {
        let expected = context
            .registry
            .discriminator_for(parent, child.protocol_id().as_str())
            .and_then(|value| T::try_from(value.0).ok())
            .unwrap_or(fallback);
        return ValueExpectation::Suggested(expected);
    }
    context
        .registry
        .discriminator_for(parent, binding_protocol(child))
        .and_then(|value| T::try_from(value.0).ok())
        .map_or(
            ValueExpectation::Suggested(fallback),
            ValueExpectation::Required,
        )
}

/// A `List` field value over decoded text, for decode-only layers whose
/// repeated fields are strings.
pub(crate) fn text_list(values: &[String]) -> FieldValue {
    FieldValue::List(values.iter().cloned().map(FieldValue::Text).collect())
}

/// A `List` field value over decoded 16-bit code points.
pub(crate) fn unsigned_list(values: &[u16]) -> FieldValue {
    FieldValue::List(values.iter().copied().map(FieldValue::from).collect())
}

pub(crate) fn make_layer<L>(
    mut layer: L,
    fields: &BTreeMap<String, FieldValue>,
) -> Result<Box<dyn Layer>, crate::codec::Error>
where
    L: Layer + 'static,
{
    reject_aliased_duplicates(layer.schema(), fields)?;
    for (name, value) in fields {
        layer.set_field(name, value.clone())?;
    }
    Ok(Box::new(layer))
}

/// Rejects a field supplied under two spellings at once.
///
/// Both spellings write the same member, so accepting them would silently
/// drop one of the caller's values. The alias table comes from the schema, so
/// every layer is covered without a per-codec list.
fn reject_aliased_duplicates(
    schema: &'static crate::layer::Schema,
    fields: &BTreeMap<String, FieldValue>,
) -> Result<(), crate::codec::Error> {
    for declared in schema.fields {
        let mut supplied = std::iter::once(declared.name)
            .chain(declared.aliases.iter().copied())
            .filter(|spelling| fields.contains_key(*spelling));
        let (Some(first), Some(second)) = (supplied.next(), supplied.next()) else {
            continue;
        };
        return Err(invalid(
            schema.protocol.as_str(),
            format!("both {second} and {first} were supplied"),
        ));
    }
    Ok(())
}
