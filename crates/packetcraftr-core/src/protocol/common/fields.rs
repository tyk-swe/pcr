// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use crate::{
    codec::EncodeContext,
    diagnostic::{Diagnostic, Severity},
    field::{self, WireValue},
    registry::Discriminator,
};

use crate::protocol::BuiltinProtocol;

use super::errors::invalid;
use super::validation::{validate_auto_raw_discriminator, validate_raw_child_discriminator};

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

pub(crate) fn resolve_u16_discriminator(
    name: &'static str,
    field: &'static str,
    value: &WireValue<u16>,
    context: &EncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(u16, WireValue<u16>), crate::codec::Error> {
    validate_auto_raw_discriminator(name, field, value, context, diagnostics)?;
    let (resolved, materialized) = resolve_u16(
        name,
        field,
        value,
        expected_discriminator(context, 0_u16, value),
        context.mode,
        diagnostics,
    )?;
    validate_raw_child_discriminator(name, u64::from(resolved), context, diagnostics)?;
    Ok((resolved, materialized))
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
                Diagnostic::new(
                    Severity::Warning,
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
    diagnostics.push(
        Diagnostic::new(
            Severity::Warning,
            "build.inconsistent_dependent_field",
            message,
        )
        .at_field(field),
    );
    Ok(())
}

/// An explicit `value` that already selects this child is honoured as-is:
/// several protocols are registered under more than one discriminator.
pub(crate) fn expected_discriminator<T>(
    context: &EncodeContext<'_>,
    fallback: T,
    value: &WireValue<T>,
) -> ValueExpectation<T>
where
    T: Copy + TryFrom<u64> + Into<u64>,
{
    let Some(child) = context.child else {
        return ValueExpectation::Suggested(fallback);
    };
    let child_is_raw = child.is_builtin(BuiltinProtocol::Raw.id());
    if let WireValue::Exact(exact) = value
        && !child_is_raw
        && context
            .child_for(Discriminator((*exact).into()))
            .is_some_and(|selected| selected.as_str() == child.binding_protocol())
    {
        return ValueExpectation::Required(*exact);
    }
    if child_is_raw {
        let expected = child
            .discriminator
            .and_then(|value| T::try_from(value.0).ok())
            .unwrap_or(fallback);
        return ValueExpectation::Suggested(expected);
    }
    child
        .discriminator
        .and_then(|value| T::try_from(value.0).ok())
        .map_or(
            ValueExpectation::Suggested(fallback),
            ValueExpectation::Required,
        )
}

pub(crate) fn text_list(values: &[String]) -> field::Value {
    field::Value::List(values.iter().cloned().map(field::Value::Text).collect())
}

pub(crate) fn unsigned_list(values: &[u16]) -> field::Value {
    field::Value::List(values.iter().copied().map(field::Value::from).collect())
}
