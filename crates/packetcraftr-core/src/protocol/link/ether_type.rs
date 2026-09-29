// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    codec::LayerEncodeContext, diagnostic::Diagnostic, field::WireValue, registry::Discriminator,
};

use super::llc::{LLC_FRAME_DISCRIMINATOR, MAX_FRAME_LENGTH};
use crate::protocol::BuiltinProtocol;
use crate::protocol::common::{
    ValueExpectation, binds_as, expected_discriminator, invalid, payload_without_padding,
    resolve_u16, strict_or_diagnostic, truncated, validate_auto_raw_discriminator,
    validate_raw_child_discriminator,
};

const LINK_RAW_FALLBACK_DISCRIMINATOR: u16 = MAX_FRAME_LENGTH + 1;

pub(super) fn link_payload_selection(
    name: &'static str,
    ether_type: u16,
    available: usize,
    header_len: usize,
) -> Result<(usize, Vec<Discriminator>), crate::codec::Error> {
    if ether_type >= 0x0600 {
        return Ok((available, vec![Discriminator(u64::from(ether_type))]));
    }
    if ether_type <= MAX_FRAME_LENGTH {
        let length = usize::from(ether_type);
        if length > available {
            return Err(truncated(
                name,
                header_len.saturating_add(length),
                header_len.saturating_add(available),
            ));
        }
        let next = if length == 0 {
            Vec::new()
        } else {
            vec![Discriminator(LLC_FRAME_DISCRIMINATOR)]
        };
        return Ok((length, next));
    }
    Ok((available, vec![Discriminator(u64::from(ether_type))]))
}

pub(super) fn resolve_ether_type(
    name: &'static str,
    value: &WireValue<u16>,
    payload: &[u8],
    context: &LayerEncodeContext<'_>,
) -> Result<(u16, WireValue<u16>, Vec<Diagnostic>), crate::codec::Error> {
    let covered_payload = payload_without_padding(name, payload, context)?;
    let expectation = link_type_expectation(name, context, value, covered_payload.len())?;
    let mut diagnostics = Vec::new();
    validate_auto_raw_discriminator(name, "ether_type", value, context, &mut diagnostics)?;
    let (ether_type, materialized) = resolve_u16(
        name,
        "ether_type",
        value,
        expectation,
        context.mode,
        &mut diagnostics,
    )?;
    validate_link_length_form(
        name,
        ether_type,
        covered_payload.len(),
        context,
        &mut diagnostics,
    )?;
    validate_raw_child_discriminator(name, u64::from(ether_type), context, &mut diagnostics)?;
    Ok((ether_type, materialized, diagnostics))
}

fn link_type_expectation(
    name: &'static str,
    context: &LayerEncodeContext<'_>,
    value: &WireValue<u16>,
    covered_payload_len: usize,
) -> Result<ValueExpectation<u16>, crate::codec::Error> {
    if context
        .child
        .is_some_and(|child| binds_as(child, BuiltinProtocol::Llc))
    {
        let length = u16::try_from(covered_payload_len)
            .ok()
            .filter(|length| *length <= MAX_FRAME_LENGTH)
            .ok_or_else(|| {
                invalid(
                    name,
                    format!("an 802.3 frame length exceeds {MAX_FRAME_LENGTH} bytes"),
                )
            })?;
        return Ok(ValueExpectation::Required(length));
    }
    if matches!(value, WireValue::Auto)
        && context
            .child
            .is_some_and(|child| BuiltinProtocol::Raw.identifies(child))
    {
        return Ok(ValueExpectation::Suggested(LINK_RAW_FALLBACK_DISCRIMINATOR));
    }
    Ok(expected_discriminator(name, context, 0_u16, value))
}

fn validate_link_length_form(
    name: &'static str,
    ether_type: u16,
    covered_payload_len: usize,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), crate::codec::Error> {
    if ether_type > MAX_FRAME_LENGTH
        || (ether_type == 0 && covered_payload_len == 0)
        || context
            .child
            .is_some_and(|child| binds_as(child, BuiltinProtocol::Llc))
    {
        return Ok(());
    }
    strict_or_diagnostic(
        name,
        "build.link_length_form",
        "ether_type",
        format!(
            "ether_type {ether_type} is an 802.3 payload length and dissects as LLC framing; only an llc child can follow it"
        ),
        context,
        diagnostics,
    )
}
