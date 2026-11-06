// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    codec::EncodeContext, diagnostic::Diagnostic, field::WireValue, registry::Discriminator,
};

use super::llc::{LLC_FRAME_DISCRIMINATOR, MAX_FRAME_LENGTH};
use crate::protocol::BuiltinProtocol;
use crate::protocol::common::{
    ValueExpectation, expected_discriminator, invalid, payload_without_padding, resolve_u16,
    strict_or_diagnostic, truncated, validate_auto_raw_discriminator,
    validate_raw_child_discriminator,
};

const LINK_RAW_FALLBACK_DISCRIMINATOR: u16 = MAX_FRAME_LENGTH + 1;

pub const IPV4: u16 = 0x0800;
pub const ARP: u16 = 0x0806;
pub const VLAN: u16 = 0x8100;
pub const VLAN_8021AD: u16 = 0x88a8;
pub const MPLS_UNICAST: u16 = 0x8847;
pub const MPLS_MULTICAST: u16 = 0x8848;
pub const PPPOE_DISCOVERY_STAGE: u16 = 0x8863;
pub const PPPOE_SESSION_STAGE: u16 = 0x8864;
pub const EAPOL: u16 = 0x888e;
pub const LLDP: u16 = 0x88cc;
pub const SLOW_PROTOCOLS: u16 = 0x8809;
pub const IPV6: u16 = 0x86dd;
pub const TRANSPARENT_ETHERNET_BRIDGING: u16 = 0x6558;
pub const ERSPAN_TYPE_II: u16 = 0x88be;
pub const ERSPAN_TYPE_III: u16 = 0x22eb;

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
    context: &EncodeContext<'_>,
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
    context: &EncodeContext<'_>,
    value: &WireValue<u16>,
    covered_payload_len: usize,
) -> Result<ValueExpectation<u16>, crate::codec::Error> {
    if context
        .child
        .is_some_and(|child| child.binds_as(BuiltinProtocol::Llc.id()))
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
            .is_some_and(|child| child.is_builtin(BuiltinProtocol::Raw.id()))
    {
        return Ok(ValueExpectation::Suggested(LINK_RAW_FALLBACK_DISCRIMINATOR));
    }
    Ok(expected_discriminator(context, 0_u16, value))
}

fn validate_link_length_form(
    name: &'static str,
    ether_type: u16,
    covered_payload_len: usize,
    context: &EncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), crate::codec::Error> {
    if ether_type > MAX_FRAME_LENGTH
        || (ether_type == 0 && covered_payload_len == 0)
        || context
            .child
            .is_some_and(|child| child.binds_as(BuiltinProtocol::Llc.id()))
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
