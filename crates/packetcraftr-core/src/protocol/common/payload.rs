// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Link-padding-aware payload narrowing.

use crate::{codec::LayerEncodeContext, layer::Padding};

use super::errors::invalid;

pub(crate) fn payload_without_padding<'a>(
    name: &str,
    payload: &'a [u8],
    context: &LayerEncodeContext<'_>,
) -> Result<&'a [u8], crate::codec::Error> {
    let trailing = context
        .packet
        .iter()
        .skip(context.index.saturating_add(1))
        .rev()
        .take_while(|layer| layer.as_any().is::<Padding>())
        .filter(|layer| {
            layer
                .as_any()
                .downcast_ref::<Padding>()
                .is_some_and(|padding| {
                    padding
                        .outside_layer
                        .is_none_or(|outside_layer| context.index >= outside_layer)
                })
        })
        .try_fold(0_usize, |total, layer| {
            let length = layer
                .as_any()
                .downcast_ref::<Padding>()
                .map_or(0, |padding| padding.bytes.len());
            total.checked_add(length)
        })
        .ok_or_else(|| invalid(name, "trailing padding length overflow"))?;
    let covered = payload
        .len()
        .checked_sub(trailing)
        .ok_or_else(|| invalid(name, "trailing padding exceeds encoded payload"))?;
    #[expect(
        clippy::indexing_slicing,
        reason = "covered comes from payload.len().checked_sub, so it is at most payload.len()"
    )]
    let covered_payload = &payload[..covered];
    Ok(covered_payload)
}
