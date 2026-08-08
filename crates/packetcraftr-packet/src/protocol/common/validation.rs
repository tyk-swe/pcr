// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Child-discriminator, strictness, and encode-budget validation.

use crate::{
    build::BuildMode,
    codec::{CodecError, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::WireValue,
    registry::Discriminator,
};

use super::errors::{binding_protocol, invalid, protocol};

pub(crate) fn validate_ipv6_routing_child(
    name: &str,
    next_header: u8,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), CodecError> {
    let raw_routing_header = next_header == 43
        && context
            .child
            .is_some_and(|child| child.protocol_id().as_str() == "raw");
    if !raw_routing_header {
        return Ok(());
    }
    let message = "IPv6 routing headers must use the typed SRH layer; routing type 0 and unsupported generic routing headers are prohibited";
    if context.mode == BuildMode::Strict {
        return Err(CodecError::Unsupported {
            protocol: protocol(name),
            message: message.to_owned(),
        });
    }
    diagnostics.push(
        Diagnostic::warning("build.untyped_ipv6_routing_header", message).at_field("next_header"),
    );
    Ok(())
}

/// Unknown discriminators may preserve opaque Raw bytes. A discriminator that
/// selects a registered typed codec must have that child; it cannot be used to
/// smuggle arbitrary bytes or claim a header that is absent.
pub(crate) fn validate_raw_child_discriminator(
    parent: &str,
    discriminator: u64,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), CodecError> {
    let Some(bound) = context
        .registry
        .child_for(parent, Discriminator(discriminator))
    else {
        return Ok(());
    };
    if bound.as_str() == "raw" {
        return Ok(());
    }

    let actual = context.child.and_then(|child| {
        (!matches!(child.protocol_id().as_str(), "padding" | "raw"))
            .then(|| binding_protocol(child))
    });
    if actual == Some(bound) {
        return Ok(());
    }
    let absent_payload = context
        .child
        .is_none_or(|child| child.protocol_id().as_str() == "padding");
    // A malformed binding also represents a known terminal discriminator
    // (IPv6 No Next Header). It is valid with no protocol payload, while any
    // actual bytes must be represented by MalformedLayer rather than Raw.
    if bound.as_str() == "malformed" && absent_payload {
        return Ok(());
    }

    let message = match actual {
        Some(actual) => {
            format!("discriminator {discriminator} selects registered layer {bound}, not {actual}")
        }
        None => format!(
            "discriminator {discriminator} selects registered layer {bound}, but that layer is absent"
        ),
    };
    if context.mode == BuildMode::Strict {
        return Err(invalid(parent, message));
    }
    let code = if context
        .child
        .is_some_and(|child| child.protocol_id().as_str() == "raw")
    {
        "build.raw_typed_discriminator"
    } else {
        "build.discriminator_child_mismatch"
    };
    diagnostics.push(Diagnostic::warning(code, message).at_field("discriminator"));
    Ok(())
}

/// The dual of [`validate_raw_child_discriminator`]: a typed child must be
/// selected by its discriminator on dissection. When the discriminator is
/// unregistered — or registered only to the raw fallback — the emitted bytes
/// would dissect back as opaque raw bytes, not as the declared layer.
/// Registered typed selections are left to `validate_raw_child_discriminator`,
/// which already rejects a mismatch there.
pub(crate) fn validate_typed_child_discriminator(
    parent: &str,
    discriminator: u64,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), CodecError> {
    let Some(child) = context.child else {
        return Ok(());
    };
    if matches!(
        child.protocol_id().as_str(),
        "raw" | "padding" | "malformed"
    ) {
        return Ok(());
    }
    if context
        .registry
        .child_for(parent, Discriminator(discriminator))
        .is_some_and(|bound| bound.as_str() != "raw")
    {
        return Ok(());
    }
    strict_or_diagnostic(
        parent,
        "build.discriminator_child_mismatch",
        "discriminator",
        format!(
            "discriminator {discriminator} does not select {}; dissection would fall back to raw bytes",
            binding_protocol(child)
        ),
        context,
        diagnostics,
    )
}

pub(crate) fn validate_auto_raw_discriminator<T>(
    name: &str,
    field: &'static str,
    value: &WireValue<T>,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), CodecError> {
    if !matches!(value, WireValue::Auto)
        || context
            .child
            .is_none_or(|child| child.protocol_id().as_str() != "raw")
    {
        return Ok(());
    }
    let message = format!(
        "Auto {field} cannot infer wire intent from Raw; supply an explicit unknown discriminator"
    );
    if context.mode == BuildMode::Strict {
        return Err(invalid(name, message));
    }
    diagnostics.push(Diagnostic::warning("build.auto_raw_discriminator", message).at_field(field));
    Ok(())
}

pub(crate) fn strict_or_diagnostic(
    name: &str,
    code: &'static str,
    field: &'static str,
    message: impl Into<String>,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), CodecError> {
    let message = message.into();
    if context.mode == BuildMode::Strict {
        return Err(invalid(name, message));
    }
    diagnostics.push(Diagnostic::warning(code, message).at_field(field));
    Ok(())
}

pub(crate) fn ensure_encode_budget(
    name: &str,
    contribution: usize,
    context: &LayerEncodeContext<'_>,
) -> Result<(), CodecError> {
    if contribution > context.remaining_packet_bytes {
        return Err(invalid(
            name,
            format!(
                "layer contributes {contribution} bytes but only {} remain in the packet-size budget",
                context.remaining_packet_bytes
            ),
        ));
    }
    Ok(())
}
