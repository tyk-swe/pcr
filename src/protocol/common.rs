// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::packet::internal::{
    BuildMode, CodecError, Diagnostic, Discriminator, FieldError, FieldLayout, FieldValue, Layer,
    LayerEncodeContext, LayerSchema, MalformedLayer, NetworkEnvelope, Padding, ProtocolId,
    WireValue,
};

pub(crate) fn protocol(name: &str) -> ProtocolId {
    ProtocolId::new(name)
}

pub(crate) fn binding_protocol(layer: &dyn Layer) -> ProtocolId {
    layer
        .as_any()
        .downcast_ref::<MalformedLayer>()
        .and_then(|layer| layer.intended_protocol.clone())
        .unwrap_or_else(|| layer.protocol_id())
}

pub(crate) fn wrong_layer(expected: &str, actual: &dyn Layer) -> CodecError {
    CodecError::WrongLayer {
        expected: protocol(expected),
        actual: actual.protocol_id(),
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

pub(crate) fn unknown_field(schema: &'static LayerSchema, field: &str) -> FieldError {
    FieldError::UnknownField {
        protocol: schema.protocol.clone(),
        field: field.to_owned(),
    }
}

pub(crate) fn wrong_type(
    schema: &'static LayerSchema,
    field: &str,
    expected: &'static str,
) -> FieldError {
    FieldError::WrongType {
        protocol: schema.protocol.clone(),
        field: field.to_owned(),
        expected,
    }
}

pub(crate) fn out_of_range(schema: &'static LayerSchema, field: &str) -> FieldError {
    FieldError::OutOfRange {
        protocol: schema.protocol.clone(),
        field: field.to_owned(),
    }
}

pub(crate) fn field_layout(name: &str, start: usize, end: usize) -> FieldLayout {
    FieldLayout {
        name: name.to_owned(),
        range: crate::packet::internal::ByteRange::new(start, end),
    }
}

pub(crate) fn wire_u8(value: &WireValue<u8>) -> FieldValue {
    match value {
        WireValue::Auto => FieldValue::Text("auto".to_string()),
        WireValue::Exact(value) => FieldValue::Unsigned(u64::from(*value)),
        WireValue::Raw(value) => FieldValue::Bytes(value.clone()),
    }
}

pub(crate) fn wire_u16(value: &WireValue<u16>) -> FieldValue {
    match value {
        WireValue::Auto => FieldValue::Text("auto".to_string()),
        WireValue::Exact(value) => FieldValue::Unsigned(u64::from(*value)),
        WireValue::Raw(value) => FieldValue::Bytes(value.clone()),
    }
}

pub(crate) fn set_wire_u8(
    target: &mut WireValue<u8>,
    schema: &'static LayerSchema,
    field: &str,
    value: FieldValue,
) -> Result<(), FieldError> {
    *target = match value {
        FieldValue::Text(value) if value.eq_ignore_ascii_case("auto") => WireValue::Auto,
        FieldValue::Unsigned(value) => {
            WireValue::Exact(u8::try_from(value).map_err(|_| out_of_range(schema, field))?)
        }
        FieldValue::Bytes(value) => WireValue::Raw(value),
        _ => return Err(wrong_type(schema, field, "unsigned, bytes, or 'auto'")),
    };
    Ok(())
}

pub(crate) fn set_wire_u16(
    target: &mut WireValue<u16>,
    schema: &'static LayerSchema,
    field: &str,
    value: FieldValue,
) -> Result<(), FieldError> {
    *target = match value {
        FieldValue::Text(value) if value.eq_ignore_ascii_case("auto") => WireValue::Auto,
        FieldValue::Unsigned(value) => {
            WireValue::Exact(u16::try_from(value).map_err(|_| out_of_range(schema, field))?)
        }
        FieldValue::Bytes(value) => WireValue::Raw(value),
        _ => return Err(wrong_type(schema, field, "unsigned, bytes, or 'auto'")),
    };
    Ok(())
}

pub(crate) fn resolve_u8(
    name: &str,
    field: &str,
    value: &WireValue<u8>,
    expected: u8,
    validate_exact: bool,
    mode: BuildMode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(u8, WireValue<u8>), CodecError> {
    match value {
        WireValue::Auto => Ok((expected, WireValue::Exact(expected))),
        WireValue::Exact(actual) => {
            validate_dependent(
                name,
                field,
                u64::from(*actual),
                u64::from(expected),
                validate_exact,
                mode,
                diagnostics,
            )?;
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
    expected: u16,
    validate_exact: bool,
    mode: BuildMode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(u16, WireValue<u16>), CodecError> {
    match value {
        WireValue::Auto => Ok((expected, WireValue::Exact(expected))),
        WireValue::Exact(actual) => {
            validate_dependent(
                name,
                field,
                u64::from(*actual),
                u64::from(expected),
                validate_exact,
                mode,
                diagnostics,
            )?;
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

fn validate_dependent(
    name: &str,
    field: &str,
    actual: u64,
    expected: u64,
    enabled: bool,
    mode: BuildMode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), CodecError> {
    if !enabled || actual == expected {
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

pub(crate) fn make_layer<L>(
    mut layer: L,
    fields: &BTreeMap<String, FieldValue>,
) -> Result<Box<dyn Layer>, CodecError>
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
) -> Result<BTreeMap<String, FieldValue>, CodecError> {
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

pub(crate) fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u64;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u64::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u64::from(*byte) << 8;
    }
    fold_checksum(sum)
}

fn fold_checksum(mut sum: u64) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn transport_checksum(
    network: NetworkEnvelope,
    protocol_number: u8,
    segment: &[u8],
) -> Result<u16, CodecError> {
    let mut pseudo = Vec::new();
    match (network.source, network.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let length = u16::try_from(segment.len())
                .map_err(|_| invalid("transport", "IPv4 transport segment exceeds 65535 bytes"))?;
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&[0, protocol_number]);
            pseudo.extend_from_slice(&length.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let length = u32::try_from(segment.len())
                .map_err(|_| invalid("transport", "IPv6 transport segment exceeds u32 length"))?;
            pseudo.extend_from_slice(&source.octets());
            pseudo.extend_from_slice(&destination.octets());
            pseudo.extend_from_slice(&length.to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, protocol_number]);
        }
        _ => return Err(invalid("transport", "mixed IP versions in pseudo-header")),
    }
    pseudo.extend_from_slice(segment);
    Ok(checksum(&pseudo))
}

pub(crate) fn network_from_addresses(source: IpAddr, destination: IpAddr) -> NetworkEnvelope {
    NetworkEnvelope {
        source,
        destination,
    }
}

pub(crate) fn ipv4(value: &FieldValue) -> Option<Ipv4Addr> {
    match value {
        FieldValue::Ipv4(value) => Some(*value),
        FieldValue::Text(value) => value.parse().ok(),
        _ => None,
    }
}

pub(crate) fn ipv6(value: &FieldValue) -> Option<Ipv6Addr> {
    match value {
        FieldValue::Ipv6(value) => Some(*value),
        FieldValue::Text(value) => value.parse().ok(),
        _ => None,
    }
}

pub(crate) fn mac(value: &FieldValue) -> Option<[u8; 6]> {
    match value {
        FieldValue::Mac(value) => Some(*value),
        FieldValue::Text(value) => {
            let normalized = value.replace('-', ":");
            let mut output = [0_u8; 6];
            let mut parts = normalized.split(':');
            for byte in &mut output {
                let part = parts.next()?;
                if part.len() != 2 {
                    return None;
                }
                *byte = u8::from_str_radix(part, 16).ok()?;
            }
            parts.next().is_none().then_some(output)
        }
        _ => None,
    }
}

pub(crate) fn bytes(value: &FieldValue) -> Option<Bytes> {
    match value {
        FieldValue::Bytes(value) => Some(value.clone()),
        _ => None,
    }
}

/// Returns the protocol-covered payload, excluding explicit trailing link padding.
pub(crate) fn payload_without_padding<'a>(
    name: &str,
    payload: &'a [u8],
    context: &LayerEncodeContext<'_>,
) -> Result<&'a [u8], CodecError> {
    let trailing = context
        .packet
        .iter()
        .skip(context.index + 1)
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
    Ok(&payload[..covered])
}

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
        .child_for(&protocol(parent), Discriminator(discriminator))
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
    if actual.as_ref() == Some(bound) {
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
        Some(actual) => format!(
            "discriminator {discriminator} selects registered layer {bound}, not {actual}"
        ),
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

pub(crate) fn validate_auto_raw_discriminator(
    name: &str,
    field: &'static str,
    is_auto: bool,
    context: &LayerEncodeContext<'_>,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), CodecError> {
    if !is_auto
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

macro_rules! impl_layer_boilerplate {
    ($ty:ty, $schema:path) => {
        fn schema(&self) -> &'static LayerSchema {
            $schema()
        }

        fn clone_box(&self) -> Box<dyn Layer> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
            self
        }
    };
}

pub(crate) use impl_layer_boilerplate;

#[cfg(test)]
mod tests {
    use super::checksum;

    #[test]
    fn checksum_preserves_end_around_carries_above_u32_accumulator_range() {
        let words = 65_538_usize;
        assert_eq!(checksum(&vec![0xff; words * 2]), 0);
    }
}
