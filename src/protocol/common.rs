// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use crate::packet::{
    build::BuildMode,
    codec::{CodecError, LayerEncodeContext, NetworkEnvelope},
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{FieldError, Layer, LayerSchema, MalformedLayer, Padding, ProtocolId},
    registry::Discriminator,
};

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
            .discriminator_for(&protocol(parent), &child.protocol_id())
            .and_then(|value| T::try_from(value.0).ok())
            .unwrap_or(fallback);
        return ValueExpectation::Suggested(expected);
    }
    context
        .registry
        .discriminator_for(&protocol(parent), &binding_protocol(child))
        .and_then(|value| T::try_from(value.0).ok())
        .map_or(
            ValueExpectation::Suggested(fallback),
            ValueExpectation::Required,
        )
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
    checksum_parts(&[bytes])
}

pub(crate) fn checksum_parts(parts: &[&[u8]]) -> u16 {
    let mut accumulator = ChecksumAccumulator::default();
    for part in parts {
        accumulator.add(part);
    }
    accumulator.finish()
}

#[derive(Default)]
struct ChecksumAccumulator {
    sum: u64,
    pending_high_byte: Option<u8>,
}

impl ChecksumAccumulator {
    fn add(&mut self, bytes: &[u8]) {
        let mut bytes = bytes;
        if let Some(high) = self.pending_high_byte {
            let Some((&low, remaining)) = bytes.split_first() else {
                return;
            };
            self.sum += u64::from(u16::from_be_bytes([high, low]));
            bytes = remaining;
            self.pending_high_byte = None;
        }
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            self.sum += u64::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        self.pending_high_byte = chunks.remainder().first().copied();
    }

    fn finish(self) -> u16 {
        let sum = self.sum
            + self
                .pending_high_byte
                .map_or(0, |high| u64::from(high) << 8);
        fold_checksum(sum)
    }
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
    transport_checksum_parts(network, protocol_number, &[segment])
}

/// Treats `parts` as one contiguous byte stream, including across odd boundaries.
pub(crate) fn transport_checksum_parts(
    network: NetworkEnvelope,
    protocol_number: u8,
    parts: &[&[u8]],
) -> Result<u16, CodecError> {
    let transport_length = parts
        .iter()
        .try_fold(0_usize, |total, part| total.checked_add(part.len()))
        .ok_or_else(|| invalid("transport", "transport segment length overflow"))?;
    let mut accumulator = ChecksumAccumulator::default();
    match (network.source, network.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let length = u16::try_from(transport_length)
                .map_err(|_| invalid("transport", "IPv4 transport segment exceeds 65535 bytes"))?;
            accumulator.add(&source.octets());
            accumulator.add(&destination.octets());
            accumulator.add(&[0, protocol_number]);
            accumulator.add(&length.to_be_bytes());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let length = u32::try_from(transport_length)
                .map_err(|_| invalid("transport", "IPv6 transport segment exceeds u32 length"))?;
            accumulator.add(&source.octets());
            accumulator.add(&destination.octets());
            accumulator.add(&length.to_be_bytes());
            accumulator.add(&[0, 0, 0, protocol_number]);
        }
        _ => return Err(invalid("transport", "mixed IP versions in pseudo-header")),
    }
    for part in parts {
        accumulator.add(part);
    }
    Ok(accumulator.finish())
}

pub(crate) fn network_from_addresses(source: IpAddr, destination: IpAddr) -> NetworkEnvelope {
    NetworkEnvelope {
        source,
        destination,
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::packet::codec::NetworkEnvelope;

    use super::{checksum, checksum_parts, transport_checksum, transport_checksum_parts};

    #[test]
    fn checksum_preserves_end_around_carries_above_u32_accumulator_range() {
        let words = 65_538_usize;
        assert_eq!(checksum(&vec![0xff; words * 2]), 0);
    }

    #[test]
    fn checksum_parts_carries_odd_bytes_across_boundaries() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(
            checksum_parts(&[&bytes[..1], &bytes[1..4], &bytes[4..]]),
            checksum(&bytes)
        );
    }

    #[test]
    fn transport_checksum_parts_match_known_vectors() {
        let header = [0x13, 0x88, 0x00, 0x35, 0x00, 0x0d, 0x00, 0x00];
        let payload = [0xde, 0xad, 0xbe, 0xef, 0x01];
        let mut segment = header.to_vec();
        segment.extend_from_slice(&payload);
        for (network, expected) in [
            (
                NetworkEnvelope {
                    source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                },
                0x6142,
            ),
            (
                NetworkEnvelope {
                    source: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                    destination: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                },
                0xf204,
            ),
        ] {
            assert_eq!(
                transport_checksum_parts(network, 17, &[&header[..3], &header[3..], &payload])
                    .unwrap(),
                expected
            );
            assert_eq!(transport_checksum(network, 17, &segment).unwrap(), expected);
        }
    }
}
