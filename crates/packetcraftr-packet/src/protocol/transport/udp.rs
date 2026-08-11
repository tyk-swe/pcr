// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! UDP datagram model and codec.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflective_layer},
    registry::Discriminator,
    semantics::BuiltinProtocol,
};

use super::super::common::{
    ValueExpectation, aliased_fields, invalid, make_layer, out_of_range, payload_without_padding,
    protocol, resolve_u16, strict_or_diagnostic, transport_checksum, transport_checksum_parts,
    truncated, wrong_layer, wrong_type,
};
use super::super::network::encode_network;

const UDP_LEN: usize = 8;
const DNS_HEADER_LEN: usize = 12;
const DNS_PORT: u16 = 53;
const DNS_RESPONSE_FLAG: u16 = 0x8000;
const DNS_RESERVED_Z_FLAG: u16 = 0x0040;

/// Child discriminators in dissection order. The destination port normally
/// wins, but a structurally plausible DNS response gives source port 53
/// precedence so replies to a client port that is also registered for a
/// tunnel still dissect as DNS. A zero port never shadows the raw fallback.
fn child_discriminators(
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<Discriminator> {
    let ports = if dns_response_prefers_source_port(source_port, payload) {
        [source_port, destination_port]
    } else {
        [destination_port, source_port]
    };
    let mut next = Vec::with_capacity(3);
    for port in ports {
        let discriminator = Discriminator(u64::from(port));
        if port != 0 && !next.contains(&discriminator) {
            next.push(discriminator);
        }
    }
    next.push(Discriminator(0));
    next
}

fn dns_response_prefers_source_port(source_port: u16, payload: &[u8]) -> bool {
    if source_port != DNS_PORT || payload.len() < DNS_HEADER_LEN {
        return false;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    flags & DNS_RESPONSE_FLAG != 0 && flags & DNS_RESERVED_Z_FLAG == 0
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Udp {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: WireValue<u16>,
    pub checksum: WireValue<u16>,
}

impl Default for Udp {
    fn default() -> Self {
        Self {
            source_port: 53_000,
            destination_port: 53,
            length: WireValue::Auto,
            checksum: WireValue::Auto,
        }
    }
}

reflective_layer! {
    fn udp_schema() => { protocol: protocol("udp"), name: "UDP" }
    impl Udp {
        "source_port" => {
            kind: Unsigned, derived: false, required: true,
            description: "UDP source port",
            get |layer| Some(layer.source_port.into()),
            set |layer, value, name| match value {
                FieldValue::Unsigned(value) => {
                    layer.source_port = u16::try_from(value)
                        .map_err(|_| out_of_range(udp_schema(), name))?;
                    Ok(())
                }
                _ => Err(wrong_type(udp_schema(), name, "unsigned")),
            },
            layout: (0, 2)
        },
        "destination_port" => {
            kind: Unsigned, derived: false, required: true,
            description: "UDP destination port",
            get |layer| Some(layer.destination_port.into()),
            set |layer, value, name| match value {
                FieldValue::Unsigned(value) => {
                    layer.destination_port = u16::try_from(value)
                        .map_err(|_| out_of_range(udp_schema(), name))?;
                    Ok(())
                }
                _ => Err(wrong_type(udp_schema(), name, "unsigned")),
            },
            layout: (2, 4)
        },
        "length" => {
            kind: Unsigned, derived: true, required: false,
            description: "UDP datagram length",
            reflect: length,
            layout: (4, 6)
        },
        "checksum" => {
            kind: Unsigned, derived: true, required: false,
            description: "UDP checksum",
            reflect: checksum,
            layout: (6, 8)
        },
    }
    layout pub(crate) fn udp_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UdpCodec;

impl LayerCodec for UdpCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("udp")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Udp>()
            .ok_or_else(|| wrong_layer("udp", layer))?;
        let covered_payload = payload_without_padding("udp", payload, context)?;
        let expected_length = UDP_LEN
            .checked_add(covered_payload.len())
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| invalid("udp", "datagram exceeds UDP length range"))?;
        let mut diagnostics = Vec::new();
        // Dissection normally selects the child from the destination port.
        // A plausible DNS response instead gives source port 53 precedence.
        // When that selection disagrees
        // with the declared child — an encapsulation away from its registered
        // port, or an opaque payload sitting on one — the built bytes would
        // not round-trip into the same layers. Padding and malformed children
        // are byte-preserving pseudo-layers outside the selection, so
        // dissected captures always rebuild.
        if let Some(child) = context.child
            && !matches!(
                BuiltinProtocol::from_id(child.protocol_id()),
                Some(BuiltinProtocol::Padding | BuiltinProtocol::Malformed)
            )
            && let Some(selected) =
                child_discriminators(layer.source_port, layer.destination_port, covered_payload)
                    .into_iter()
                    .find_map(|discriminator| context.registry.child_for("udp", discriminator))
            && *selected != *child.protocol_id()
        {
            let message = match context
                .registry
                .discriminator_for("udp", child.protocol_id().as_str())
                .filter(|discriminator| discriminator.0 != 0)
            {
                Some(registered) => format!(
                    "{} dissects only from UDP port {}; set that port on one endpoint",
                    child.protocol_id(),
                    registered.0
                ),
                None => format!(
                    "these UDP ports dissect the payload as {selected}, not {}; move it off the registered port",
                    child.protocol_id()
                ),
            };
            strict_or_diagnostic(
                "udp",
                "build.udp_encapsulation_port",
                "destination_port",
                message,
                context,
                &mut diagnostics,
            )?;
        }
        let (length, materialized_length) = resolve_u16(
            "udp",
            "length",
            &layer.length,
            ValueExpectation::Required(expected_length),
            context.mode,
            &mut diagnostics,
        )?;
        let network = encode_network(context)?;
        let mut header = [0_u8; UDP_LEN];
        header[0..2].copy_from_slice(&layer.source_port.to_be_bytes());
        header[2..4].copy_from_slice(&layer.destination_port.to_be_bytes());
        header[4..6].copy_from_slice(&length.to_be_bytes());
        let mut checksum_expected =
            transport_checksum_parts(network, 17, &[&header, covered_payload])?;
        if checksum_expected == 0 {
            checksum_expected = 0xffff;
        }
        let ipv4_omitted = matches!(network.source, IpAddr::V4(_))
            && matches!(layer.checksum, WireValue::Exact(0));
        let (checksum, materialized_checksum) = resolve_u16(
            "udp",
            "checksum",
            &layer.checksum,
            if ipv4_omitted {
                ValueExpectation::Suggested(checksum_expected)
            } else {
                ValueExpectation::Required(checksum_expected)
            },
            context.mode,
            &mut diagnostics,
        )?;
        header[6..8].copy_from_slice(&checksum.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.length = materialized_length;
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer {
            prefix: header.to_vec(),
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: udp_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < UDP_LEN {
            return Err(truncated("udp", UDP_LEN, input.len()));
        }
        let length_field = u16::from_be_bytes([input[4], input[5]]);
        let length = usize::from(length_field);
        if length < UDP_LEN {
            return Err(invalid(
                "udp",
                format!("length {length} is below {UDP_LEN}"),
            ));
        }
        if input.len() < length {
            return Err(truncated("udp", length, input.len()));
        }
        let checksum_value = u16::from_be_bytes([input[6], input[7]]);
        let mut diagnostics = Vec::new();
        if context.verify_checksums
            && let Some(network) = context.network
        {
            if checksum_value == 0 {
                if matches!(network.source, IpAddr::V6(_)) {
                    diagnostics.push(
                        Diagnostic::warning(
                            "decode.udp_checksum",
                            "zero UDP checksum is invalid for IPv6",
                        )
                        .at_field("checksum"),
                    );
                }
            } else if transport_checksum(network, 17, &input[..length])? != 0 {
                diagnostics.push(
                    Diagnostic::warning("decode.udp_checksum", "UDP checksum mismatch")
                        .at_field("checksum"),
                );
            }
        }
        let payload_len = length - UDP_LEN;
        let source_port = u16::from_be_bytes([input[0], input[1]]);
        let destination_port = u16::from_be_bytes([input[2], input[3]]);
        Ok(DecodedLayerValue {
            layer: Box::new(Udp {
                source_port,
                destination_port,
                length: WireValue::Exact(length_field),
                checksum: WireValue::Exact(checksum_value),
            }),
            consumed: UDP_LEN,
            payload_len,
            // Both endpoints are offered before the raw fallback. Destination
            // normally wins; a plausible DNS response gives source port 53
            // precedence so a tunnel-service-numbered client port stays DNS.
            next: if payload_len == 0 {
                Vec::new()
            } else {
                child_discriminators(source_port, destination_port, &input[UDP_LEN..length])
            },
            fields: udp_layout(),
            diagnostics,
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Udp::default(),
            &aliased_fields(
                "udp",
                fields,
                &[("sport", "source_port"), ("dport", "destination_port")],
            )?,
        )
    }
}
