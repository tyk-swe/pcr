// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! UDP datagram model and codec.

use std::collections::BTreeMap;
use std::net::IpAddr;

use packetcraftr_packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
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

/// Child discriminators in dissection order: the destination port, then the
/// source port, then the raw fallback. A zero port is not a service port and
/// must never shadow the fallback slot, so it is skipped rather than offered.
fn child_discriminators(source_port: u16, destination_port: u16) -> Vec<Discriminator> {
    let mut next = Vec::with_capacity(3);
    for port in [destination_port, source_port] {
        if port != 0 {
            next.push(Discriminator(u64::from(port)));
        }
    }
    next.push(Discriminator(0));
    next
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
            get |layer| Some(reflect_get(&layer.length)),
            set |layer, value, name| reflect_set(&mut layer.length, udp_schema(), name, value),
            layout: (4, 6)
        },
        "checksum" => {
            kind: Unsigned, derived: true, required: false,
            description: "UDP checksum",
            get |layer| Some(reflect_get(&layer.checksum)),
            set |layer, value, name| reflect_set(&mut layer.checksum, udp_schema(), name, value),
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

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
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
        // Dissection selects the child from the destination port, then the
        // source port, then the raw fallback. When that selection disagrees
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
            && let Some(selected) = child_discriminators(layer.source_port, layer.destination_port)
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
            payload_offset: UDP_LEN,
            payload_len,
            // Encapsulations register on their well-known ports, so both
            // ports are offered as discriminators before the raw fallback:
            // either endpoint of a tunnel may own the registered port.
            next: if payload_len == 0 {
                Vec::new()
            } else {
                child_discriminators(source_port, destination_port)
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
