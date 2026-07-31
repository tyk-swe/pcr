// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IPv6 base header model and codec.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};

use packetcraftr_packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ValueExpectation, aliased_fields, expected_discriminator, invalid, make_layer,
    network_from_addresses, out_of_range, payload_without_padding, protocol, resolve_u8,
    resolve_u16, strict_or_diagnostic, truncated, validate_auto_raw_discriminator,
    validate_ipv6_routing_child, validate_raw_child_discriminator, wrong_layer, wrong_type,
};

use super::encode::{is_ipv6_extension_layer, is_outer_network_layer};

const IPV6_LEN: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6 {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: WireValue<u16>,
    pub next_header: WireValue<u8>,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
}

impl Default for Ipv6 {
    fn default() -> Self {
        Self {
            traffic_class: 0,
            flow_label: 0,
            payload_length: WireValue::Auto,
            next_header: WireValue::Auto,
            hop_limit: 64,
            source: Ipv6Addr::UNSPECIFIED,
            destination: Ipv6Addr::UNSPECIFIED,
        }
    }
}

reflective_layer! {
    fn ipv6_schema() => { protocol: protocol("ipv6"), name: "IPv6" }
    impl Ipv6 {
        "traffic_class" => { kind: Unsigned, derived: false, required: false, description: "IPv6 traffic class", get |layer| Some(reflect_get(&layer.traffic_class)), set |layer, value, name| reflect_set(&mut layer.traffic_class, ipv6_schema(), name, value), layout: (0, 4) },
        "flow_label" => { kind: Unsigned, derived: false, required: false, description: "IPv6 flow label", get |layer| Some(reflect_get(&layer.flow_label)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.flow_label = u32::try_from(value).ok().filter(|value| *value <= 0x000f_ffff).ok_or_else(|| out_of_range(ipv6_schema(), name))?; Ok(()) }, _ => Err(wrong_type(ipv6_schema(), name, "unsigned")) }, layout: (0, 4) },
        "payload_length" => { kind: Unsigned, derived: true, required: false, description: "IPv6 payload length", get |layer| Some(reflect_get(&layer.payload_length)), set |layer, value, name| reflect_set(&mut layer.payload_length, ipv6_schema(), name, value), layout: (4, 6) },
        "next_header" => { kind: Unsigned, derived: true, required: false, description: "Next-header discriminator", get |layer| Some(reflect_get(&layer.next_header)), set |layer, value, name| reflect_set(&mut layer.next_header, ipv6_schema(), name, value), layout: (6, 7) },
        "hop_limit" => { kind: Unsigned, derived: false, required: true, description: "Hop limit", get |layer| Some(reflect_get(&layer.hop_limit)), set |layer, value, name| reflect_set(&mut layer.hop_limit, ipv6_schema(), name, value), layout: (7, 8) },
        "source" => { kind: Ipv6, derived: false, required: true, description: "Source IPv6 address", get |layer| Some(reflect_get(&layer.source)), set |layer, value, name| reflect_set(&mut layer.source, ipv6_schema(), name, value), layout: (8, 24) },
        "destination" => { kind: Ipv6, derived: false, required: true, description: "Destination IPv6 address", get |layer| Some(reflect_get(&layer.destination)), set |layer, value, name| reflect_set(&mut layer.destination, ipv6_schema(), name, value), layout: (24, 40) },
    }
    layout pub(crate) fn ipv6_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Ipv6Codec;

impl LayerCodec for Ipv6Codec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv6")
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
            .downcast_ref::<Ipv6>()
            .ok_or_else(|| wrong_layer("ipv6", layer))?;
        if layer.flow_label > 0x000f_ffff {
            return Err(invalid("ipv6", "flow label exceeds 20 bits"));
        }
        let inherit_context = is_outer_network_layer(context.packet, context.index);
        let source = if layer.source.is_unspecified() && inherit_context {
            match context.build_context.source {
                Some(IpAddr::V6(source)) => source,
                _ => layer.source,
            }
        } else {
            layer.source
        };
        let srh_active = context
            .packet
            .iter()
            .skip(context.index + 1)
            // Only the contiguous IPv6 extension chain belongs to this
            // envelope. A routing header beyond a transport, opaque payload,
            // or nested network header belongs to another protocol scope.
            .take_while(|candidate| is_ipv6_extension_layer(*candidate))
            .find_map(|candidate| {
                let srh = candidate
                    .as_any()
                    .downcast_ref::<super::super::ipv6::SegmentRoutingHeader>()?;
                let last = srh.segments.len().checked_sub(1)?;
                let segments_left = match srh.segments_left {
                    WireValue::Auto => last,
                    WireValue::Exact(value) => usize::from(value).min(last),
                    WireValue::Raw(_) => return None,
                };
                srh.segments.get(last - segments_left).copied()
            });
        let mut diagnostics = Vec::new();
        if let Some(active) = srh_active
            && !layer.destination.is_unspecified()
            && layer.destination != active
        {
            strict_or_diagnostic(
                "ipv6",
                "build.srh_outer_destination",
                "destination",
                format!(
                    "outer destination {} does not match active SRH segment {active}",
                    layer.destination
                ),
                context,
                &mut diagnostics,
            )?;
        }
        let destination = if layer.destination.is_unspecified() {
            srh_active.unwrap_or({
                if inherit_context {
                    match context.build_context.destination {
                        Some(IpAddr::V6(destination)) => destination,
                        _ => layer.destination,
                    }
                } else {
                    layer.destination
                }
            })
        } else {
            layer.destination
        };
        let covered_payload = payload_without_padding("ipv6", payload, context)?;
        let expected_length = u16::try_from(covered_payload.len())
            .map_err(|_| invalid("ipv6", "jumbograms are not supported"))?;
        let (payload_length, materialized_length) = resolve_u16(
            "ipv6",
            "payload_length",
            &layer.payload_length,
            ValueExpectation::Required(expected_length),
            context.mode,
            &mut diagnostics,
        )?;
        let expected_next = expected_discriminator("ipv6", context, 59_u8);
        validate_auto_raw_discriminator(
            "ipv6",
            "next_header",
            &layer.next_header,
            context,
            &mut diagnostics,
        )?;
        let (next_header, materialized_next) = resolve_u8(
            "ipv6",
            "next_header",
            &layer.next_header,
            expected_next,
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(
            "ipv6",
            u64::from(next_header),
            context,
            &mut diagnostics,
        )?;
        validate_ipv6_routing_child("ipv6", next_header, context, &mut diagnostics)?;
        let version_flow = (6u32 << 28) | (u32::from(layer.traffic_class) << 20) | layer.flow_label;
        let mut prefix = Vec::with_capacity(IPV6_LEN);
        prefix.extend_from_slice(&version_flow.to_be_bytes());
        prefix.extend_from_slice(&payload_length.to_be_bytes());
        prefix.push(next_header);
        prefix.push(layer.hop_limit);
        prefix.extend_from_slice(&source.octets());
        prefix.extend_from_slice(&destination.octets());
        let mut materialized = layer.clone();
        materialized.payload_length = materialized_length;
        materialized.next_header = materialized_next;
        materialized.source = source;
        materialized.destination = destination;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: ipv6_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < IPV6_LEN {
            return Err(truncated("ipv6", IPV6_LEN, input.len()));
        }
        if input[0] >> 4 != 6 {
            return Err(invalid(
                "ipv6",
                format!("version is {}, not 6", input[0] >> 4),
            ));
        }
        let payload_length_field = u16::from_be_bytes([input[4], input[5]]);
        let payload_length = usize::from(payload_length_field);
        // A jumbogram must start with a Hop-by-Hop header carrying the Jumbo
        // Payload option. With any other next header, the declared IPv6
        // payload is empty and any remaining capture bytes are outside it;
        // the dissector will classify them as link padding or a malformed
        // trailer according to the enclosing link context.
        if payload_length == 0 && input.len() > IPV6_LEN && input[6] == 0 {
            return Err(CodecError::Unsupported {
                protocol: protocol("ipv6"),
                message: "IPv6 jumbogram payload requires a Hop-by-Hop Jumbo Payload option"
                    .to_string(),
            });
        }
        let required = IPV6_LEN
            .checked_add(payload_length)
            .ok_or_else(|| invalid("ipv6", "payload length overflow"))?;
        if input.len() < required {
            return Err(truncated("ipv6", required, input.len()));
        }
        let first = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        let mut source_bytes = [0; 16];
        source_bytes.copy_from_slice(&input[8..24]);
        let source = Ipv6Addr::from(source_bytes);
        let mut destination_bytes = [0; 16];
        destination_bytes.copy_from_slice(&input[24..40]);
        let destination = Ipv6Addr::from(destination_bytes);
        let next = input[6];
        Ok(DecodedLayerValue {
            layer: Box::new(Ipv6 {
                traffic_class: ((first >> 20) & 0xff) as u8,
                flow_label: first & 0x000f_ffff,
                payload_length: WireValue::Exact(payload_length_field),
                next_header: WireValue::Exact(next),
                hop_limit: input[7],
                source,
                destination,
            }),
            consumed: IPV6_LEN,
            payload_offset: IPV6_LEN,
            payload_len: payload_length,
            next: vec![Discriminator(u64::from(next))],
            fields: ipv6_layout(),
            diagnostics: Vec::new(),
            stop: payload_length == 0,
            network: Some(network_from_addresses(source.into(), destination.into())),
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Ipv6::default(),
            &aliased_fields("ipv6", fields, &[("src", "source"), ("dst", "destination")])?,
        )
    }
}
