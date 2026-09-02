// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IPv6 base header model and codec.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{
    ValueExpectation, expected_discriminator, invalid, make_layer, network_from_addresses,
    payload_without_padding, protocol, resolve_u8, resolve_u16, strict_or_diagnostic, truncated,
    typed_layer, validate_auto_raw_discriminator, validate_ipv6_routing_child,
    validate_raw_child_discriminator,
};

use super::envelope::{is_ipv6_extension_layer, is_outer_network_layer};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Ipv6.as_str();

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
    fn ipv6_schema() => { protocol: protocol(NAME), name: "IPv6" }
    impl Ipv6 {
        "traffic_class" => { kind: Unsigned, derived: false, required: false, description: "IPv6 traffic class", reflect: traffic_class, layout: (0, 4) },
        "flow_label" => { kind: Unsigned, derived: false, required: false, description: "IPv6 flow label", reflect_bounded: flow_label, 0x000f_ffff_u64, layout: (0, 4) },
        "payload_length" => { kind: Unsigned, derived: true, required: false, description: "IPv6 payload length", reflect: payload_length, layout: (4, 6) },
        "next_header" => { kind: Unsigned, derived: true, required: false, description: "Next-header discriminator", reflect: next_header, layout: (6, 7) },
        "hop_limit" => { kind: Unsigned, derived: false, required: true, description: "Hop limit", reflect: hop_limit, layout: (7, 8) },
        "source" | "src" => { kind: Ipv6, derived: false, required: true, description: "Source IPv6 address", reflect: source, layout: (8, 24) },
        "destination" | "dst" => { kind: Ipv6, derived: false, required: true, description: "Destination IPv6 address", reflect: destination, layout: (24, 40) },
    }
    layout pub(crate) fn ipv6_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Ipv6Codec;

impl LayerCodec for Ipv6Codec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &ipv6_schema().protocol
    }
    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Ipv6>(NAME, layer)?;
        if layer.flow_label > 0x000f_ffff {
            return Err(invalid(NAME, "flow label exceeds 20 bits"));
        }
        let (source, destination, mut diagnostics) = resolve_addresses(layer, context)?;
        let covered_payload = payload_without_padding(NAME, payload, context)?;
        let expected_length = u16::try_from(covered_payload.len())
            .map_err(|_| invalid(NAME, "jumbograms are not supported"))?;
        let (payload_length, materialized_length) = resolve_u16(
            NAME,
            "payload_length",
            &layer.payload_length,
            ValueExpectation::Required(expected_length),
            context.mode,
            &mut diagnostics,
        )?;
        let expected_next = expected_discriminator(NAME, context, 59_u8, &layer.next_header);
        validate_auto_raw_discriminator(
            NAME,
            "next_header",
            &layer.next_header,
            context,
            &mut diagnostics,
        )?;
        let (next_header, materialized_next) = resolve_u8(
            NAME,
            "next_header",
            &layer.next_header,
            expected_next,
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator(NAME, u64::from(next_header), context, &mut diagnostics)?;
        validate_ipv6_routing_child(NAME, next_header, context, &mut diagnostics)?;
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
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(ipv6_layout())
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<IPV6_LEN>() else {
            return Err(truncated(NAME, IPV6_LEN, input.len()));
        };
        if header[0] >> 4 != 6 {
            return Err(invalid(
                NAME,
                format!("version is {}, not 6", header[0] >> 4),
            ));
        }
        let payload_length_field = u16::from_be_bytes([header[4], header[5]]);
        let payload_length = usize::from(payload_length_field);
        // A jumbogram must start with a Hop-by-Hop header carrying the Jumbo
        // Payload option. With any other next header, the declared IPv6
        // payload is empty and any remaining capture bytes are outside it;
        // the dissector will classify them as link padding or a malformed
        // trailer according to the enclosing link context.
        if payload_length == 0 && input.len() > IPV6_LEN && header[6] == 0 {
            return Err(crate::codec::Error::Unsupported {
                protocol: protocol(NAME),
                message: "IPv6 jumbogram payload requires a Hop-by-Hop Jumbo Payload option"
                    .to_string(),
            });
        }
        let required = IPV6_LEN
            .checked_add(payload_length)
            .ok_or_else(|| invalid(NAME, "payload length overflow"))?;
        if input.len() < required {
            return Err(truncated(NAME, required, input.len()));
        }
        let first = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let source_bytes = input
            .get(8..)
            .and_then(<[u8]>::first_chunk::<16>)
            .ok_or_else(|| truncated(NAME, IPV6_LEN, input.len()))?;
        let source = Ipv6Addr::from(*source_bytes);
        let destination_bytes = input
            .get(24..)
            .and_then(<[u8]>::first_chunk::<16>)
            .ok_or_else(|| truncated(NAME, IPV6_LEN, input.len()))?;
        let destination = Ipv6Addr::from(*destination_bytes);
        let next = header[6];
        Ok(DecodedLayer {
            layer: Box::new(Ipv6 {
                traffic_class: ((first >> 20) & 0xff) as u8,
                flow_label: first & 0x000f_ffff,
                payload_length: WireValue::Exact(payload_length_field),
                next_header: WireValue::Exact(next),
                hop_limit: header[7],
                source,
                destination,
            }),
            consumed: IPV6_LEN,
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
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Ipv6::default(), fields)
    }
}

fn resolve_addresses(
    layer: &Ipv6,
    context: &LayerEncodeContext<'_>,
) -> Result<(Ipv6Addr, Ipv6Addr, Vec<Diagnostic>), crate::codec::Error> {
    let inherit = is_outer_network_layer(context.packet, context.index);
    let source = match context.build_context.source {
        Some(IpAddr::V6(source)) if inherit && layer.source.is_unspecified() => source,
        _ => layer.source,
    };
    let active_segment = context
        .packet
        .iter()
        .skip(context.index.saturating_add(1))
        .take_while(|candidate| is_ipv6_extension_layer(*candidate))
        .find_map(|candidate| {
            let routing = candidate
                .as_any()
                .downcast_ref::<crate::protocol::ipv6::SegmentRoutingHeader>()?;
            let last = routing.segments.len().checked_sub(1)?;
            let segments_left = match routing.segments_left {
                WireValue::Auto => last,
                WireValue::Exact(value) => usize::from(value).min(last),
                WireValue::Raw(_) => return None,
            };
            last.checked_sub(segments_left)
                .and_then(|index| routing.segments.get(index))
                .copied()
        });
    let mut diagnostics = Vec::new();
    if let Some(active) = active_segment
        && !layer.destination.is_unspecified()
        && layer.destination != active
    {
        strict_or_diagnostic(
            NAME,
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
    let destination = match (
        layer.destination.is_unspecified(),
        active_segment,
        context.build_context.destination,
    ) {
        (true, Some(active), _) => active,
        (true, None, Some(IpAddr::V6(destination))) if inherit => destination,
        _ => layer.destination,
    };
    Ok((source, destination, diagnostics))
}
