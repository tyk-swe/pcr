// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext, NetworkEnvelope,
    },
    diagnostic::Diagnostic,
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ValueExpectation, aliased_fields, checksum, expected_discriminator, invalid, make_layer,
    network_from_addresses, out_of_range, payload_without_padding, protocol, resolve_u8,
    resolve_u16, strict_or_diagnostic, truncated, validate_auto_raw_discriminator,
    validate_ipv6_routing_child, validate_raw_child_discriminator, wrong_layer, wrong_type,
};

const IPV4_MIN_LEN: usize = 20;
const IPV6_LEN: usize = 40;

fn is_ipv6_extension_layer(layer: &dyn Layer) -> bool {
    matches!(
        layer.protocol_id().as_str(),
        "ipv6_hop_by_hop" | "ipv6_destination_options" | "ipv6_fragment" | "ipv6_srh"
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4 {
    pub dscp_ecn: u8,
    pub total_length: WireValue<u16>,
    pub identification: u16,
    pub reserved_flag: bool,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: WireValue<u8>,
    pub checksum: WireValue<u16>,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub options: Bytes,
}

impl Default for Ipv4 {
    fn default() -> Self {
        Self {
            dscp_ecn: 0,
            total_length: WireValue::Auto,
            identification: 0,
            reserved_flag: false,
            dont_fragment: false,
            more_fragments: false,
            fragment_offset: 0,
            ttl: 64,
            protocol: WireValue::Auto,
            checksum: WireValue::Auto,
            source: Ipv4Addr::UNSPECIFIED,
            destination: Ipv4Addr::UNSPECIFIED,
            options: Bytes::new(),
        }
    }
}

reflective_layer! {
    fn ipv4_schema() => { protocol: protocol("ipv4"), name: "IPv4" }
    impl Ipv4 {
        "dscp_ecn" => { kind: Unsigned, derived: false, required: false, description: "DSCP and ECN octet", get |layer| Some(reflect_get(&layer.dscp_ecn)), set |layer, value, name| reflect_set(&mut layer.dscp_ecn, ipv4_schema(), name, value), layout: (1, 2) },
        "total_length" => { kind: Unsigned, derived: true, required: false, description: "IPv4 total length", get |layer| Some(reflect_get(&layer.total_length)), set |layer, value, name| reflect_set(&mut layer.total_length, ipv4_schema(), name, value), layout: (2, 4) },
        "identification" => { kind: Unsigned, derived: false, required: false, description: "Fragment identification", get |layer| Some(reflect_get(&layer.identification)), set |layer, value, name| reflect_set(&mut layer.identification, ipv4_schema(), name, value), layout: (4, 6) },
        "reserved_flag" => { kind: Bool, derived: false, required: false, description: "Reserved IPv4 flag bit", get |layer| Some(reflect_get(&layer.reserved_flag)), set |layer, value, name| reflect_set(&mut layer.reserved_flag, ipv4_schema(), name, value), layout: (6, 8) },
        "dont_fragment" => { kind: Bool, derived: false, required: false, description: "Don't-fragment flag", get |layer| Some(reflect_get(&layer.dont_fragment)), set |layer, value, name| reflect_set(&mut layer.dont_fragment, ipv4_schema(), name, value), layout: (6, 8) },
        "more_fragments" => { kind: Bool, derived: false, required: false, description: "More-fragments flag", get |layer| Some(reflect_get(&layer.more_fragments)), set |layer, value, name| reflect_set(&mut layer.more_fragments, ipv4_schema(), name, value), layout: (6, 8) },
        "fragment_offset" => { kind: Unsigned, derived: false, required: false, description: "Fragment offset in eight-byte units", get |layer| Some(reflect_get(&layer.fragment_offset)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.fragment_offset = u16::try_from(value).ok().filter(|value| *value <= 0x1fff).ok_or_else(|| out_of_range(ipv4_schema(), name))?; Ok(()) }, _ => Err(wrong_type(ipv4_schema(), name, "unsigned")) }, layout: (6, 8) },
        "ttl" => { kind: Unsigned, derived: false, required: true, description: "Time to live", get |layer| Some(reflect_get(&layer.ttl)), set |layer, value, name| reflect_set(&mut layer.ttl, ipv4_schema(), name, value), layout: (8, 9) },
        "protocol" => { kind: Unsigned, derived: true, required: false, description: "Next protocol discriminator", get |layer| Some(reflect_get(&layer.protocol)), set |layer, value, name| reflect_set(&mut layer.protocol, ipv4_schema(), name, value), layout: (9, 10) },
        "checksum" => { kind: Unsigned, derived: true, required: false, description: "IPv4 header checksum", get |layer| Some(reflect_get(&layer.checksum)), set |layer, value, name| reflect_set(&mut layer.checksum, ipv4_schema(), name, value), layout: (10, 12) },
        "source" => { kind: Ipv4, derived: false, required: true, description: "Source IPv4 address", get |layer| Some(reflect_get(&layer.source)), set |layer, value, name| reflect_set(&mut layer.source, ipv4_schema(), name, value), layout: (12, 16) },
        "destination" => { kind: Ipv4, derived: false, required: true, description: "Destination IPv4 address", get |layer| Some(reflect_get(&layer.destination)), set |layer, value, name| reflect_set(&mut layer.destination, ipv4_schema(), name, value), layout: (16, 20) },
        "options" => { kind: Bytes, derived: false, required: false, description: "Verbatim IPv4 option bytes", get |layer| Some(reflect_get(&layer.options)), set |layer, value, name| reflect_set(&mut layer.options, ipv4_schema(), name, value), layout: (20, header_len) },
        normalize |layer| { layer.total_length.normalize(); layer.protocol.normalize(); layer.checksum.normalize(); }
    }
    layout fn ipv4_layout(header_len: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Ipv4Codec;

impl LayerCodec for Ipv4Codec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv4")
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
            .downcast_ref::<Ipv4>()
            .ok_or_else(|| wrong_layer("ipv4", layer))?;
        if layer.fragment_offset > 0x1fff {
            return Err(invalid("ipv4", "fragment offset exceeds 13 bits"));
        }
        if layer.options.len() > 40 {
            return Err(invalid("ipv4", "options exceed the 40-byte IPv4 limit"));
        }

        let inherit_context = is_outer_network_layer(context.packet, context.index);
        let source = if layer.source.is_unspecified() && inherit_context {
            match context.build_context.source {
                Some(IpAddr::V4(source)) => source,
                _ => layer.source,
            }
        } else {
            layer.source
        };
        let destination = if layer.destination.is_unspecified() && inherit_context {
            match context.build_context.destination {
                Some(IpAddr::V4(destination)) => destination,
                _ => layer.destination,
            }
        } else {
            layer.destination
        };

        let mut diagnostics = Vec::new();
        if layer.reserved_flag {
            let message = "reserved IPv4 flag bit is set";
            if context.mode == crate::packet::build::BuildMode::Strict {
                return Err(invalid("ipv4", message));
            }
            diagnostics.push(
                Diagnostic::warning("build.ipv4_reserved_flag", message).at_field("reserved_flag"),
            );
        }
        let mut options = layer.options.to_vec();
        let padding = (4 - (options.len() % 4)) % 4;
        if padding != 0 {
            options.resize(options.len() + padding, 0);
            diagnostics.push(
                Diagnostic::warning(
                    "build.ipv4_options_padded",
                    format!("padded IPv4 options with {padding} zero byte(s)"),
                )
                .at_field("options"),
            );
        }
        let header_len = IPV4_MIN_LEN + options.len();
        let covered_payload = payload_without_padding("ipv4", payload, context)?;
        if layer.dont_fragment && (layer.more_fragments || layer.fragment_offset != 0) {
            strict_or_diagnostic(
                "ipv4",
                "build.ipv4_conflicting_fragment_flags",
                "dont_fragment",
                "don't-fragment cannot be combined with MF or a non-zero fragment offset",
                context,
                &mut diagnostics,
            )?;
        }
        if layer.more_fragments && covered_payload.len() % 8 != 0 {
            strict_or_diagnostic(
                "ipv4",
                "build.ipv4_fragment_alignment",
                "more_fragments",
                format!(
                    "non-final fragment payload length {} is not a multiple of eight bytes",
                    covered_payload.len()
                ),
                context,
                &mut diagnostics,
            )?;
        }
        if (layer.fragment_offset != 0 || layer.more_fragments)
            && context.child.is_some_and(|child| {
                !matches!(
                    child.protocol_id().as_str(),
                    "raw" | "padding" | "malformed"
                )
            })
        {
            strict_or_diagnostic(
                "ipv4",
                "build.typed_fragment_payload",
                "fragment_offset",
                "fragment payload must be Raw; convert typed fragment payloads to Raw explicitly",
                context,
                &mut diagnostics,
            )?;
        }
        let total_expected = header_len
            .checked_add(covered_payload.len())
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| invalid("ipv4", "packet exceeds IPv4 total-length range"))?;
        let (total_length, materialized_total) = resolve_u16(
            "ipv4",
            "total_length",
            &layer.total_length,
            ValueExpectation::Required(total_expected),
            context.mode,
            &mut diagnostics,
        )?;
        let expected_protocol = expected_discriminator("ipv4", context, 255_u8);
        validate_auto_raw_discriminator(
            "ipv4",
            "protocol",
            &layer.protocol,
            context,
            &mut diagnostics,
        )?;
        let (next_protocol, materialized_protocol) = resolve_u8(
            "ipv4",
            "protocol",
            &layer.protocol,
            expected_protocol,
            context.mode,
            &mut diagnostics,
        )?;
        if layer.fragment_offset == 0 && !layer.more_fragments {
            validate_raw_child_discriminator(
                "ipv4",
                u64::from(next_protocol),
                context,
                &mut diagnostics,
            )?;
        }

        let ihl =
            u8::try_from(header_len / 4).map_err(|_| invalid("ipv4", "header length overflow"))?;
        let mut prefix = vec![0u8; header_len];
        prefix[0] = (4 << 4) | ihl;
        prefix[1] = layer.dscp_ecn;
        prefix[2..4].copy_from_slice(&total_length.to_be_bytes());
        prefix[4..6].copy_from_slice(&layer.identification.to_be_bytes());
        let flags_offset = (if layer.reserved_flag { 1 << 15 } else { 0 })
            | (if layer.dont_fragment { 1 << 14 } else { 0 })
            | (if layer.more_fragments { 1 << 13 } else { 0 })
            | layer.fragment_offset;
        prefix[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        prefix[8] = layer.ttl;
        prefix[9] = next_protocol;
        prefix[12..16].copy_from_slice(&source.octets());
        prefix[16..20].copy_from_slice(&destination.octets());
        prefix[20..].copy_from_slice(&options);
        let checksum_expected = checksum(&prefix);
        let (header_checksum, materialized_checksum) = resolve_u16(
            "ipv4",
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(checksum_expected),
            context.mode,
            &mut diagnostics,
        )?;
        prefix[10..12].copy_from_slice(&header_checksum.to_be_bytes());

        let mut materialized = layer.clone();
        materialized.total_length = materialized_total;
        materialized.protocol = materialized_protocol;
        materialized.checksum = materialized_checksum;
        materialized.source = source;
        materialized.destination = destination;
        materialized.options = Bytes::from(options);
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: ipv4_layout(header_len),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < IPV4_MIN_LEN {
            return Err(truncated("ipv4", IPV4_MIN_LEN, input.len()));
        }
        if input[0] >> 4 != 4 {
            return Err(invalid(
                "ipv4",
                format!("version is {}, not 4", input[0] >> 4),
            ));
        }
        let ihl = usize::from(input[0] & 0x0f);
        if ihl < 5 {
            return Err(invalid("ipv4", format!("IHL {ihl} is below 5")));
        }
        let header_len = ihl
            .checked_mul(4)
            .ok_or_else(|| invalid("ipv4", "IHL overflow"))?;
        if input.len() < header_len {
            return Err(truncated("ipv4", header_len, input.len()));
        }
        let total_length = usize::from(u16::from_be_bytes([input[2], input[3]]));
        if total_length < header_len {
            return Err(invalid(
                "ipv4",
                format!("total length {total_length} is smaller than header {header_len}"),
            ));
        }
        if input.len() < total_length {
            return Err(truncated("ipv4", total_length, input.len()));
        }
        let flags_offset = u16::from_be_bytes([input[6], input[7]]);
        let next = input[9];
        let source = Ipv4Addr::new(input[12], input[13], input[14], input[15]);
        let destination = Ipv4Addr::new(input[16], input[17], input[18], input[19]);
        let mut diagnostics = Vec::new();
        if context.verify_checksums && checksum(&input[..header_len]) != 0 {
            diagnostics.push(
                Diagnostic::warning("decode.ipv4_checksum", "IPv4 header checksum mismatch")
                    .at_field("checksum"),
            );
        }
        let fragment_offset = flags_offset & 0x1fff;
        if flags_offset & 0x8000 != 0 {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.ipv4_reserved_flag",
                    "reserved IPv4 flag bit is non-zero",
                )
                .at_field("reserved_flag"),
            );
        }
        let payload_len = total_length - header_len;
        Ok(DecodedLayerValue {
            layer: Box::new(Ipv4 {
                dscp_ecn: input[1],
                total_length: WireValue::Exact(total_length as u16),
                identification: u16::from_be_bytes([input[4], input[5]]),
                reserved_flag: (flags_offset & 0x8000) != 0,
                dont_fragment: (flags_offset & 0x4000) != 0,
                more_fragments: (flags_offset & 0x2000) != 0,
                fragment_offset,
                ttl: input[8],
                protocol: WireValue::Exact(next),
                checksum: WireValue::Exact(u16::from_be_bytes([input[10], input[11]])),
                source,
                destination,
                options: Bytes::copy_from_slice(&input[20..header_len]),
            }),
            consumed: header_len,
            payload_offset: header_len,
            payload_len,
            next: if fragment_offset == 0 && (flags_offset & 0x2000) == 0 {
                vec![Discriminator(u64::from(next))]
            } else {
                vec![Discriminator(255)]
            },
            fields: ipv4_layout(header_len),
            diagnostics,
            stop: payload_len == 0,
            network: Some(network_from_addresses(source.into(), destination.into())),
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            Ipv4::default(),
            &aliased_fields("ipv4", fields, &[("src", "source"), ("dst", "destination")])?,
        )
    }
}

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
        normalize |layer| { layer.payload_length.normalize(); layer.next_header.normalize(); }
    }
    layout fn ipv6_layout();
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
        let payload_length = usize::from(u16::from_be_bytes([input[4], input[5]]));
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
                payload_length: WireValue::Exact(payload_length as u16),
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

pub(crate) fn encode_network(
    context: &LayerEncodeContext<'_>,
) -> Result<NetworkEnvelope, CodecError> {
    for index in (0..context.index).rev() {
        let Some(layer) = context.packet.layer(index) else {
            continue;
        };
        if let Some(ipv4) = layer.as_any().downcast_ref::<Ipv4>() {
            let inherit_context = is_outer_network_layer(context.packet, index);
            let source = if ipv4.source.is_unspecified() && inherit_context {
                context
                    .build_context
                    .source
                    .and_then(|source| match source {
                        IpAddr::V4(source) => Some(source),
                        IpAddr::V6(_) => None,
                    })
                    .unwrap_or(ipv4.source)
            } else {
                ipv4.source
            };
            let destination = if ipv4.destination.is_unspecified() && inherit_context {
                context
                    .build_context
                    .destination
                    .and_then(|destination| match destination {
                        IpAddr::V4(destination) => Some(destination),
                        IpAddr::V6(_) => None,
                    })
                    .unwrap_or(ipv4.destination)
            } else {
                ipv4.destination
            };
            return Ok(network_from_addresses(source.into(), destination.into()));
        }
        if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            let inherit_context = is_outer_network_layer(context.packet, index);
            // Only routing headers inside the nearest IPv6 envelope can
            // replace its pseudo-header destination. An SRH belonging to an
            // outer tunnel must not affect an encapsulated transport.
            let segment_routing_destination = ((index + 1)..context.index)
                .filter_map(|candidate_index| context.packet.layer(candidate_index))
                .take_while(|candidate| is_ipv6_extension_layer(*candidate))
                .filter_map(|candidate| {
                    candidate
                        .as_any()
                        .downcast_ref::<super::super::ipv6::SegmentRoutingHeader>()?
                        .segments
                        .last()
                        .copied()
                })
                .last();
            let source = if ipv6.source.is_unspecified() && inherit_context {
                context
                    .build_context
                    .source
                    .and_then(|source| match source {
                        IpAddr::V6(source) => Some(source),
                        IpAddr::V4(_) => None,
                    })
                    .unwrap_or(ipv6.source)
            } else {
                ipv6.source
            };
            let destination = if ipv6.destination.is_unspecified() && inherit_context {
                context
                    .build_context
                    .destination
                    .and_then(|destination| match destination {
                        IpAddr::V6(destination) => Some(destination),
                        IpAddr::V4(_) => None,
                    })
                    .unwrap_or(ipv6.destination)
            } else {
                ipv6.destination
            };
            return Ok(network_from_addresses(
                source.into(),
                segment_routing_destination.unwrap_or(destination).into(),
            ));
        }
    }
    match (
        context.build_context.source,
        context.build_context.destination,
    ) {
        (Some(source), Some(destination)) if source.is_ipv4() == destination.is_ipv4() => {
            Ok(NetworkEnvelope {
                source,
                destination,
            })
        }
        _ => Err(invalid(
            "transport",
            "transport checksum requires matching source and destination IP addresses",
        )),
    }
}

fn is_outer_network_layer(packet: &crate::packet::Packet, index: usize) -> bool {
    !packet
        .iter()
        .take(index)
        .any(|layer| matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::packet::{
        Packet,
        build::{BuildContext, BuildOptions, Builder},
        registry::ProtocolRegistry,
    };
    use crate::protocol::{
        builtin::Module as BuiltinProtocols, ipv6::SegmentRoutingHeader, transport::Udp,
    };

    fn address(value: &str) -> Ipv6Addr {
        value.parse().unwrap()
    }

    fn tunnel_registry() -> Arc<ProtocolRegistry> {
        let mut builder = ProtocolRegistry::builder();
        builder.module(&BuiltinProtocols).unwrap();
        builder.bind("ipv6", 41, "ipv6", 100).unwrap();
        builder.bind("ipv6_srh", 41, "ipv6", 100).unwrap();
        Arc::new(builder.build().unwrap())
    }

    #[test]
    fn outer_srh_does_not_change_inner_ipv6_udp_checksum() {
        let inner_source = address("2001:db8:1::1");
        let inner_destination = address("2001:db8:1::2");
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                next_header: WireValue::Exact(43),
                source: address("2001:db8::1"),
                destination: address("2001:db8::10"),
                ..Ipv6::default()
            })
            .push(SegmentRoutingHeader {
                next_header: WireValue::Exact(41),
                segments: vec![address("2001:db8::10")],
                ..SegmentRoutingHeader::default()
            })
            .push(Ipv6 {
                source: inner_source,
                destination: inner_destination,
                ..Ipv6::default()
            })
            .push(Udp::default());

        let built = Builder::new(tunnel_registry())
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let udp_offset = 40 + 24 + 40;
        assert_eq!(
            super::super::super::common::transport_checksum(
                network_from_addresses(inner_source.into(), inner_destination.into()),
                17,
                &built.bytes[udp_offset..],
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn inner_srh_does_not_override_outer_ipv6_destination() {
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                next_header: WireValue::Exact(41),
                source: address("2001:db8::1"),
                destination: address("2001:db8::2"),
                ..Ipv6::default()
            })
            .push(Ipv6 {
                source: address("2001:db8:1::1"),
                destination: address("2001:db8:1::10"),
                ..Ipv6::default()
            })
            .push(SegmentRoutingHeader {
                segments: vec![address("2001:db8:1::10")],
                ..SegmentRoutingHeader::default()
            })
            .push(Udp::default());

        Builder::new(tunnel_registry())
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
    }

    #[test]
    fn build_context_materializes_only_the_outer_network_envelope() {
        let source = Ipv4Addr::new(192, 0, 2, 1);
        let destination = Ipv4Addr::new(192, 0, 2, 2);
        let mut packet = Packet::new();
        packet
            .push(Ipv4::default())
            .push(Ipv4::default())
            .push(Udp::default());

        let built = Builder::new(Arc::new(crate::protocol::builtin::registry().unwrap()))
            .build(
                packet,
                BuildContext {
                    source: Some(source.into()),
                    destination: Some(destination.into()),
                    ..BuildContext::default()
                },
                BuildOptions::default(),
            )
            .unwrap();

        assert_eq!(&built.bytes[12..16], &source.octets());
        assert_eq!(&built.bytes[16..20], &destination.octets());
        assert_eq!(&built.bytes[32..40], &[0; 8]);
        assert_eq!(
            super::super::super::common::transport_checksum(
                network_from_addresses(Ipv4Addr::UNSPECIFIED.into(), Ipv4Addr::UNSPECIFIED.into(),),
                17,
                &built.bytes[40..],
            )
            .unwrap(),
            0
        );
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RawIpCodec;

impl LayerCodec for RawIpCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("raw_ip")
    }
    fn accepts_decoded_protocol(&self, protocol: &ProtocolId) -> bool {
        matches!(protocol.as_str(), "ipv4" | "ipv6")
    }
    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        _layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        Err(CodecError::Unsupported {
            protocol: protocol("raw_ip"),
            message: "raw_ip is a decode-only link root; build IPv4 or IPv6 directly".to_string(),
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        let Some(version) = input.first().map(|byte| byte >> 4) else {
            return Err(truncated("raw_ip", 1, 0));
        };
        match version {
            4 => Ipv4Codec.decode(input, context),
            6 => Ipv6Codec.decode(input, context),
            _ => Err(invalid(
                "raw_ip",
                format!("unknown IP version nibble {version}"),
            )),
        }
    }

    fn make_layer(
        &self,
        _fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        Err(CodecError::Unsupported {
            protocol: protocol("raw_ip"),
            message: "raw_ip has no constructible layer".to_string(),
        })
    }
}
