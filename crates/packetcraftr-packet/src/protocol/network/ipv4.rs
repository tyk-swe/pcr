// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IPv4 header model and codec.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use bytes::Bytes;

use crate::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
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
    validate_raw_child_discriminator, wrong_layer, wrong_type,
};

use super::encode::is_outer_network_layer;

const IPV4_MIN_LEN: usize = 20;

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
    }
    layout pub(crate) fn ipv4_layout(header_len: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Ipv4Codec;

impl LayerCodec for Ipv4Codec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv4")
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
        let inherit_source = inherit_context && layer.source.is_unspecified();
        let inherit_destination = inherit_context && layer.destination.is_unspecified();
        let source = match context.build_context.source {
            Some(IpAddr::V4(source)) if inherit_source => source,
            _ => layer.source,
        };
        let destination = match context.build_context.destination {
            Some(IpAddr::V4(destination)) if inherit_destination => destination,
            _ => layer.destination,
        };

        let mut diagnostics = Vec::new();
        if layer.reserved_flag {
            let message = "reserved IPv4 flag bit is set";
            if context.mode == crate::build::BuildMode::Strict {
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
        let total_length_field = u16::from_be_bytes([input[2], input[3]]);
        let total_length = usize::from(total_length_field);
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
                total_length: WireValue::Exact(total_length_field),
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
