// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IPv4 header model and codec.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use bytes::Bytes;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::{Diagnostic, IPV4_CHECKSUM},
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
    packet::semantics::ipv4_source_route_destination,
    registry::Discriminator,
};

use crate::protocol::common::{
    ValueExpectation, checksum, child_is_opaque, expected_discriminator, invalid, make_layer,
    network_from_addresses, payload_without_padding, protocol, resolve_u8, resolve_u16,
    strict_or_diagnostic, truncated, typed_layer, validate_auto_raw_discriminator,
    validate_raw_child_discriminator,
};

use super::envelope::is_outer_network_layer;

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Ipv4.as_str();

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
    fn ipv4_schema() => { protocol: protocol(NAME), name: "IPv4" }
    impl Ipv4 {
        "dscp_ecn" => { kind: Unsigned, derived: false, required: false, description: "DSCP and ECN octet", reflect: dscp_ecn, layout: (1, 2) },
        "total_length" => { kind: Unsigned, derived: true, required: false, description: "IPv4 total length", reflect: total_length, layout: (2, 4) },
        "identification" => { kind: Unsigned, derived: false, required: false, description: "Fragment identification", reflect: identification, layout: (4, 6) },
        "reserved_flag" => { kind: Bool, derived: false, required: false, description: "Reserved IPv4 flag bit", reflect: reserved_flag, layout: (6, 8) },
        "dont_fragment" => { kind: Bool, derived: false, required: false, description: "Don't-fragment flag", reflect: dont_fragment, layout: (6, 8) },
        "more_fragments" => { kind: Bool, derived: false, required: false, description: "More-fragments flag", reflect: more_fragments, layout: (6, 8) },
        "fragment_offset" => { kind: Unsigned, derived: false, required: false, description: "Fragment offset in eight-byte units", reflect_bounded: fragment_offset, 0x1fff_u64, layout: (6, 8) },
        "ttl" => { kind: Unsigned, derived: false, required: true, description: "Time to live", reflect: ttl, layout: (8, 9) },
        "protocol" => { kind: Unsigned, derived: true, required: false, description: "Next protocol discriminator", reflect: protocol, layout: (9, 10) },
        "checksum" => { kind: Unsigned, derived: true, required: false, description: "IPv4 header checksum", reflect: checksum, layout: (10, 12) },
        "source" | "src" => { kind: Ipv4, derived: false, required: true, description: "Source IPv4 address", reflect: source, layout: (12, 16) },
        "destination" | "dst" => { kind: Ipv4, derived: false, required: true, description: "Destination IPv4 address", reflect: destination, layout: (16, 20) },
        "options" => { kind: Bytes, derived: false, required: false, description: "Verbatim IPv4 option bytes", reflect: options, layout: (20, header_len) },
    }
    layout pub(crate) fn ipv4_layout(header_len: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Ipv4Codec;

impl LayerCodec for Ipv4Codec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &ipv4_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Ipv4>(NAME, layer)?;
        let (source, destination) = resolve_addresses(layer, context);
        let (options, covered_payload_len, mut diagnostics) =
            prepare_payload(layer, payload, context)?;
        let header_len = IPV4_MIN_LEN.saturating_add(options.len());
        let total_expected = header_len
            .checked_add(covered_payload_len)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| invalid(NAME, "packet exceeds IPv4 total-length range"))?;
        let (total_length, materialized_total) = resolve_u16(
            NAME,
            "total_length",
            &layer.total_length,
            ValueExpectation::Required(total_expected),
            context.mode,
            &mut diagnostics,
        )?;
        let expected_protocol = expected_discriminator(NAME, context, 255_u8, &layer.protocol);
        validate_auto_raw_discriminator(
            NAME,
            "protocol",
            &layer.protocol,
            context,
            &mut diagnostics,
        )?;
        let (next_protocol, materialized_protocol) = resolve_u8(
            NAME,
            "protocol",
            &layer.protocol,
            expected_protocol,
            context.mode,
            &mut diagnostics,
        )?;
        if layer.fragment_offset == 0 && !layer.more_fragments {
            validate_raw_child_discriminator(
                NAME,
                u64::from(next_protocol),
                context,
                &mut diagnostics,
            )?;
        }

        let ihl =
            u8::try_from(header_len / 4).map_err(|_| invalid(NAME, "header length overflow"))?;
        let flags_offset = (if layer.reserved_flag { 1 << 15 } else { 0 })
            | (if layer.dont_fragment { 1 << 14 } else { 0 })
            | (if layer.more_fragments { 1 << 13 } else { 0 })
            | layer.fragment_offset;
        let mut prefix = Vec::with_capacity(header_len);
        prefix.push((4 << 4) | ihl);
        prefix.push(layer.dscp_ecn);
        prefix.extend_from_slice(&total_length.to_be_bytes());
        prefix.extend_from_slice(&layer.identification.to_be_bytes());
        prefix.extend_from_slice(&flags_offset.to_be_bytes());
        prefix.push(layer.ttl);
        prefix.push(next_protocol);
        // The checksum bytes stay zero while the header checksum is computed.
        prefix.extend_from_slice(&[0, 0]);
        prefix.extend_from_slice(&source.octets());
        prefix.extend_from_slice(&destination.octets());
        prefix.extend_from_slice(&options);
        let checksum_expected = checksum(&prefix);
        let (header_checksum, materialized_checksum) = resolve_u16(
            NAME,
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(checksum_expected),
            context.mode,
            &mut diagnostics,
        )?;
        #[expect(
            clippy::indexing_slicing,
            reason = "the fixed twenty-byte prefix above always reserves bytes 10..12 for the checksum"
        )]
        {
            prefix[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        }

        let mut materialized = layer.clone();
        materialized.total_length = materialized_total;
        materialized.protocol = materialized_protocol;
        materialized.checksum = materialized_checksum;
        materialized.source = source;
        materialized.destination = destination;
        materialized.options = Bytes::from(options);
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(ipv4_layout(header_len))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(header) = input.first_chunk::<IPV4_MIN_LEN>() else {
            return Err(truncated(NAME, IPV4_MIN_LEN, input.len()));
        };
        if header[0] >> 4 != 4 {
            return Err(invalid(
                NAME,
                format!("version is {}, not 4", header[0] >> 4),
            ));
        }
        let ihl = usize::from(header[0] & 0x0f);
        if ihl < 5 {
            return Err(invalid(NAME, format!("IHL {ihl} is below 5")));
        }
        let header_len = ihl
            .checked_mul(4)
            .ok_or_else(|| invalid(NAME, "IHL overflow"))?;
        let (Some(full_header), Some(options)) =
            (input.get(..header_len), input.get(IPV4_MIN_LEN..header_len))
        else {
            return Err(truncated(NAME, header_len, input.len()));
        };
        let total_length_field = u16::from_be_bytes([header[2], header[3]]);
        let total_length = usize::from(total_length_field);
        if total_length < header_len {
            return Err(invalid(
                NAME,
                format!("total length {total_length} is smaller than header {header_len}"),
            ));
        }
        if input.len() < total_length {
            return Err(truncated(NAME, total_length, input.len()));
        }
        let flags_offset = u16::from_be_bytes([header[6], header[7]]);
        let next = header[9];
        let source = Ipv4Addr::new(header[12], header[13], header[14], header[15]);
        let destination = Ipv4Addr::new(header[16], header[17], header[18], header[19]);
        let pseudo_header_destination = ipv4_source_route_destination(destination, options)
            .map_err(|error| invalid(NAME, error.to_string()))?;
        let mut diagnostics = Vec::new();
        if checksum(full_header) != 0 {
            diagnostics.push(
                Diagnostic::warning(IPV4_CHECKSUM, "IPv4 header checksum mismatch")
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
        let payload_len = total_length.saturating_sub(header_len);
        Ok(DecodedLayerValue {
            layer: Box::new(Ipv4 {
                dscp_ecn: header[1],
                total_length: WireValue::Exact(total_length_field),
                identification: u16::from_be_bytes([header[4], header[5]]),
                reserved_flag: (flags_offset & 0x8000) != 0,
                dont_fragment: (flags_offset & 0x4000) != 0,
                more_fragments: (flags_offset & 0x2000) != 0,
                fragment_offset,
                ttl: header[8],
                protocol: WireValue::Exact(next),
                checksum: WireValue::Exact(u16::from_be_bytes([header[10], header[11]])),
                source,
                destination,
                options: Bytes::copy_from_slice(options),
            }),
            consumed: header_len,
            payload_len,
            next: if fragment_offset == 0 && (flags_offset & 0x2000) == 0 {
                vec![Discriminator(u64::from(next))]
            } else {
                vec![Discriminator(255)]
            },
            fields: ipv4_layout(header_len),
            diagnostics,
            stop: payload_len == 0,
            network: Some(network_from_addresses(
                source.into(),
                pseudo_header_destination.into(),
            )),
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Ipv4::default(), fields)
    }
}

fn resolve_addresses(layer: &Ipv4, context: &LayerEncodeContext<'_>) -> (Ipv4Addr, Ipv4Addr) {
    let inherit = is_outer_network_layer(context.packet, context.index);
    let source = match context.build_context.source {
        Some(IpAddr::V4(source)) if inherit && layer.source.is_unspecified() => source,
        _ => layer.source,
    };
    let destination = match context.build_context.destination {
        Some(IpAddr::V4(destination)) if inherit && layer.destination.is_unspecified() => {
            destination
        }
        _ => layer.destination,
    };
    (source, destination)
}

fn prepare_payload(
    layer: &Ipv4,
    payload: &[u8],
    context: &LayerEncodeContext<'_>,
) -> Result<(Vec<u8>, usize, Vec<Diagnostic>), crate::codec::Error> {
    if layer.fragment_offset > 0x1fff {
        return Err(invalid(NAME, "fragment offset exceeds 13 bits"));
    }
    if layer.options.len() > 40 {
        return Err(invalid(NAME, "options exceed the 40-byte IPv4 limit"));
    }
    let mut diagnostics = Vec::new();
    if layer.reserved_flag {
        let message = "reserved IPv4 flag bit is set";
        if context.mode == crate::codec::Mode::Strict {
            return Err(invalid(NAME, message));
        }
        diagnostics.push(
            Diagnostic::warning("build.ipv4_reserved_flag", message).at_field("reserved_flag"),
        );
    }
    let mut options = layer.options.to_vec();
    let padding = 4_usize.saturating_sub(options.len() % 4) % 4;
    if padding != 0 {
        options.resize(options.len().saturating_add(padding), 0);
        diagnostics.push(
            Diagnostic::warning(
                "build.ipv4_options_padded",
                format!("padded IPv4 options with {padding} zero byte(s)"),
            )
            .at_field("options"),
        );
    }
    let covered_payload_len = payload_without_padding(NAME, payload, context)?.len();
    if layer.dont_fragment && (layer.more_fragments || layer.fragment_offset != 0) {
        strict_or_diagnostic(
            NAME,
            "build.ipv4_conflicting_fragment_flags",
            "dont_fragment",
            "don't-fragment cannot be combined with MF or a non-zero fragment offset",
            context,
            &mut diagnostics,
        )?;
    }
    if layer.more_fragments && covered_payload_len % 8 != 0 {
        strict_or_diagnostic(
            NAME,
            "build.ipv4_fragment_alignment",
            "more_fragments",
            format!(
                "non-final fragment payload length {covered_payload_len} is not a multiple of eight bytes"
            ),
            context,
            &mut diagnostics,
        )?;
    }
    let typed_fragment = (layer.fragment_offset != 0 || layer.more_fragments)
        && context.child.is_some_and(|child| !child_is_opaque(child));
    if typed_fragment {
        strict_or_diagnostic(
            NAME,
            "build.typed_fragment_payload",
            "fragment_offset",
            "fragment payload must be Raw; convert typed fragment payloads to Raw explicitly",
            context,
            &mut diagnostics,
        )?;
    }
    Ok((options, covered_payload_len, diagnostics))
}
