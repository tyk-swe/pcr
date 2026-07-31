// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};

use bytes::Bytes;

use packetcraftr_packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext, NetworkEnvelope,
    },
    field::{FieldValue, WireValue},
    layer::{Layer, ProtocolId, reflect_get, reflect_set, reflective_layer},
    registry::Discriminator,
};

use super::super::common::{
    ValueExpectation, aliased_fields, expected_discriminator, invalid, make_layer, out_of_range,
    payload_without_padding, protocol, resolve_u8, strict_or_diagnostic, truncated,
    validate_auto_raw_discriminator, validate_ipv6_routing_child, validate_raw_child_discriminator,
    wrong_layer, wrong_type,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopByHop {
    pub next_header: WireValue<u8>,
    pub options: Bytes,
}

impl Default for HopByHop {
    fn default() -> Self {
        Self {
            next_header: WireValue::Auto,
            options: Bytes::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationOptions {
    pub next_header: WireValue<u8>,
    pub options: Bytes,
}

impl Default for DestinationOptions {
    fn default() -> Self {
        Self {
            next_header: WireValue::Auto,
            options: Bytes::new(),
        }
    }
}

macro_rules! declare_options_layer {
    ($ty:ty, $schema:ident, $protocol:literal, $name:literal, $layout:ident) => {
        reflective_layer! {
            fn $schema() => { protocol: protocol($protocol), name: $name }
            impl $ty {
                "next_header" => { kind: Unsigned, derived: true, required: false, description: "IPv6 next-header discriminator", get |layer| Some(reflect_get(&layer.next_header)), set |layer, value, name| reflect_set(&mut layer.next_header, $schema(), name, value), layout: (0, 1) },
                "options" => { kind: Bytes, derived: false, required: false, description: "Option bytes, padded to an eight-byte header boundary", get |layer| Some(reflect_get(&layer.options)), set |layer, value, name| reflect_set(&mut layer.options, $schema(), name, value), layout: (2, header_len) },
            }
            layout pub(crate) fn $layout(header_len: usize);
        }
    };
}

declare_options_layer!(
    HopByHop,
    hop_schema,
    "ipv6_hop_by_hop",
    "IPv6 Hop-by-Hop Options",
    hop_layout
);
declare_options_layer!(
    DestinationOptions,
    destination_schema,
    "ipv6_destination_options",
    "IPv6 Destination Options",
    destination_layout
);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HopByHopCodec;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DestinationOptionsCodec;

fn encode_options<L>(
    name: &str,
    layer: &L,
    next_header: &WireValue<u8>,
    options: &Bytes,
    layout: fn(usize) -> Vec<packetcraftr_packet::layout::FieldLayout>,
    context: &LayerEncodeContext<'_>,
) -> Result<EncodedLayer, CodecError>
where
    L: Layer + Clone + 'static,
{
    let expectation = expected_discriminator(name, context, 59_u8);
    let mut diagnostics = Vec::new();
    validate_auto_raw_discriminator(name, "next_header", next_header, context, &mut diagnostics)?;
    let (next, _) = resolve_u8(
        name,
        "next_header",
        next_header,
        expectation,
        context.mode,
        &mut diagnostics,
    )?;
    validate_raw_child_discriminator(name, u64::from(next), context, &mut diagnostics)?;
    validate_ipv6_routing_child(name, next, context, &mut diagnostics)?;
    let unpadded = options
        .len()
        .checked_add(2)
        .ok_or_else(|| invalid(name, "option length overflow"))?;
    let header_len = unpadded
        .checked_add((8 - unpadded % 8) % 8)
        .ok_or_else(|| invalid(name, "option padding overflow"))?;
    if header_len > 2_048 {
        return Err(invalid(
            name,
            "options header exceeds 2048-byte secure default",
        ));
    }
    let hdr_ext_len = u8::try_from(header_len / 8 - 1)
        .map_err(|_| invalid(name, "options header length cannot be represented"))?;
    let mut prefix = vec![0u8; header_len];
    prefix[0] = next;
    prefix[1] = hdr_ext_len;
    prefix[2..2 + options.len()].copy_from_slice(options);
    let mut materialized = layer.clone_box();
    materialized.set_field("next_header", FieldValue::Unsigned(u64::from(next)))?;
    materialized.set_field(
        "options",
        FieldValue::Bytes(Bytes::copy_from_slice(&prefix[2..header_len])),
    )?;
    Ok(EncodedLayer {
        prefix,
        suffix: Vec::new(),
        materialized,
        fields: layout(header_len),
        diagnostics,
    })
}

fn decode_options<L>(
    name: &str,
    input: &[u8],
    make: impl FnOnce(u8, Bytes) -> L,
    layout: fn(usize) -> Vec<packetcraftr_packet::layout::FieldLayout>,
) -> Result<DecodedLayerValue, CodecError>
where
    L: Layer + 'static,
{
    if input.len() < 8 {
        return Err(truncated(name, 8, input.len()));
    }
    let header_len = (usize::from(input[1]) + 1)
        .checked_mul(8)
        .ok_or_else(|| invalid(name, "header length overflow"))?;
    if input.len() < header_len {
        return Err(truncated(name, header_len, input.len()));
    }
    Ok(DecodedLayerValue {
        layer: Box::new(make(
            input[0],
            Bytes::copy_from_slice(&input[2..header_len]),
        )),
        consumed: header_len,
        payload_offset: header_len,
        payload_len: input.len() - header_len,
        next: vec![Discriminator(u64::from(input[0]))],
        fields: layout(header_len),
        diagnostics: Vec::new(),
        stop: input.len() == header_len,
        network: None,
    })
}

impl LayerCodec for HopByHopCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv6_hop_by_hop")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<HopByHop>()
            .ok_or_else(|| wrong_layer("ipv6_hop_by_hop", layer))?;
        encode_options(
            "ipv6_hop_by_hop",
            layer,
            &layer.next_header,
            &layer.options,
            hop_layout,
            context,
        )
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        decode_options(
            "ipv6_hop_by_hop",
            input,
            |next, options| HopByHop {
                next_header: WireValue::Exact(next),
                options,
            },
            hop_layout,
        )
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(HopByHop::default(), fields)
    }
}

impl LayerCodec for DestinationOptionsCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv6_destination_options")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<DestinationOptions>()
            .ok_or_else(|| wrong_layer("ipv6_destination_options", layer))?;
        encode_options(
            "ipv6_destination_options",
            layer,
            &layer.next_header,
            &layer.options,
            destination_layout,
            context,
        )
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        decode_options(
            "ipv6_destination_options",
            input,
            |next, options| DestinationOptions {
                next_header: WireValue::Exact(next),
                options,
            },
            destination_layout,
        )
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(DestinationOptions::default(), fields)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Fragment {
    pub next_header: WireValue<u8>,
    /// Offset in eight-byte units, as encoded on the wire.
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub identification: u32,
}

impl Default for Ipv6Fragment {
    fn default() -> Self {
        Self {
            next_header: WireValue::Auto,
            fragment_offset: 0,
            more_fragments: false,
            identification: 0,
        }
    }
}

reflective_layer! {
    fn fragment_schema() => { protocol: protocol("ipv6_fragment"), name: "IPv6 Fragment" }
    impl Ipv6Fragment {
        "next_header" => { kind: Unsigned, derived: true, required: false, description: "IPv6 next-header discriminator", get |layer| Some(reflect_get(&layer.next_header)), set |layer, value, name| reflect_set(&mut layer.next_header, fragment_schema(), name, value), layout: (0, 1) },
        "fragment_offset" => { kind: Unsigned, derived: false, required: true, description: "Fragment offset in eight-byte units", get |layer| Some(reflect_get(&layer.fragment_offset)), set |layer, value, name| match value { FieldValue::Unsigned(value) => { layer.fragment_offset = u16::try_from(value).ok().filter(|value| *value <= 0x1fff).ok_or_else(|| out_of_range(fragment_schema(), name))?; Ok(()) }, _ => Err(wrong_type(fragment_schema(), name, "unsigned")) }, layout: (2, 4) },
        "more_fragments" => { kind: Bool, derived: false, required: true, description: "More-fragments flag", get |layer| Some(reflect_get(&layer.more_fragments)), set |layer, value, name| reflect_set(&mut layer.more_fragments, fragment_schema(), name, value), layout: (2, 4) },
        "identification" => { kind: Unsigned, derived: false, required: true, description: "Fragment identification", get |layer| Some(reflect_get(&layer.identification)), set |layer, value, name| reflect_set(&mut layer.identification, fragment_schema(), name, value), layout: (4, 8) },
    }
    layout pub(crate) fn fragment_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Ipv6FragmentCodec;

impl LayerCodec for Ipv6FragmentCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv6_fragment")
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
            .downcast_ref::<Ipv6Fragment>()
            .ok_or_else(|| wrong_layer("ipv6_fragment", layer))?;
        if layer.fragment_offset > 0x1fff {
            return Err(invalid("ipv6_fragment", "fragment offset exceeds 13 bits"));
        }
        let expectation = expected_discriminator("ipv6_fragment", context, 59_u8);
        let mut diagnostics = Vec::new();
        validate_auto_raw_discriminator(
            "ipv6_fragment",
            "next_header",
            &layer.next_header,
            context,
            &mut diagnostics,
        )?;
        let covered_payload = payload_without_padding("ipv6_fragment", payload, context)?;
        if layer.more_fragments && covered_payload.len() % 8 != 0 {
            strict_or_diagnostic(
                "ipv6_fragment",
                "build.ipv6_fragment_alignment",
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
                "ipv6_fragment",
                "build.typed_fragment_payload",
                "fragment_offset",
                "fragment payload must be Raw; convert typed fragment payloads to Raw explicitly",
                context,
                &mut diagnostics,
            )?;
        }
        let (next, materialized_next) = resolve_u8(
            "ipv6_fragment",
            "next_header",
            &layer.next_header,
            expectation,
            context.mode,
            &mut diagnostics,
        )?;
        if layer.fragment_offset == 0 && !layer.more_fragments {
            validate_raw_child_discriminator(
                "ipv6_fragment",
                u64::from(next),
                context,
                &mut diagnostics,
            )?;
        }
        validate_ipv6_routing_child("ipv6_fragment", next, context, &mut diagnostics)?;
        let offset_flags = (layer.fragment_offset << 3) | u16::from(layer.more_fragments);
        let mut prefix = Vec::with_capacity(8);
        prefix.extend_from_slice(&[next, 0]);
        prefix.extend_from_slice(&offset_flags.to_be_bytes());
        prefix.extend_from_slice(&layer.identification.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.next_header = materialized_next;
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: fragment_layout(),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 8 {
            return Err(truncated("ipv6_fragment", 8, input.len()));
        }
        let offset_flags = u16::from_be_bytes([input[2], input[3]]);
        if input[1] != 0 || offset_flags & 0x0006 != 0 {
            return Err(invalid("ipv6_fragment", "reserved bits are non-zero"));
        }
        let fragment_offset = offset_flags >> 3;
        Ok(DecodedLayerValue {
            layer: Box::new(Ipv6Fragment {
                next_header: WireValue::Exact(input[0]),
                fragment_offset,
                more_fragments: offset_flags & 1 != 0,
                identification: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
            }),
            consumed: 8,
            payload_offset: 8,
            payload_len: input.len() - 8,
            next: if fragment_offset == 0 && offset_flags & 1 == 0 {
                vec![Discriminator(u64::from(input[0]))]
            } else {
                // A non-initial fragment cannot be decoded as a transport
                // header; preserve its bytes explicitly as Raw.
                vec![Discriminator(255)]
            },
            fields: fragment_layout(),
            diagnostics: Vec::new(),
            stop: input.len() == 8,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(Ipv6Fragment::default(), fields)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentRoutingHeader {
    pub next_header: WireValue<u8>,
    pub segments_left: WireValue<u8>,
    pub last_entry: WireValue<u8>,
    pub flags: u8,
    pub tag: u16,
    /// Visit order (first visited segment through final destination).
    pub segments: Vec<Ipv6Addr>,
    /// Type-length-value bytes following the segment list, including padding.
    pub tlvs: Bytes,
}

impl Default for SegmentRoutingHeader {
    fn default() -> Self {
        Self {
            next_header: WireValue::Auto,
            segments_left: WireValue::Auto,
            last_entry: WireValue::Auto,
            flags: 0,
            tag: 0,
            segments: Vec::new(),
            tlvs: Bytes::new(),
        }
    }
}

reflective_layer! {
    fn srh_schema() => { protocol: protocol("ipv6_srh"), name: "IPv6 Segment Routing Header" }
    impl SegmentRoutingHeader {
        "next_header" => { kind: Unsigned, derived: true, required: false, description: "IPv6 next-header discriminator", get |layer| Some(reflect_get(&layer.next_header)), set |layer, value, name| reflect_set(&mut layer.next_header, srh_schema(), name, value), layout: (0, 1) },
        "segments_left" => { kind: Unsigned, derived: true, required: false, description: "Remaining segments", get |layer| Some(reflect_get(&layer.segments_left)), set |layer, value, name| reflect_set(&mut layer.segments_left, srh_schema(), name, value), layout: (3, 4) },
        "last_entry" => { kind: Unsigned, derived: true, required: false, description: "Highest segment-list index", get |layer| Some(reflect_get(&layer.last_entry)), set |layer, value, name| reflect_set(&mut layer.last_entry, srh_schema(), name, value), layout: (4, 5) },
        "flags" => { kind: Unsigned, derived: false, required: false, description: "SRH flags", get |layer| Some(reflect_get(&layer.flags)), set |layer, value, name| reflect_set(&mut layer.flags, srh_schema(), name, value), layout: (5, 6) },
        "tag" => { kind: Unsigned, derived: false, required: false, description: "SRH tag", get |layer| Some(reflect_get(&layer.tag)), set |layer, value, name| reflect_set(&mut layer.tag, srh_schema(), name, value), layout: (6, 8) },
        "segments" => { kind: List, derived: false, required: true, description: "Segments in visit order", get |layer| Some(FieldValue::List(layer.segments.iter().copied().map(FieldValue::Ipv6).collect())), set |layer, value, name| match value { FieldValue::List(values) => { layer.segments = values.into_iter().map(|value| match value { FieldValue::Ipv6(value) => Ok(value), FieldValue::Text(value) => value.parse().map_err(|_| wrong_type(srh_schema(), name, "list of IPv6 addresses")), _ => Err(wrong_type(srh_schema(), name, "list of IPv6 addresses")) }).collect::<Result<Vec<_>, _>>()?; Ok(()) }, _ => Err(wrong_type(srh_schema(), name, "list")) }, layout: (8, segments_end) },
        "tlvs" => { kind: Bytes, derived: false, required: false, description: "TLV bytes following the segment list, including padding", get |layer| Some(reflect_get(&layer.tlvs)), set |layer, value, name| reflect_set(&mut layer.tlvs, srh_schema(), name, value), layout: (segments_end, header_len) },
    }
    layout pub(crate) fn srh_layout(segments_end: usize, header_len: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SegmentRoutingHeaderCodec;

impl LayerCodec for SegmentRoutingHeaderCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("ipv6_srh")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<SegmentRoutingHeader>()
            .ok_or_else(|| wrong_layer("ipv6_srh", layer))?;
        if layer.segments.is_empty() || layer.segments.len() > 127 {
            return Err(invalid("ipv6_srh", "SRH requires 1..=127 segments"));
        }
        if layer.flags != 0 {
            return Err(invalid("ipv6_srh", "unsupported SRH flags must be zero"));
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the guard above rejects an empty segment list and any list longer than \
                      127, so the decremented length is at most 126"
        )]
        let expected_last = (layer.segments.len() - 1) as u8;
        let mut diagnostics = Vec::new();
        let expectation = expected_discriminator("ipv6_srh", context, 59_u8);
        validate_auto_raw_discriminator(
            "ipv6_srh",
            "next_header",
            &layer.next_header,
            context,
            &mut diagnostics,
        )?;
        let (next, materialized_next) = resolve_u8(
            "ipv6_srh",
            "next_header",
            &layer.next_header,
            expectation,
            context.mode,
            &mut diagnostics,
        )?;
        validate_raw_child_discriminator("ipv6_srh", u64::from(next), context, &mut diagnostics)?;
        validate_ipv6_routing_child("ipv6_srh", next, context, &mut diagnostics)?;
        let (segments_left, materialized_left) = resolve_u8(
            "ipv6_srh",
            "segments_left",
            &layer.segments_left,
            ValueExpectation::Suggested(expected_last),
            context.mode,
            &mut diagnostics,
        )?;
        if segments_left > expected_last {
            let message =
                format!("segments_left is {segments_left}, exceeding last_entry {expected_last}");
            if context.mode == packetcraftr_packet::build::BuildMode::Strict {
                return Err(invalid("ipv6_srh", message));
            }
            diagnostics.push(
                packetcraftr_packet::diagnostic::Diagnostic::warning(
                    "build.srh_segments_left",
                    message,
                )
                .at_field("segments_left"),
            );
        }
        let (last_entry, materialized_last) = resolve_u8(
            "ipv6_srh",
            "last_entry",
            &layer.last_entry,
            ValueExpectation::Required(expected_last),
            context.mode,
            &mut diagnostics,
        )?;
        let segments_end = layer
            .segments
            .len()
            .checked_mul(16)
            .and_then(|length| length.checked_add(8))
            .ok_or_else(|| invalid("ipv6_srh", "SRH segment-list length overflow"))?;
        let unpadded_len = segments_end
            .checked_add(layer.tlvs.len())
            .ok_or_else(|| invalid("ipv6_srh", "SRH TLV length overflow"))?;
        let header_len = unpadded_len
            .checked_add((8 - unpadded_len % 8) % 8)
            .ok_or_else(|| invalid("ipv6_srh", "SRH padding overflow"))?;
        let hdr_ext_len = u8::try_from(header_len / 8 - 1)
            .map_err(|_| invalid("ipv6_srh", "SRH length cannot be represented"))?;
        let mut prefix = Vec::with_capacity(header_len);
        prefix.extend_from_slice(&[next, hdr_ext_len, 4, segments_left, last_entry, 0]);
        prefix.extend_from_slice(&layer.tag.to_be_bytes());
        for segment in layer.segments.iter().rev() {
            prefix.extend_from_slice(&segment.octets());
        }
        prefix.extend_from_slice(&layer.tlvs);
        prefix.resize(header_len, 0);
        let mut materialized = layer.clone();
        materialized.next_header = materialized_next;
        materialized.segments_left = materialized_left;
        materialized.last_entry = materialized_last;
        materialized.tlvs = Bytes::copy_from_slice(&prefix[segments_end..]);
        Ok(EncodedLayer {
            prefix,
            suffix: Vec::new(),
            materialized: Box::new(materialized),
            fields: srh_layout(segments_end, header_len),
            diagnostics,
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.len() < 8 {
            return Err(truncated("ipv6_srh", 8, input.len()));
        }
        if input[2] == 0 {
            return Err(CodecError::Unsupported {
                protocol: protocol("ipv6_srh"),
                message: "IPv6 routing type 0 is prohibited".to_owned(),
            });
        }
        if input[2] != 4 {
            return Err(CodecError::Unsupported {
                protocol: protocol("ipv6_srh"),
                message: format!("unsupported routing type {}", input[2]),
            });
        }
        let header_len = (usize::from(input[1]) + 1)
            .checked_mul(8)
            .ok_or_else(|| invalid("ipv6_srh", "header length overflow"))?;
        if input.len() < header_len {
            return Err(truncated("ipv6_srh", header_len, input.len()));
        }
        let count = usize::from(input[4]) + 1;
        let segments_end = count
            .checked_mul(16)
            .and_then(|length| length.checked_add(8))
            .ok_or_else(|| invalid("ipv6_srh", "segment-list length overflow"))?;
        if header_len < segments_end || input[3] > input[4] {
            return Err(invalid(
                "ipv6_srh",
                "Last Entry or Segments Left is inconsistent",
            ));
        }
        if input[5] != 0 {
            return Err(invalid("ipv6_srh", "unsupported flags are non-zero"));
        }
        let mut wire_segments = Vec::with_capacity(count);
        for chunk in input[8..segments_end].chunks_exact(16) {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(chunk);
            wire_segments.push(Ipv6Addr::from(bytes));
        }
        wire_segments.reverse();
        let final_destination = wire_segments
            .last()
            .copied()
            .ok_or_else(|| invalid("ipv6_srh", "segment list is empty"))?;
        let network = context.network.map(|network| NetworkEnvelope {
            source: network.source,
            destination: IpAddr::V6(final_destination),
        });
        Ok(DecodedLayerValue {
            layer: Box::new(SegmentRoutingHeader {
                next_header: WireValue::Exact(input[0]),
                segments_left: WireValue::Exact(input[3]),
                last_entry: WireValue::Exact(input[4]),
                flags: input[5],
                tag: u16::from_be_bytes([input[6], input[7]]),
                segments: wire_segments,
                tlvs: Bytes::copy_from_slice(&input[segments_end..header_len]),
            }),
            consumed: header_len,
            payload_offset: header_len,
            payload_len: input.len() - header_len,
            next: vec![Discriminator(u64::from(input[0]))],
            fields: srh_layout(segments_end, header_len),
            diagnostics: Vec::new(),
            stop: input.len() == header_len,
            network,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        make_layer(
            SegmentRoutingHeader::default(),
            &aliased_fields("ipv6_srh", fields, &[("segs", "segments")])?,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{builtin::registry as default_registry, network::Ipv6, transport::Udp};
    use packetcraftr_packet::{
        Packet,
        build::{BuildContext, BuildMode, BuildOptions, Builder},
        codec::{CodecError, LayerCodec, LayerDecodeContext, NetworkEnvelope},
        decode::{DecodeOptions, Dissector},
        field::WireValue,
        layer::Raw,
    };

    fn decode_context(
        registry: &packetcraftr_packet::registry::ProtocolRegistry,
    ) -> LayerDecodeContext<'_> {
        LayerDecodeContext {
            registry,
            layer_index: 1,
            absolute_offset: 40,
            verify_checksums: true,
            allow_trailing_padding: false,
            network: None,
            discriminator: None,
        }
    }

    fn ipv6_packet() -> Packet {
        let mut packet = Packet::new();
        packet.push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        });
        packet
    }

    #[test]
    fn srh_encodes_rfc8754_segment_list_and_round_trips() {
        let first: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let final_destination: Ipv6Addr = "2001:db8::20".parse().unwrap();
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(Arc::clone(&registry));
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                source: "2001:db8::1".parse().unwrap(),
                destination: first,
                ..Ipv6::default()
            })
            .push(SegmentRoutingHeader {
                tag: 0x1234,
                segments: vec![first, final_destination],
                ..SegmentRoutingHeader::default()
            })
            .push(Udp {
                source_port: 12345,
                destination_port: 9,
                ..Udp::default()
            });

        let built = builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        assert_eq!(built.bytes[6], 43);
        assert_eq!(&built.bytes[24..40], &first.octets());
        assert_eq!(built.bytes[42], 4);
        assert_eq!(built.bytes[43], 1);
        assert_eq!(built.bytes[44], 1);
        assert_eq!(&built.bytes[48..64], &final_destination.octets());
        assert_eq!(&built.bytes[64..80], &first.octets());

        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(
                built.bytes.clone(),
                protocol("ipv6"),
                DecodeOptions::default(),
            )
            .unwrap();
        assert_eq!(
            decoded
                .packet
                .get::<SegmentRoutingHeader>()
                .unwrap()
                .segments,
            vec![first, final_destination]
        );
        let rebuilt = builder
            .build(
                decoded.packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap();
        assert_eq!(rebuilt.bytes, built.bytes);
    }

    #[test]
    fn srh_preserves_tlvs_after_the_segment_list() {
        let segment: Ipv6Addr = "2001:db8::20".parse().unwrap();
        let tlvs = [5, 2, 0xaa, 0xbb, 1, 2, 0, 0];
        let mut bytes = vec![0_u8; 40 + 32];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&32_u16.to_be_bytes());
        bytes[6] = 43;
        bytes[7] = 64;
        bytes[24..40].copy_from_slice(&segment.octets());
        bytes[40] = 59;
        bytes[41] = 3;
        bytes[42] = 4;
        bytes[48..64].copy_from_slice(&segment.octets());
        bytes[64..72].copy_from_slice(&tlvs);

        let registry = Arc::new(default_registry().unwrap());
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(bytes.clone(), protocol("ipv6"), DecodeOptions::default())
            .unwrap();
        let srh = decoded.packet.get::<SegmentRoutingHeader>().unwrap();
        assert_eq!(srh.segments, [segment]);
        assert_eq!(srh.tlvs.as_ref(), tlvs);

        let rebuilt = Builder::new(registry)
            .build(
                decoded.packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap();
        assert_eq!(rebuilt.bytes.as_ref(), bytes);
    }

    #[test]
    fn routing_type_zero_is_preserved_as_malformed_not_misdecoded() {
        let registry = Arc::new(default_registry().unwrap());
        let mut bytes = vec![0u8; 40 + 24];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&24u16.to_be_bytes());
        bytes[6] = 43;
        bytes[7] = 64;
        bytes[40] = 59;
        bytes[41] = 2;
        bytes[42] = 0;
        bytes[43] = 0;

        let expected = Bytes::from(bytes.clone());
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(bytes, protocol("ipv6"), DecodeOptions::default())
            .unwrap();
        assert!(
            decoded
                .packet
                .get::<packetcraftr_packet::layer::MalformedLayer>()
                .is_some()
        );
        assert!(
            decoded
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "decode.malformed_layer")
        );

        let document = packetcraftr_packet::document::PacketDocument::from_packet(&decoded.packet);
        let reloaded = document.to_packet(&registry, 64).unwrap();
        let rebuilt = Builder::new(registry)
            .build(reloaded, BuildContext::default(), BuildOptions::default())
            .unwrap();
        assert_eq!(rebuilt.bytes, expected);
        assert!(rebuilt.requires_live_opt_in);
    }

    #[test]
    fn option_header_materializes_emitted_alignment_padding() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                source: "2001:db8::1".parse().unwrap(),
                destination: "2001:db8::2".parse().unwrap(),
                ..Ipv6::default()
            })
            .push(HopByHop {
                options: Bytes::from_static(&[0]),
                ..HopByHop::default()
            })
            .push(Udp::default());
        let built = Builder::new(Arc::clone(&registry))
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        assert_eq!(built.packet.get::<HopByHop>().unwrap().options.len(), 6);
        let decoded = Dissector::new(registry)
            .decode_with_root(built.bytes, protocol("ipv6"), DecodeOptions::default())
            .unwrap();
        assert_eq!(decoded.packet.get::<HopByHop>().unwrap().options.len(), 6);
    }

    #[test]
    fn destination_options_materialize_padding_and_round_trip() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = ipv6_packet();
        packet
            .push(DestinationOptions {
                options: Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7]),
                ..DestinationOptions::default()
            })
            .push(Udp::default());
        let built = Builder::new(Arc::clone(&registry))
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        assert_eq!(
            built
                .packet
                .get::<DestinationOptions>()
                .unwrap()
                .options
                .len(),
            14
        );
        let decoded = Dissector::new(registry)
            .decode_with_root(built.bytes, protocol("ipv6"), DecodeOptions::default())
            .unwrap();
        assert_eq!(
            decoded
                .packet
                .get::<DestinationOptions>()
                .unwrap()
                .options
                .len(),
            14
        );
    }

    #[test]
    fn option_decoders_reject_short_and_declared_truncated_headers() {
        let registry = default_registry().unwrap();
        let context = decode_context(&registry);
        for codec in [
            &HopByHopCodec as &dyn LayerCodec,
            &DestinationOptionsCodec as &dyn LayerCodec,
        ] {
            assert!(matches!(
                codec.decode(&[0; 7], &context),
                Err(CodecError::Truncated { needed: 8, .. })
            ));
            let mut input = [0_u8; 8];
            input[1] = 1;
            assert!(matches!(
                codec.decode(&input, &context),
                Err(CodecError::Truncated { needed: 16, .. })
            ));
        }
    }

    #[test]
    fn option_headers_reject_the_secure_default_boundary() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = ipv6_packet();
        packet
            .push(HopByHop {
                options: Bytes::from(vec![0; 2_047]),
                ..HopByHop::default()
            })
            .push(Udp::default());
        assert!(
            Builder::new(registry)
                .build(packet, BuildContext::default(), BuildOptions::default())
                .is_err()
        );
    }

    #[test]
    fn atomic_fragment_round_trips_to_its_typed_child() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = ipv6_packet();
        packet
            .push(Ipv6Fragment {
                identification: 0x1234_5678,
                ..Ipv6Fragment::default()
            })
            .push(Udp::default());
        let built = Builder::new(Arc::clone(&registry))
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let decoded = Dissector::new(registry)
            .decode_with_root(built.bytes, protocol("ipv6"), DecodeOptions::default())
            .unwrap();
        assert_eq!(
            decoded.packet.get::<Ipv6Fragment>().unwrap().identification,
            0x1234_5678
        );
        assert!(decoded.packet.get::<Udp>().is_some());
    }

    #[test]
    fn nonfinal_fragment_round_trips_as_raw_payload() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = ipv6_packet();
        packet
            .push(Ipv6Fragment {
                next_header: WireValue::Exact(17),
                more_fragments: true,
                identification: 7,
                ..Ipv6Fragment::default()
            })
            .push(Raw::new(Bytes::from_static(&[0; 8])));
        let built = Builder::new(Arc::clone(&registry))
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let decoded = Dissector::new(registry)
            .decode_with_root(built.bytes, protocol("ipv6"), DecodeOptions::default())
            .unwrap();
        assert_eq!(
            decoded.packet.get::<Raw>().unwrap().bytes,
            Bytes::from_static(&[0; 8])
        );
        assert!(decoded.packet.get::<Udp>().is_none());
    }

    #[test]
    fn fragment_encoding_rejects_offset_alignment_and_typed_payload_violations() {
        let registry = Arc::new(default_registry().unwrap());

        let mut excessive_offset = ipv6_packet();
        excessive_offset
            .push(Ipv6Fragment {
                fragment_offset: 0x2000,
                ..Ipv6Fragment::default()
            })
            .push(Raw::new(Bytes::new()));
        assert!(
            Builder::new(Arc::clone(&registry))
                .build(
                    excessive_offset,
                    BuildContext::default(),
                    BuildOptions::default()
                )
                .is_err()
        );

        let mut unaligned = ipv6_packet();
        unaligned
            .push(Ipv6Fragment {
                next_header: WireValue::Exact(17),
                more_fragments: true,
                ..Ipv6Fragment::default()
            })
            .push(Raw::new(Bytes::from_static(&[0; 7])));
        assert!(
            Builder::new(Arc::clone(&registry))
                .build(unaligned, BuildContext::default(), BuildOptions::default())
                .is_err()
        );

        let mut typed = ipv6_packet();
        typed
            .push(Ipv6Fragment {
                more_fragments: true,
                ..Ipv6Fragment::default()
            })
            .push(Udp::default());
        assert!(
            Builder::new(registry)
                .build(typed, BuildContext::default(), BuildOptions::default())
                .is_err()
        );
    }

    #[test]
    fn permissive_fragment_build_reports_alignment_and_typed_payload_diagnostics() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = ipv6_packet();
        packet
            .push(Ipv6Fragment {
                more_fragments: true,
                ..Ipv6Fragment::default()
            })
            .push(Udp::default())
            .push(Raw::new(Bytes::from_static(&[1])));
        let built = Builder::new(registry)
            .build(
                packet,
                BuildContext::default(),
                BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
            )
            .unwrap();
        assert!(
            built
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "build.ipv6_fragment_alignment")
        );
        assert!(
            built
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "build.typed_fragment_payload")
        );
        assert!(built.requires_live_opt_in);
    }

    #[test]
    fn fragment_decoder_rejects_reserved_bits_and_routes_noninitial_data_to_raw() {
        let registry = default_registry().unwrap();
        let context = decode_context(&registry);
        for input in [[17, 1, 0, 0, 0, 0, 0, 1], [17, 0, 0, 2, 0, 0, 0, 1]] {
            assert!(matches!(
                Ipv6FragmentCodec.decode(&input, &context),
                Err(CodecError::Invalid { .. })
            ));
        }

        let noninitial = [17, 0, 0, 8, 0, 0, 0, 1];
        let decoded = Ipv6FragmentCodec.decode(&noninitial, &context).unwrap();
        assert_eq!(decoded.next, vec![Discriminator(255)]);
        let atomic = [17, 0, 0, 0, 0, 0, 0, 1];
        let decoded = Ipv6FragmentCodec.decode(&atomic, &context).unwrap();
        assert_eq!(decoded.next, vec![Discriminator(17)]);
    }

    #[test]
    fn srh_encoding_rejects_invalid_segment_counts_and_flags() {
        let registry = Arc::new(default_registry().unwrap());
        for header in [
            SegmentRoutingHeader::default(),
            SegmentRoutingHeader {
                segments: vec![Ipv6Addr::LOCALHOST; 128],
                ..SegmentRoutingHeader::default()
            },
            SegmentRoutingHeader {
                flags: 1,
                segments: vec![Ipv6Addr::LOCALHOST],
                ..SegmentRoutingHeader::default()
            },
        ] {
            let mut packet = ipv6_packet();
            packet.push(header).push(Udp::default());
            assert!(
                Builder::new(Arc::clone(&registry))
                    .build(packet, BuildContext::default(), BuildOptions::default())
                    .is_err()
            );
        }
    }

    #[test]
    fn srh_segments_left_mismatch_is_strictly_rejected_and_permissively_diagnosed() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = ipv6_packet();
        packet
            .push(SegmentRoutingHeader {
                segments_left: WireValue::Exact(2),
                segments: vec![Ipv6Addr::LOCALHOST],
                ..SegmentRoutingHeader::default()
            })
            .push(Udp::default());
        assert!(
            Builder::new(Arc::clone(&registry))
                .build(
                    packet.clone(),
                    BuildContext::default(),
                    BuildOptions::default()
                )
                .is_err()
        );
        let built = Builder::new(registry)
            .build(
                packet,
                BuildContext::default(),
                BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
            )
            .unwrap();
        assert!(
            built
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "build.srh_segments_left")
        );
    }

    #[test]
    fn srh_decoder_rejects_truncation_routing_types_layout_flags_and_indices() {
        let registry = default_registry().unwrap();
        let context = decode_context(&registry);
        assert!(matches!(
            SegmentRoutingHeaderCodec.decode(&[0; 7], &context),
            Err(CodecError::Truncated { .. })
        ));

        for routing_type in [0, 3] {
            let mut input = [0_u8; 8];
            input[2] = routing_type;
            assert!(matches!(
                SegmentRoutingHeaderCodec.decode(&input, &context),
                Err(CodecError::Unsupported { .. })
            ));
        }

        let mut declared_truncated = [0_u8; 8];
        declared_truncated[1] = 2;
        declared_truncated[2] = 4;
        assert!(matches!(
            SegmentRoutingHeaderCodec.decode(&declared_truncated, &context),
            Err(CodecError::Truncated { .. })
        ));

        let mut invalid_layout = [0_u8; 16];
        invalid_layout[1] = 1;
        invalid_layout[2] = 4;
        assert!(matches!(
            SegmentRoutingHeaderCodec.decode(&invalid_layout, &context),
            Err(CodecError::Invalid { .. })
        ));

        for (segments_left, last_entry, flags) in [(1, 0, 0), (0, 1, 0), (0, 0, 1)] {
            let mut input = [0_u8; 24];
            input[1] = 2;
            input[2] = 4;
            input[3] = segments_left;
            input[4] = last_entry;
            input[5] = flags;
            assert!(matches!(
                SegmentRoutingHeaderCodec.decode(&input, &context),
                Err(CodecError::Invalid { .. })
            ));
        }
    }

    #[test]
    fn srh_decoder_updates_network_destination_to_the_final_segment() {
        let registry = default_registry().unwrap();
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let outer_destination: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let final_destination: Ipv6Addr = "2001:db8::20".parse().unwrap();
        let context = LayerDecodeContext {
            network: Some(NetworkEnvelope {
                source: IpAddr::V6(source),
                destination: IpAddr::V6(outer_destination),
            }),
            ..decode_context(&registry)
        };
        let mut input = [0_u8; 24];
        input[0] = 17;
        input[1] = 2;
        input[2] = 4;
        input[8..24].copy_from_slice(&final_destination.octets());
        let decoded = SegmentRoutingHeaderCodec.decode(&input, &context).unwrap();
        assert_eq!(
            decoded.network,
            Some(NetworkEnvelope {
                source: IpAddr::V6(source),
                destination: IpAddr::V6(final_destination),
            })
        );
        assert!(decoded.stop);
    }
}
