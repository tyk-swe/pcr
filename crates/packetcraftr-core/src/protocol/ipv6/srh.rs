// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};

use bytes::Bytes;

use crate::{
    codec::{
        DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
        NetworkEnvelope,
    },
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{
    ValueExpectation, aliased_fields, expected_discriminator, invalid, make_layer, protocol,
    resolve_u8, truncated, validate_auto_raw_discriminator, validate_ipv6_routing_child,
    validate_raw_child_discriminator, wrong_layer, wrong_type,
};

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
        "next_header" => { kind: Unsigned, tier: Derived, description: "IPv6 next-header discriminator", wire: next_header, layout: (0, 1) },
        "segments_left" => { kind: Unsigned, tier: Derived, description: "Remaining segments", wire: segments_left, layout: (3, 4) },
        "last_entry" => { kind: Unsigned, tier: Derived, description: "Highest segment-list index", wire: last_entry, layout: (4, 5) },
        "flags" => { kind: Unsigned, tier: Optional, default: "0", description: "SRH flags", reflect: flags, layout: (5, 6) },
        "tag" => { kind: Unsigned, tier: Optional, default: "0", description: "SRH tag", reflect: tag, layout: (6, 8) },
        "segments" | "segs" => { kind: List, element: Ipv6, tier: Required, description: "Segments in visit order", get |layer| Some(FieldValue::List(layer.segments.iter().copied().map(FieldValue::Ipv6).collect())), set |layer, value, name| match value { FieldValue::List(values) => { layer.segments = values.into_iter().map(|value| match value { FieldValue::Ipv6(value) => Ok(value), FieldValue::Text(value) => value.parse().map_err(|_| wrong_type(srh_schema(), name, "list of IPv6 addresses")), _ => Err(wrong_type(srh_schema(), name, "list of IPv6 addresses")) }).collect::<Result<Vec<_>, _>>()?; Ok(()) }, _ => Err(wrong_type(srh_schema(), name, "list")) }, layout: (8, segments_end) },
        "tlvs" => { kind: Bytes, tier: Optional, default: "0x", description: "TLV bytes following the segment list, including padding", reflect: tlvs, layout: (segments_end, header_len) },
    }
    layout pub(crate) fn srh_layout(segments_end: usize, header_len: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SegmentRoutingHeaderCodec;

impl LayerCodec for SegmentRoutingHeaderCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("ipv6_srh")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
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
        let expected_last = layer.segments.len().saturating_sub(1) as u8;
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
            if context.mode == crate::build::Mode::Strict {
                return Err(invalid("ipv6_srh", message));
            }
            diagnostics.push(
                crate::diagnostic::Diagnostic::warning("build.srh_segments_left", message)
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
        let (segments_end, header_len) = srh_lengths(layer)?;
        let hdr_ext_len = u8::try_from((header_len / 8).saturating_sub(1))
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
        #[expect(
            clippy::indexing_slicing,
            reason = "`prefix` was resized to `header_len`, which `srh_lengths` guarantees is at \
                      least `segments_end`"
        )]
        let tlvs = Bytes::copy_from_slice(&prefix[segments_end..]);
        materialized.tlvs = tlvs;
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
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(header) = input.first_chunk::<8>() else {
            return Err(truncated("ipv6_srh", 8, input.len()));
        };
        if header[2] == 0 {
            return Err(crate::codec::Error::Unsupported {
                protocol: protocol("ipv6_srh"),
                message: "IPv6 routing type 0 is prohibited".to_owned(),
            });
        }
        if header[2] != 4 {
            return Err(crate::codec::Error::Unsupported {
                protocol: protocol("ipv6_srh"),
                message: format!("unsupported routing type {}", header[2]),
            });
        }
        let header_len = usize::from(header[1])
            .saturating_add(1)
            .checked_mul(8)
            .ok_or_else(|| invalid("ipv6_srh", "header length overflow"))?;
        if input.len() < header_len {
            return Err(truncated("ipv6_srh", header_len, input.len()));
        }
        let count = usize::from(header[4]).saturating_add(1);
        let segments_end = count
            .checked_mul(16)
            .and_then(|length| length.checked_add(8))
            .ok_or_else(|| invalid("ipv6_srh", "segment-list length overflow"))?;
        if header_len < segments_end || header[3] > header[4] {
            return Err(invalid(
                "ipv6_srh",
                "Last Entry or Segments Left is inconsistent",
            ));
        }
        if header[5] != 0 {
            return Err(invalid("ipv6_srh", "unsupported flags are non-zero"));
        }
        let segment_bytes = input
            .get(8..segments_end)
            .ok_or_else(|| truncated("ipv6_srh", segments_end, input.len()))?;
        let mut wire_segments = Vec::with_capacity(count);
        for chunk in segment_bytes.chunks_exact(16) {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(chunk);
            wire_segments.push(Ipv6Addr::from(bytes));
        }
        wire_segments.reverse();
        let final_destination = wire_segments
            .last()
            .copied()
            .ok_or_else(|| invalid("ipv6_srh", "segment list is empty"))?;
        let tlv_bytes = input
            .get(segments_end..header_len)
            .ok_or_else(|| truncated("ipv6_srh", header_len, input.len()))?;
        let network = context.network.map(|network| NetworkEnvelope {
            source: network.source,
            destination: IpAddr::V6(final_destination),
        });
        Ok(DecodedLayerValue {
            layer: Box::new(SegmentRoutingHeader {
                next_header: WireValue::Exact(header[0]),
                segments_left: WireValue::Exact(header[3]),
                last_entry: WireValue::Exact(header[4]),
                flags: header[5],
                tag: u16::from_be_bytes([header[6], header[7]]),
                segments: wire_segments,
                tlvs: Bytes::copy_from_slice(tlv_bytes),
            }),
            consumed: header_len,
            payload_len: input.len().saturating_sub(header_len),
            next: vec![Discriminator(u64::from(header[0]))],
            fields: srh_layout(segments_end, header_len),
            diagnostics: Vec::new(),
            stop: input.len() == header_len,
            network,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(
            SegmentRoutingHeader::default(),
            &aliased_fields("ipv6_srh", fields, &[("segs", "segments")])?,
        )
    }
}

fn srh_lengths(layer: &SegmentRoutingHeader) -> Result<(usize, usize), crate::codec::Error> {
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
        .checked_next_multiple_of(8)
        .ok_or_else(|| invalid("ipv6_srh", "SRH padding overflow"))?;
    Ok((segments_end, header_len))
}
