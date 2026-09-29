// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::{Diagnostic, ICMPV4_CHECKSUM, ICMPV6_CHECKSUM},
    field::{self, FieldValue, WireValue},
    layer::{Layer, Schema, reflective_layer},
    layout::{ByteRange, FieldLayout},
};

use super::{ip_protocol, resolve_envelope};
use crate::protocol::common::{
    ValueExpectation, checksum, checksum_parts, ensure_encode_budget, invalid, make_layer,
    out_of_range, payload_without_padding, protocol, resolve_u16, transport_checksum,
    transport_checksum_parts, truncated, typed_layer, wrong_type,
};

use crate::protocol::BuiltinProtocol;

const V4_NAME: &str = BuiltinProtocol::Icmpv4.as_str();
const V6_NAME: &str = BuiltinProtocol::Icmpv6.as_str();

const ICMP_MIN_LEN: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmpv4 {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: WireValue<u16>,
    pub body: Bytes,
}

impl Default for Icmpv4 {
    fn default() -> Self {
        Self {
            icmp_type: 8,
            code: 0,
            checksum: WireValue::Auto,
            body: Bytes::from_static(&[0, 0, 0, 0]),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmpv6 {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: WireValue<u16>,
    pub body: Bytes,
}

impl Default for Icmpv6 {
    fn default() -> Self {
        Self {
            icmp_type: 128,
            code: 0,
            checksum: WireValue::Auto,
            body: Bytes::from_static(&[0, 0, 0, 0]),
        }
    }
}

fn body_unsigned(body: &Bytes, start: usize, width: usize) -> Option<FieldValue> {
    let bytes = body.get(start..start.checked_add(width)?)?;
    let mut value = 0_u64;
    for byte in bytes {
        value = (value << 8) | u64::from(*byte);
    }
    Some(FieldValue::Unsigned(value))
}

fn body_rest(body: &Bytes) -> Option<FieldValue> {
    (body.len() >= 4).then(|| FieldValue::Bytes(body.slice(4..)))
}

fn patch_body(body: &mut Bytes, start: usize, bytes: &[u8]) {
    let end = start.saturating_add(bytes.len());
    let mut edited = Vec::with_capacity(body.len().max(end));
    edited.extend_from_slice(body);
    edited.resize(edited.len().max(end), 0);
    edited[start..end].copy_from_slice(bytes);
    *body = Bytes::from(edited);
}

fn patch_body_rest(body: &mut Bytes, rest: &[u8]) {
    let mut edited = Vec::with_capacity(4usize.saturating_add(rest.len()));
    edited.extend_from_slice(body.get(..4).unwrap_or(body));
    edited.resize(4, 0);
    edited.extend_from_slice(rest);
    *body = Bytes::from(edited);
}

fn set_body_unsigned(
    body: &mut Bytes,
    start: usize,
    width: usize,
    schema: &'static Schema,
    value: FieldValue,
    name: &str,
) -> Result<(), field::Error> {
    let FieldValue::Unsigned(value) = value else {
        return Err(wrong_type(schema, name, "unsigned"));
    };
    let bytes = value.to_be_bytes();
    let (high, low) = bytes.split_at(bytes.len() - width);
    if high.iter().any(|byte| *byte != 0) {
        return Err(out_of_range(schema, name));
    }
    patch_body(body, start, low);
    Ok(())
}

fn set_rest(
    body: &mut Bytes,
    schema: &'static Schema,
    value: FieldValue,
    name: &str,
) -> Result<(), field::Error> {
    match value {
        FieldValue::Bytes(value) => {
            patch_body_rest(body, &value);
            Ok(())
        }
        _ => Err(wrong_type(schema, name, "bytes")),
    }
}

/// `body` starts at message offset four.
fn view_layout(
    fields: &mut Vec<FieldLayout>,
    body_len: usize,
    name: &'static str,
    range: ByteRange,
) {
    if range.end.saturating_sub(4) <= body_len {
        fields.push(FieldLayout { name, range });
    }
}

fn finish_layout(mut fields: Vec<FieldLayout>, body_len: usize) -> Vec<FieldLayout> {
    if body_len >= 4 {
        fields.push(FieldLayout {
            name: "rest",
            range: ByteRange::new(8, 4_usize.saturating_add(body_len)),
        });
    }
    fields.sort_by_key(|field| field.range.start);
    fields
}

reflective_layer! {
    fn icmpv4_schema() => { protocol: protocol(V4_NAME), name: "ICMPv4" }
    impl Icmpv4 {
        "type" => {
            kind: Unsigned, derived: false, required: true,
            description: "ICMP message type",
            reflect: icmp_type,
            layout: (0, 1)
        },
        "code" => {
            kind: Unsigned, derived: false, required: true,
            description: "ICMP message code",
            reflect: code,
            layout: (1, 2)
        },
        "checksum" => {
            kind: Unsigned, derived: true, required: false,
            description: "ICMP checksum",
            reflect: checksum,
            layout: (2, 4)
        },
        "identifier" => {
            kind: Unsigned, derived: false, required: false,
            description: "Identifier (echo-style and extended messages)",
            get |layer| body_unsigned(&layer.body, 0, 2),
            set |layer, value, name| set_body_unsigned(&mut layer.body, 0, 2, icmpv4_schema(), value, name)
        },
        "sequence" => {
            kind: Unsigned, derived: false, required: false,
            description: "Sequence number (echo-style and extended messages)",
            get |layer| body_unsigned(&layer.body, 2, 2),
            set |layer, value, name| set_body_unsigned(&mut layer.body, 2, 2, icmpv4_schema(), value, name)
        },
        "rest" => {
            kind: Bytes, derived: false, required: false,
            description: "Quoted datagram or payload after the type-specific field",
            get |layer| body_rest(&layer.body),
            set |layer, value, name| set_rest(&mut layer.body, icmpv4_schema(), value, name)
        },
        "gateway" => {
            kind: Ipv4, derived: false, required: false,
            description: "Gateway address (redirect)",
            get |layer| layer.body.get(..4).and_then(|bytes| {
                <[u8; 4]>::try_from(bytes).ok().map(|bytes| FieldValue::Ipv4(Ipv4Addr::from(bytes)))
            }),
            set |layer, value, name| layer.set_gateway(value, name)
        },
        "mtu" => {
            kind: Unsigned, derived: false, required: false,
            description: "Next-hop MTU (destination unreachable, code 4)",
            get |layer| body_unsigned(&layer.body, 2, 2),
            set |layer, value, name| set_body_unsigned(&mut layer.body, 2, 2, icmpv4_schema(), value, name)
        },
        "pointer" => {
            kind: Unsigned, derived: false, required: false,
            description: "Erroneous header octet (parameter problem)",
            get |layer| body_unsigned(&layer.body, 0, 1),
            set |layer, value, name| set_body_unsigned(&mut layer.body, 0, 1, icmpv4_schema(), value, name)
        },
        "body" => {
            kind: Bytes, derived: false, required: false,
            description: "Type-specific ICMP body",
            reflect: body,
            layout: (4, 4_usize.saturating_add(body_len))
        },
    }
    layout fn icmpv4_base_layout(body_len: usize);
}

fn icmpv4_layout(body_len: usize) -> Vec<FieldLayout> {
    let mut fields = icmpv4_base_layout(body_len);
    view_layout(&mut fields, body_len, "pointer", ByteRange::new(4, 5));
    view_layout(&mut fields, body_len, "identifier", ByteRange::new(4, 6));
    view_layout(&mut fields, body_len, "gateway", ByteRange::new(4, 8));
    view_layout(&mut fields, body_len, "sequence", ByteRange::new(6, 8));
    view_layout(&mut fields, body_len, "mtu", ByteRange::new(6, 8));
    finish_layout(fields, body_len)
}

impl Icmpv4 {
    fn set_gateway(&mut self, value: FieldValue, name: &str) -> Result<(), field::Error> {
        let address = match value {
            FieldValue::Ipv4(address) => address,
            FieldValue::Text(value) => value
                .parse::<Ipv4Addr>()
                .map_err(|_| wrong_type(icmpv4_schema(), name, "ipv4"))?,
            _ => return Err(wrong_type(icmpv4_schema(), name, "ipv4")),
        };
        patch_body(&mut self.body, 0, &address.octets());
        Ok(())
    }
}

reflective_layer! {
    fn icmpv6_schema() => { protocol: protocol(V6_NAME), name: "ICMPv6" }
    impl Icmpv6 {
        "type" => {
            kind: Unsigned, derived: false, required: true,
            description: "ICMPv6 message type",
            reflect: icmp_type,
            layout: (0, 1)
        },
        "code" => {
            kind: Unsigned, derived: false, required: true,
            description: "ICMPv6 message code",
            reflect: code,
            layout: (1, 2)
        },
        "checksum" => {
            kind: Unsigned, derived: true, required: false,
            description: "ICMPv6 checksum",
            reflect: checksum,
            layout: (2, 4)
        },
        "identifier" => {
            kind: Unsigned, derived: false, required: false,
            description: "Identifier (echo-style and extended messages)",
            get |layer| body_unsigned(&layer.body, 0, 2),
            set |layer, value, name| set_body_unsigned(&mut layer.body, 0, 2, icmpv6_schema(), value, name)
        },
        "sequence" => {
            kind: Unsigned, derived: false, required: false,
            description: "Sequence number (echo-style and extended messages)",
            get |layer| body_unsigned(&layer.body, 2, 2),
            set |layer, value, name| set_body_unsigned(&mut layer.body, 2, 2, icmpv6_schema(), value, name)
        },
        "rest" => {
            kind: Bytes, derived: false, required: false,
            description: "Quoted datagram or payload after the type-specific field",
            get |layer| body_rest(&layer.body),
            set |layer, value, name| set_rest(&mut layer.body, icmpv6_schema(), value, name)
        },
        "mtu" => {
            kind: Unsigned, derived: false, required: false,
            description: "Packet-too-big MTU",
            get |layer| body_unsigned(&layer.body, 0, 4),
            set |layer, value, name| set_body_unsigned(&mut layer.body, 0, 4, icmpv6_schema(), value, name)
        },
        "pointer" => {
            kind: Unsigned, derived: false, required: false,
            description: "Erroneous header offset (parameter problem)",
            get |layer| body_unsigned(&layer.body, 0, 4),
            set |layer, value, name| set_body_unsigned(&mut layer.body, 0, 4, icmpv6_schema(), value, name)
        },
        "body" => {
            kind: Bytes, derived: false, required: false,
            description: "Type-specific ICMPv6 body",
            reflect: body,
            layout: (4, 4_usize.saturating_add(body_len))
        },
    }
    layout fn icmpv6_base_layout(body_len: usize);
}

fn icmpv6_layout(body_len: usize) -> Vec<FieldLayout> {
    let mut fields = icmpv6_base_layout(body_len);
    view_layout(&mut fields, body_len, "identifier", ByteRange::new(4, 6));
    view_layout(&mut fields, body_len, "mtu", ByteRange::new(4, 8));
    view_layout(&mut fields, body_len, "pointer", ByteRange::new(4, 8));
    view_layout(&mut fields, body_len, "sequence", ByteRange::new(6, 8));
    finish_layout(fields, body_len)
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Icmpv4Codec;

impl LayerCodec for Icmpv4Codec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &icmpv4_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Icmpv4>(V4_NAME, layer)?;
        let contribution = ICMP_MIN_LEN
            .checked_add(layer.body.len())
            .ok_or_else(|| invalid(V4_NAME, "message length overflow"))?;
        ensure_encode_budget(V4_NAME, contribution, context)?;
        let covered_payload = payload_without_padding(V4_NAME, payload, context)?;
        let mut prefix = Vec::with_capacity(contribution);
        prefix.extend_from_slice(&[layer.icmp_type, layer.code, 0, 0]);
        prefix.extend_from_slice(&layer.body);
        let expected = checksum_parts(&[&prefix, covered_payload]);
        let mut diagnostics = Vec::new();
        let (checksum, materialized_checksum) = resolve_u16(
            V4_NAME,
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected),
            context.mode,
            &mut diagnostics,
        )?;
        {
            prefix[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(icmpv4_layout(layer.body.len()))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<ICMP_MIN_LEN>() else {
            return Err(truncated(V4_NAME, ICMP_MIN_LEN, input.len()));
        };
        let body = input.slice(ICMP_MIN_LEN..);
        let body_len = body.len();
        let mut diagnostics = Vec::new();
        if checksum(&input) != 0 {
            diagnostics.push(
                Diagnostic::warning(ICMPV4_CHECKSUM, "ICMPv4 checksum mismatch")
                    .at_field("checksum"),
            );
        }
        Ok(DecodedLayer {
            layer: Box::new(Icmpv4 {
                icmp_type: header[0],
                code: header[1],
                checksum: WireValue::Exact(u16::from_be_bytes([header[2], header[3]])),
                body,
            }),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: icmpv4_layout(body_len),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Icmpv4::default(), fields)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Icmpv6Codec;

impl LayerCodec for Icmpv6Codec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &icmpv6_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Icmpv6>(V6_NAME, layer)?;
        let contribution = ICMP_MIN_LEN
            .checked_add(layer.body.len())
            .ok_or_else(|| invalid(V6_NAME, "message length overflow"))?;
        ensure_encode_budget(V6_NAME, contribution, context)?;
        let covered_payload = payload_without_padding(V6_NAME, payload, context)?;
        let mut prefix = Vec::with_capacity(contribution);
        prefix.extend_from_slice(&[layer.icmp_type, layer.code, 0, 0]);
        prefix.extend_from_slice(&layer.body);
        let expected = transport_checksum_parts(
            V6_NAME,
            resolve_envelope(V6_NAME, context)?,
            ip_protocol::ICMPV6,
            &[&prefix, covered_payload],
        )?;
        let mut diagnostics = Vec::new();
        let (checksum, materialized_checksum) = resolve_u16(
            V6_NAME,
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected),
            context.mode,
            &mut diagnostics,
        )?;
        {
            prefix[2..4].copy_from_slice(&checksum.to_be_bytes());
        }
        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(icmpv6_layout(layer.body.len()))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<ICMP_MIN_LEN>() else {
            return Err(truncated(V6_NAME, ICMP_MIN_LEN, input.len()));
        };
        let body = input.slice(ICMP_MIN_LEN..);
        let body_len = body.len();
        let mut diagnostics = Vec::new();
        if let Some(network) = context.network
            && transport_checksum(V6_NAME, network, ip_protocol::ICMPV6, &input)? != 0
        {
            diagnostics.push(
                Diagnostic::warning(ICMPV6_CHECKSUM, "ICMPv6 checksum mismatch")
                    .at_field("checksum"),
            );
        }
        Ok(DecodedLayer {
            layer: Box::new(Icmpv6 {
                icmp_type: header[0],
                code: header[1],
                checksum: WireValue::Exact(u16::from_be_bytes([header[2], header[3]])),
                body,
            }),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: icmpv6_layout(body_len),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Icmpv6::default(), fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::Layer;

    fn set(layer: &mut impl Layer, name: &str, value: impl Into<FieldValue>) {
        layer.set_field(name, value.into()).unwrap();
    }

    #[test]
    fn echo_views_edit_body_in_place() {
        let mut layer = Icmpv4::default();
        set(&mut layer, "identifier", 0x1234_u64);
        set(&mut layer, "sequence", 9_u64);
        set(&mut layer, "rest", Bytes::from_static(&[0xaa, 0xbb]));
        assert_eq!(
            layer.body.as_ref(),
            &[0x12, 0x34, 0, 9, 0xaa, 0xbb],
            "typed views patch the verbatim body"
        );
        assert_eq!(
            layer.field("identifier"),
            Some(FieldValue::Unsigned(0x1234))
        );
        assert_eq!(layer.field("sequence"), Some(FieldValue::Unsigned(9)));
        assert_eq!(
            layer.field("rest"),
            Some(FieldValue::Bytes(Bytes::from_static(&[0xaa, 0xbb])))
        );
    }

    #[test]
    fn echo_views_extend_a_short_body() {
        let mut layer = Icmpv4 {
            body: Bytes::new(),
            ..Icmpv4::default()
        };
        set(&mut layer, "sequence", 1_u64);
        assert_eq!(layer.body.as_ref(), &[0, 0, 0, 1]);
    }

    #[test]
    fn error_views_edit_type_specific_fields() {
        let mut v4 = Icmpv4 {
            icmp_type: 3,
            code: 4,
            ..Icmpv4::default()
        };
        set(&mut v4, "mtu", 1400_u64);
        assert_eq!(v4.body.as_ref(), &[0, 0, 0x05, 0x78]);

        let mut redirect = Icmpv4 {
            icmp_type: 5,
            ..Icmpv4::default()
        };
        set(
            &mut redirect,
            "gateway",
            FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
        );
        assert_eq!(redirect.body.as_ref(), &[192, 0, 2, 1]);

        let mut problem = Icmpv4 {
            icmp_type: 12,
            ..Icmpv4::default()
        };
        set(&mut problem, "pointer", 8_u64);
        assert_eq!(problem.body.as_ref(), &[8, 0, 0, 0]);

        let mut v6 = Icmpv6 {
            icmp_type: 2,
            ..Icmpv6::default()
        };
        set(&mut v6, "mtu", 1280_u64);
        assert_eq!(v6.body.as_ref(), &[0, 0, 0x05, 0x00]);
        let mut v6_pointer = Icmpv6 {
            icmp_type: 4,
            ..Icmpv6::default()
        };
        set(&mut v6_pointer, "pointer", 40_u64);
        assert_eq!(v6_pointer.body.as_ref(), &[0, 0, 0, 40]);
    }

    #[test]
    fn out_of_range_views_are_rejected() {
        let mut layer = Icmpv4::default();
        assert!(matches!(
            layer.set_field("identifier", FieldValue::Unsigned(0x1_0000)),
            Err(field::Error::OutOfRange { .. })
        ));
        assert!(matches!(
            layer.set_field("rest", FieldValue::Unsigned(1)),
            Err(field::Error::WrongType { .. })
        ));
        assert_eq!(
            layer.body.as_ref(),
            &[0, 0, 0, 0],
            "failed writes leave the body untouched"
        );
    }

    #[test]
    fn views_accept_exactly_the_values_their_width_holds() {
        let mut v4 = Icmpv4::default();
        set(&mut v4, "pointer", 0xff_u64);
        assert_eq!(v4.body.as_ref(), &[0xff, 0, 0, 0]);
        assert!(matches!(
            v4.set_field("pointer", FieldValue::Unsigned(0x100)),
            Err(field::Error::OutOfRange { .. })
        ));

        let mut v6 = Icmpv6::default();
        set(&mut v6, "mtu", u64::from(u32::MAX));
        assert_eq!(v6.body.as_ref(), &[0xff; 4]);
        assert!(matches!(
            v6.set_field("mtu", FieldValue::Unsigned(1 << 32)),
            Err(field::Error::OutOfRange { .. })
        ));
        assert_eq!(v6.body.as_ref(), &[0xff; 4]);
    }

    #[test]
    fn short_bodies_report_absent_views() {
        let layer = Icmpv4 {
            icmp_type: 99,
            body: Bytes::from_static(&[1, 2]),
            ..Icmpv4::default()
        };
        assert_eq!(
            layer.field("identifier"),
            Some(FieldValue::Unsigned(0x0102))
        );
        assert_eq!(layer.field("sequence"), None);
        assert_eq!(layer.field("rest"), None);
        assert_eq!(
            layer.field("body"),
            Some(FieldValue::Bytes(Bytes::from_static(&[1, 2])))
        );
    }

    #[test]
    fn view_layout_tracks_body_coverage() {
        let layout = icmpv4_layout(8);
        let names: Vec<_> = layout.iter().map(|field| field.name).collect();
        for expected in [
            "identifier",
            "sequence",
            "mtu",
            "gateway",
            "pointer",
            "rest",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
        let rest = layout.iter().find(|field| field.name == "rest").unwrap();
        assert_eq!(rest.range, ByteRange::new(8, 12));
        let short = icmpv4_layout(2);
        let names: Vec<_> = short.iter().map(|field| field.name).collect();
        assert!(names.contains(&"identifier") && names.contains(&"pointer"));
        assert!(!names.contains(&"sequence") && !names.contains(&"rest"));
    }
}
