// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::{Diagnostic, IGMP_CHECKSUM},
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
};

use crate::protocol::common::{
    ValueExpectation, checksum, checksum_parts, ensure_encode_budget, invalid, make_layer,
    payload_without_padding, protocol, resolve_u16, truncated, typed_layer,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Igmp.as_str();

const IGMP_HEADER_LEN: usize = 4;
const IGMP_MIN_LEN: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Igmp {
    pub igmp_type: u8,
    pub code: u8,
    pub checksum: WireValue<u16>,
    pub body: Bytes,
}

impl Default for Igmp {
    fn default() -> Self {
        Self {
            igmp_type: 0x11,
            code: 0,
            checksum: WireValue::Auto,
            body: Bytes::from_static(&[0, 0, 0, 0]),
        }
    }
}

reflective_layer! {
    fn igmp_schema() => { protocol: protocol(NAME), name: "IGMP" }
    impl Igmp {
        "type" => {
            kind: Unsigned, derived: false, required: true,
            description: "IGMP message type",
            reflect: igmp_type,
            layout: (0, 1)
        },
        "code" => {
            kind: Unsigned, derived: false, required: true,
            description: "Type-specific IGMP code or reserved octet",
            reflect: code,
            layout: (1, 2)
        },
        "checksum" => {
            kind: Unsigned, derived: true, required: false,
            description: "IGMP checksum",
            reflect: checksum,
            layout: (2, 4)
        },
        "body" => {
            kind: Bytes, derived: false, required: false,
            description: "Version- and type-specific IGMP body",
            reflect: body,
            layout: (4, body_len.saturating_add(4))
        },
    }
    layout pub(crate) fn igmp_layout(body_len: usize);
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct IgmpCodec;

impl LayerCodec for IgmpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &igmp_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Igmp>(NAME, layer)?;
        let contribution = IGMP_HEADER_LEN
            .checked_add(layer.body.len())
            .ok_or_else(|| invalid(NAME, "message length overflow"))?;
        if contribution < IGMP_MIN_LEN {
            return Err(invalid(
                NAME,
                format!("message length {contribution} is below the 8-byte minimum"),
            ));
        }
        ensure_encode_budget(NAME, contribution, context)?;

        let mut prefix = Vec::with_capacity(contribution);
        prefix.extend_from_slice(&[layer.igmp_type, layer.code, 0, 0]);
        prefix.extend_from_slice(&layer.body);
        let covered_payload = payload_without_padding(NAME, payload, context)?;
        let expected = checksum_parts(&[&prefix, covered_payload]);
        let mut diagnostics = Vec::new();
        let (checksum, materialized_checksum) = resolve_u16(
            NAME,
            "checksum",
            &layer.checksum,
            ValueExpectation::Required(expected),
            context.mode,
            &mut diagnostics,
        )?;
        #[expect(
            clippy::indexing_slicing,
            reason = "`prefix` starts with the four-byte IGMP header and the guard above rejects \
                      any message shorter than eight bytes"
        )]
        let checksum_slot = &mut prefix[2..4];
        checksum_slot.copy_from_slice(&checksum.to_be_bytes());

        let mut materialized = layer.clone();
        materialized.checksum = materialized_checksum;
        Ok(EncodedLayer::header(prefix, Box::new(materialized))
            .with_fields(igmp_layout(layer.body.len()))
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<IGMP_MIN_LEN>() else {
            return Err(truncated(NAME, IGMP_MIN_LEN, input.len()));
        };
        let mut diagnostics = Vec::new();
        if checksum(input) != 0 {
            diagnostics.push(
                Diagnostic::warning(IGMP_CHECKSUM, "IGMP checksum mismatch").at_field("checksum"),
            );
        }
        let body = input
            .get(IGMP_HEADER_LEN..)
            .ok_or_else(|| truncated(NAME, IGMP_MIN_LEN, input.len()))?;
        Ok(DecodedLayer {
            layer: Box::new(Igmp {
                igmp_type: header[0],
                code: header[1],
                checksum: WireValue::Exact(u16::from_be_bytes([header[2], header[3]])),
                body: Bytes::copy_from_slice(body),
            }),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: igmp_layout(body.len()),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Igmp::default(), fields)
    }
}
