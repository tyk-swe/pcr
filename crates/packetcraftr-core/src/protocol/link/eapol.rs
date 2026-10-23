// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{Codec, DecodeContext, Decoded, EncodeContext, Encoded},
    field::{self, WireValue},
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{
    ValueExpectation, ensure_encode_budget, invalid, make_layer, payload_without_padding, protocol,
    resolve_u16, truncated, typed_layer,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Eapol.as_str();

const EAPOL_LEN: usize = 4;

/// Discriminator of the body that follows the header.
const EAPOL_BODY: u64 = 0;

/// EAP over LAN header (IEEE 802.1X).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eapol {
    pub version: u8,
    /// 0 EAP-Packet, 1 Start, 2 Logoff, 3 Key, 4 ASF-Alert, 5 MKA, 6 Announcement.
    pub packet_type: u8,
    /// Body length in bytes, excluding this header.
    pub length: WireValue<u16>,
}

impl Default for Eapol {
    /// An EAPOL-Start frame, which carries no body.
    fn default() -> Self {
        Self {
            version: 2,
            packet_type: 1,
            length: WireValue::Auto,
        }
    }
}

reflective_layer! {
    fn eapol_schema() => { protocol: protocol(NAME), name: "EAPOL" }
    impl Eapol {
        "version" => { kind: Unsigned, derived: false, required: false, description: "802.1X protocol version", reflect: version, layout: (0, 1) },
        "packet_type" | "type" => { kind: Unsigned, derived: false, required: false, description: "Packet type: 0 EAP-Packet, 1 Start, 2 Logoff, 3 Key, 4 ASF-Alert, 5 MKA, 6 Announcement", reflect: packet_type, layout: (1, 2) },
        "length" => { kind: Unsigned, derived: true, required: false, description: "Body length excluding the header", reflect: length, layout: (2, 4) },
    }
    layout pub(crate) fn eapol_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EapolCodec;

impl Codec for EapolCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &eapol_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &EncodeContext<'_>,
    ) -> Result<Encoded, crate::codec::Error> {
        let layer = typed_layer::<Eapol>(NAME, layer)?;
        ensure_encode_budget(NAME, EAPOL_LEN, context)?;
        let covered_payload = payload_without_padding(NAME, payload, context)?;
        let expected_length = u16::try_from(covered_payload.len())
            .map_err(|_| invalid(NAME, "body exceeds the EAPOL length range"))?;

        let mut diagnostics = Vec::new();
        if context
            .child
            .is_some_and(<dyn Layer>::is::<super::eap::Eap>)
            && layer.packet_type != 0
        {
            crate::protocol::common::strict_or_diagnostic(
                NAME,
                "build.eapol_type",
                "packet_type",
                "an EAP child requires EAPOL packet_type=0",
                context,
                &mut diagnostics,
            )?;
        }
        let (length, materialized_length) = resolve_u16(
            NAME,
            "length",
            &layer.length,
            ValueExpectation::Required(expected_length),
            context.mode,
            &mut diagnostics,
        )?;

        let mut prefix = Vec::with_capacity(EAPOL_LEN);
        prefix.push(layer.version);
        prefix.push(layer.packet_type);
        prefix.extend_from_slice(&length.to_be_bytes());
        let mut materialized = layer.clone();
        materialized.length = materialized_length;
        Ok(Encoded::header(prefix, Box::new(materialized))
            .with_fields(eapol_layout())
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &DecodeContext<'_>,
    ) -> Result<Decoded, crate::codec::Error> {
        let Some(header) = input.first_chunk::<EAPOL_LEN>() else {
            return Err(truncated(NAME, EAPOL_LEN, input.len()));
        };
        let length_field = u16::from_be_bytes([header[2], header[3]]);
        let length = usize::from(length_field);
        if input.len().saturating_sub(EAPOL_LEN) < length {
            return Err(truncated(
                NAME,
                EAPOL_LEN.saturating_add(length),
                input.len(),
            ));
        }
        Ok(Decoded {
            fields: eapol_layout(),
            layer: Box::new(Eapol {
                version: header[0],
                packet_type: header[1],
                length: WireValue::Exact(length_field),
            }),
            consumed: EAPOL_LEN,
            payload_len: length,
            next: if length == 0 {
                Vec::new()
            } else {
                vec![
                    Discriminator(256 + u64::from(header[1])),
                    Discriminator(EAPOL_BODY),
                ]
            },
            diagnostics: Vec::new(),
            stop: length == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, field::Value>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Eapol::default(), fields)
    }
}
