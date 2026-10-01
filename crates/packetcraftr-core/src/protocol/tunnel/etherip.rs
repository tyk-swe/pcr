// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{
    ensure_encode_budget, invalid, make_layer, protocol, strict_or_diagnostic, truncated,
    typed_layer, validate_raw_child_discriminator,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Etherip.as_str();

const ETHERIP_LEN: usize = 2;
const ETHERIP_VERSION: u8 = 3;
const VERSION_MAX: u8 = 0x0f;
const RESERVED_MAX: u16 = 0x0fff;

/// EtherIP header (RFC 3378), IP protocol 97: a 4-bit version and 12 reserved
/// bits ahead of one complete Ethernet frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Etherip {
    pub version: u8,
    pub reserved: u16,
}

impl Default for Etherip {
    fn default() -> Self {
        Self {
            version: ETHERIP_VERSION,
            reserved: 0,
        }
    }
}

reflective_layer! {
    fn etherip_schema() => { protocol: protocol(NAME), name: "EtherIP" }
    impl Etherip {
        "version" => { kind: Unsigned, derived: false, required: false, description: "4-bit EtherIP version; RFC 3378 defines only version 3", reflect_bounded: version, VERSION_MAX, layout: (0, 1) },
        "reserved" => { kind: Unsigned, derived: false, required: false, description: "12 reserved bits after the version, zero on transmission", reflect_bounded: reserved, RESERVED_MAX, layout: (0, 2) }
    }
    layout pub(crate) fn etherip_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EtheripCodec;

impl LayerCodec for EtheripCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &etherip_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Etherip>(NAME, layer)?;
        ensure_encode_budget(NAME, ETHERIP_LEN, context)?;
        if layer.version > VERSION_MAX || layer.reserved > RESERVED_MAX {
            return Err(invalid(NAME, "field exceeds its wire range"));
        }

        let mut diagnostics = Vec::new();
        validate_raw_child_discriminator(NAME, 0, context, &mut diagnostics)?;
        if layer.version != ETHERIP_VERSION {
            strict_or_diagnostic(
                NAME,
                "build.etherip_version",
                "version",
                "RFC 3378 defines only EtherIP version 3",
                context,
                &mut diagnostics,
            )?;
        }
        if layer.reserved != 0 {
            strict_or_diagnostic(
                NAME,
                "build.etherip_reserved",
                "reserved",
                "EtherIP reserved bits must be zero on transmission",
                context,
                &mut diagnostics,
            )?;
        }

        let [reserved_hi, reserved_lo] = layer.reserved.to_be_bytes();
        let prefix = vec![(layer.version << 4) | reserved_hi, reserved_lo];
        Ok(EncodedLayer::header(prefix, Box::new(layer.clone()))
            .with_fields(etherip_layout())
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<ETHERIP_LEN>() else {
            return Err(truncated(NAME, ETHERIP_LEN, input.len()));
        };
        let layer = Etherip {
            version: header[0] >> 4,
            reserved: u16::from_be_bytes([header[0] & 0x0f, header[1]]),
        };

        let mut diagnostics = Vec::new();
        if layer.version != ETHERIP_VERSION {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.etherip_version",
                    "EtherIP version is not the RFC 3378 version 3; the payload is still dissected as Ethernet",
                )
                .at_field("version"),
            );
        }
        if layer.reserved != 0 {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.etherip_reserved",
                    "EtherIP reserved bits are non-zero",
                )
                .at_field("reserved"),
            );
        }
        let payload_len = input.len().saturating_sub(ETHERIP_LEN);
        Ok(DecodedLayer {
            fields: etherip_layout(),
            layer: Box::new(layer),
            consumed: ETHERIP_LEN,
            payload_len,
            next: vec![Discriminator(0)],
            diagnostics,
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Etherip::default(), fields)
    }
}
