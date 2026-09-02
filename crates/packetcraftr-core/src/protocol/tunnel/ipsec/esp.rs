// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{
    child_is_opaque, ensure_encode_budget, make_layer, payload_without_padding, protocol,
    strict_or_diagnostic, truncated, typed_layer,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Esp.as_str();

const ESP_LEN: usize = 8;

/// IPsec ESP header (RFC 4303), IP protocol 50.
///
/// Everything after the sequence number is ciphertext — including the
/// trailer and ICV — so the payload is deliberately opaque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Esp {
    /// Security parameters index.
    pub spi: u32,
    /// Anti-replay sequence number.
    pub sequence: u32,
}

impl Default for Esp {
    fn default() -> Self {
        Self {
            // The first SPI outside the reserved ranges: zero must never
            // appear on the wire and 1-255 are held by IANA.
            spi: 256,
            sequence: 0,
        }
    }
}

reflective_layer! {
    fn esp_schema() => { protocol: protocol(NAME), name: "ESP" }
    impl Esp {
        "spi" => { kind: Unsigned, derived: false, required: true, description: "Security parameters index", reflect: spi, layout: (0, 4) },
        "sequence" => { kind: Unsigned, derived: false, required: false, description: "Anti-replay sequence number", reflect: sequence, layout: (4, 8) }
    }
    layout pub(crate) fn esp_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EspCodec;

impl LayerCodec for EspCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &esp_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Esp>(NAME, layer)?;
        ensure_encode_budget(NAME, ESP_LEN, context)?;
        let mut diagnostics = Vec::new();
        // The ciphertext always ends in the two-byte Pad Length / Next
        // Header trailer, so a shorter payload cannot be a complete packet.
        if payload_without_padding(NAME, payload, context)?.len() < 2 {
            strict_or_diagnostic(
                NAME,
                "build.esp_trailer",
                "spi",
                "the encrypted payload must include the two-byte ESP trailer",
                context,
                &mut diagnostics,
            )?;
        }
        if layer.spi == 0 {
            strict_or_diagnostic(
                NAME,
                "build.esp_spi",
                "spi",
                "SPI zero is reserved and must not appear on the wire",
                context,
                &mut diagnostics,
            )?;
        }
        // The payload is ciphertext: a typed child would serialize plaintext
        // protocol structure that dissection deliberately never recovers, so
        // the layer stack could not round-trip.
        if let Some(child) = context.child
            && !child_is_opaque(child)
        {
            strict_or_diagnostic(
                NAME,
                "build.esp_ciphertext",
                "spi",
                format!(
                    "the ESP payload is ciphertext; carry the {} bytes as a raw layer",
                    child.protocol_id()
                ),
                context,
                &mut diagnostics,
            )?;
        }
        let mut prefix = Vec::with_capacity(ESP_LEN);
        prefix.extend_from_slice(&layer.spi.to_be_bytes());
        prefix.extend_from_slice(&layer.sequence.to_be_bytes());
        Ok(EncodedLayer::header(prefix, Box::new(layer.clone()))
            .with_fields(esp_layout())
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<ESP_LEN>() else {
            return Err(truncated(NAME, ESP_LEN, input.len()));
        };
        let payload_len = input.len().saturating_sub(ESP_LEN);
        let mut diagnostics = Vec::new();
        if payload_len < 2 {
            diagnostics.push(
                Diagnostic::warning(
                    "decode.esp_trailer",
                    "the ciphertext is too short for the two-byte ESP trailer",
                )
                .at_field("sequence"),
            );
        }
        Ok(DecodedLayer {
            fields: esp_layout(),
            layer: Box::new(Esp {
                spi: u32::from_be_bytes([header[0], header[1], header[2], header[3]]),
                sequence: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
            }),
            consumed: ESP_LEN,
            payload_len,
            // Ciphertext: always the opaque child.
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
        make_layer(Esp::default(), fields)
    }
}
