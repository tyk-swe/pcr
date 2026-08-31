// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::common::{
    child_is_opaque, ensure_encode_budget, make_layer, protocol, strict_or_diagnostic, truncated,
    typed_layer,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::L2tpv3.as_str();

const L2TPV3_LEN: usize = 4;

/// L2TPv3 session header over IP (RFC 3931), IP protocol 115.
///
/// The wire carries only the 32-bit session identifier; the negotiated
/// cookie that may follow has no on-wire length, so everything after the
/// header is deliberately opaque. Session zero addresses the control
/// connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2tpv3 {
    /// 32-bit session identifier; zero is the control connection.
    pub session_id: u32,
}

impl Default for L2tpv3 {
    fn default() -> Self {
        Self { session_id: 1 }
    }
}

reflective_layer! {
    fn l2tpv3_schema() => { protocol: protocol(NAME), name: "L2TPv3" }
    impl L2tpv3 {
        "session_id" => { kind: Unsigned, derived: false, required: true, description: "32-bit session identifier; zero is the control connection", reflect: session_id, layout: (0, 4) }
    }
    layout pub(crate) fn l2tpv3_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct L2tpv3Codec;

impl LayerCodec for L2tpv3Codec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &l2tpv3_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<L2tpv3>(NAME, layer)?;
        ensure_encode_budget(NAME, L2TPV3_LEN, context)?;
        let mut diagnostics = Vec::new();
        // The negotiated cookie sits between this header and the tunneled
        // frame with no on-wire length, so a typed child would serialize
        // structure that dissection deliberately never recovers.
        if let Some(child) = context.child
            && !child_is_opaque(child)
        {
            strict_or_diagnostic(
                NAME,
                "build.l2tpv3_cookie",
                "session_id",
                format!(
                    "the payload begins with the negotiated cookie; carry the {} bytes as a raw layer",
                    child.protocol_id()
                ),
                context,
                &mut diagnostics,
            )?;
        }
        Ok(EncodedLayer::header(
            layer.session_id.to_be_bytes().to_vec(),
            Box::new(layer.clone()),
        )
        .with_fields(l2tpv3_layout())
        .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(header) = input.first_chunk::<L2TPV3_LEN>() else {
            return Err(truncated(NAME, L2TPV3_LEN, input.len()));
        };
        let payload_len = input.len().saturating_sub(L2TPV3_LEN);
        Ok(DecodedLayerValue {
            fields: l2tpv3_layout(),
            layer: Box::new(L2tpv3 {
                session_id: u32::from_be_bytes(*header),
            }),
            consumed: L2TPV3_LEN,
            payload_len,
            // Cookie and tunneled frame, or control AVPs: always opaque.
            next: vec![Discriminator(0)],
            diagnostics: Vec::new(),
            stop: payload_len == 0,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(L2tpv3::default(), fields)
    }
}
