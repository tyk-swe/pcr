// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::protocol::common::{ensure_encode_budget, strict_or_diagnostic, truncated, typed_layer};

use crate::{
    codec::{Codec, DecodeContext, Decoded, EncodeContext, Encoded},
    layer::{Id, Layer, reflective_layer},
    registry::Discriminator,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::L2tpv3.as_str();

const L2TPV3_LEN: usize = 4;

/// L2TPv3 session header over IP (RFC 3931), IP protocol 115.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2tpv3 {
    pub session_id: u32,
}

impl Default for L2tpv3 {
    fn default() -> Self {
        Self { session_id: 1 }
    }
}

reflective_layer! {
    fn l2tpv3_schema() => { protocol: Id::new(NAME), name: "L2TPv3" }
    impl L2tpv3 {
        "session_id" => { kind: Unsigned, derived: false, required: true, description: "32-bit session identifier; zero is the control connection", reflect: session_id, layout: (0, 4) }
    }
    layout pub(crate) fn l2tpv3_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct L2tpv3Codec;

impl Codec for L2tpv3Codec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &l2tpv3_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &EncodeContext<'_>,
    ) -> Result<Encoded, crate::codec::Error> {
        let layer = typed_layer::<L2tpv3>(NAME, layer)?;
        ensure_encode_budget(NAME, L2TPV3_LEN, context)?;
        let mut diagnostics = Vec::new();
        if let Some(child) = context.child
            && !child.is_opaque()
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
        Ok(Encoded::header(
            layer.session_id.to_be_bytes().to_vec(),
            Box::new(layer.clone()),
        )
        .with_fields(l2tpv3_layout())
        .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &DecodeContext<'_>,
    ) -> Result<Decoded, crate::codec::Error> {
        let Some(header) = input.first_chunk::<L2TPV3_LEN>() else {
            return Err(truncated(NAME, L2TPV3_LEN, input.len()));
        };
        let payload_len = input.len().saturating_sub(L2TPV3_LEN);
        Ok(Decoded {
            fields: l2tpv3_layout(),
            layer: Box::new(L2tpv3 {
                session_id: u32::from_be_bytes(*header),
            }),
            consumed: L2TPV3_LEN,
            payload_len,
            next: vec![Discriminator(0)],
            diagnostics: Vec::new(),
            stop: payload_len == 0,
            network: None,
        })
    }

    fn schema(&self) -> Option<&'static crate::layer::Schema> {
        Some(l2tpv3_schema())
    }

    fn new_layer(&self) -> Result<Box<dyn Layer>, crate::codec::Error> {
        Ok(Box::new(L2tpv3::default()))
    }
}
