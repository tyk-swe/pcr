// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Version-dispatching raw IP capture-root codec.

use std::collections::BTreeMap;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::Layer,
};

use crate::protocol::common::{invalid, protocol, truncated};

use super::{Ipv4Codec, Ipv6Codec};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::RawIp.as_str();

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RawIpCodec;

/// `raw_ip` has no reflective layer of its own — it only dispatches on the
/// version nibble — so its identifier is interned here instead of borrowed
/// from a schema.
fn raw_ip_protocol() -> &'static crate::layer::Id {
    static PROTOCOL: std::sync::OnceLock<crate::layer::Id> = std::sync::OnceLock::new();
    PROTOCOL.get_or_init(|| protocol(NAME))
}

impl LayerCodec for RawIpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        raw_ip_protocol()
    }
    fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
        matches!(protocol.as_str(), "ipv4" | "ipv6")
    }
    fn encode(
        &self,
        _layer: &dyn Layer,
        _payload: &[u8],
        _context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        Err(crate::codec::Error::Unsupported {
            protocol: protocol(NAME),
            message: "raw_ip is a decode-only link root; build IPv4 or IPv6 directly".to_string(),
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(version) = input.first().map(|byte| byte >> 4) else {
            return Err(truncated(NAME, 1, 0));
        };
        match version {
            4 => Ipv4Codec.decode(input, context),
            6 => Ipv6Codec.decode(input, context),
            _ => Err(invalid(
                NAME,
                format!("unknown IP version nibble {version}"),
            )),
        }
    }

    fn make_layer(
        &self,
        _fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        Err(crate::codec::Error::Unsupported {
            protocol: protocol(NAME),
            message: "raw_ip has no constructible layer".to_string(),
        })
    }
}
