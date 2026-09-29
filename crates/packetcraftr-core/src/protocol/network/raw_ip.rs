// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::Layer,
};

use crate::protocol::common::{invalid, protocol, truncated, unsupported};

use super::{Ipv4Codec, Ipv6Codec};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::RawIp.as_str();

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RawIpCodec;

impl LayerCodec for RawIpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        const PROTOCOL: &crate::layer::Id = &protocol(NAME);
        PROTOCOL
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
        Err(unsupported(
            NAME,
            "raw_ip is a decode-only link root; build IPv4 or IPv6 directly",
        ))
    }

    fn decode(
        &self,
        input: Bytes,
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
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
        Err(unsupported(NAME, "raw_ip has no constructible layer"))
    }
}
