// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Version-dispatching raw IP capture-root codec.

use std::collections::BTreeMap;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::Layer,
};

use super::super::common::{invalid, protocol, truncated};

use super::{Ipv4Codec, Ipv6Codec};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RawIpCodec;

impl LayerCodec for RawIpCodec {
    fn protocol_id(&self) -> crate::layer::Id {
        protocol("raw_ip")
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
            protocol: protocol("raw_ip"),
            message: "raw_ip is a decode-only link root; build IPv4 or IPv6 directly".to_string(),
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let Some(version) = input.first().map(|byte| byte >> 4) else {
            return Err(truncated("raw_ip", 1, 0));
        };
        match version {
            4 => Ipv4Codec.decode(input, context),
            6 => Ipv6Codec.decode(input, context),
            _ => Err(invalid(
                "raw_ip",
                format!("unknown IP version nibble {version}"),
            )),
        }
    }

    fn make_layer(
        &self,
        _fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        Err(crate::codec::Error::Unsupported {
            protocol: protocol("raw_ip"),
            message: "raw_ip has no constructible layer".to_string(),
        })
    }
}
