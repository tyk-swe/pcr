// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Version-dispatching raw IP capture-root codec.

use packetcraftr_packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, NativeLayerCodec, NativeLayerDecodeContext,
        NativeLayerEncodeContext,
    },
    layer::Layer,
};

use super::super::common::{invalid, protocol, truncated};

use super::{Ipv4Codec, Ipv6Codec};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RawIpCodec;

impl NativeLayerCodec for RawIpCodec {
    fn encode(
        &self,
        _layer: &dyn Layer,
        _payload: &[u8],
        _context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        Err(CodecError::Unsupported {
            protocol: protocol("raw_ip"),
            message: "raw_ip is a decode-only link root; build IPv4 or IPv6 directly".to_string(),
        })
    }

    fn decode(
        &self,
        input: &[u8],
        context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, CodecError> {
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
        _fields: &packetcraftr_packet::layer::ValidatedFieldSet,
    ) -> Result<Box<dyn Layer>, CodecError> {
        Err(CodecError::Unsupported {
            protocol: protocol("raw_ip"),
            message: "raw_ip has no constructible layer".to_string(),
        })
    }
}
