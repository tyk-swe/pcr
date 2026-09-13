// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::{Dhcpv4, Dhcpv6, Limits, v4, v6};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Layer, Raw, raw_layout},
    protocol::common::{invalid, typed_layer},
};
use bytes::Bytes;
use std::collections::BTreeMap;
macro_rules! codec {
    ($codec:ident,$ty:ident,$module:ident,$name:literal) => {
        #[derive(Clone, Copy, Debug, Default)]
        pub(crate) struct $codec;
        impl LayerCodec for $codec {
            fn protocol_id(&self) -> &'static crate::layer::Id {
                &$module::schema().protocol
            }
            fn published_schema(&self) -> Option<&'static crate::layer::Schema> {
                Some($module::schema())
            }
            fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
                matches!(protocol.as_str(), $name | "raw")
            }
            fn encode(
                &self,
                layer: &dyn Layer,
                payload: &[u8],
                context: &LayerEncodeContext<'_>,
            ) -> Result<EncodedLayer, crate::codec::Error> {
                if !payload.is_empty() {
                    return Err(invalid($name, "DHCP is a complete UDP payload"));
                }
                let layer = typed_layer::<$ty>($name, layer)?;
                let wire = layer
                    .to_wire_with_limits(Limits {
                        max_message_bytes: context.remaining_packet_bytes,
                        ..Default::default()
                    })
                    .map_err(|error| invalid($name, error.to_string()))?;
                let normalized = $ty::from_wire(wire.clone())
                    .map_err(|error| invalid($name, error.to_string()))?;
                Ok(EncodedLayer::header(wire.to_vec(), Box::new(normalized))
                    .with_fields($module::layout()))
            }
            fn decode(
                &self,
                input: &[u8],
                _context: &LayerDecodeContext<'_>,
            ) -> Result<DecodedLayer, crate::codec::Error> {
                if ($name == "dhcpv4" && input.get(236..240) != Some(b"\x63\x82\x53\x63"))
                    || ($name == "dhcpv6" && input.len() < 4)
                {
                    let mut raw = DecodedLayer::terminal(
                        Box::new(Raw::new(Bytes::copy_from_slice(input))),
                        input.len(),
                    );
                    raw.fields = raw_layout(input.len());
                    return Ok(raw);
                }
                let layer = $ty::from_wire(Bytes::copy_from_slice(input))
                    .map_err(|error| invalid($name, error.to_string()))?;
                let mut decoded = DecodedLayer::terminal(Box::new(layer), input.len());
                decoded.fields = $module::layout();
                Ok(decoded)
            }
            fn make_layer(
                &self,
                fields: &BTreeMap<String, FieldValue>,
            ) -> Result<Box<dyn Layer>, crate::codec::Error> {
                let mut layer = match fields.get("wire") {
                    Some(FieldValue::Bytes(wire)) => $ty::from_wire(wire.clone())
                        .map_err(|error| invalid($name, error.to_string()))?,
                    Some(_) => return Err(invalid($name, "wire must be retained bytes")),
                    None => $ty::default(),
                };
                for (name, value) in fields {
                    if name == "wire" || layer.field(name).as_ref() == Some(value) {
                        continue;
                    }
                    layer.set_field_path(name, value.clone())?;
                }
                if fields.contains_key("options")
                    && let Some(message_type) = fields.get("message_type")
                    && layer.field("message_type").as_ref() != Some(message_type)
                {
                    return Err(invalid(
                        $name,
                        "message_type conflicts with supplied options",
                    ));
                }
                Ok(Box::new(layer))
            }
        }
    };
}
codec!(Dhcpv4Codec, Dhcpv4, v4, "dhcpv4");
codec!(Dhcpv6Codec, Dhcpv6, v6, "dhcpv6");
