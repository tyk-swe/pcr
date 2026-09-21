// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Head, StartLine, parse_head};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Layer, Raw, raw_layout, reflective_layer},
    protocol::{
        BuiltinProtocol,
        common::{ensure_encode_budget, invalid, read_only, typed_layer},
    },
    registry::Discriminator,
};
use bytes::Bytes;
use std::collections::BTreeMap;
const NAME: &str = BuiltinProtocol::Http.as_str();
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Http {
    head: Head,
}
impl Http {
    pub fn head(&self) -> &Head {
        &self.head
    }
}

impl TryFrom<&[u8]> for Http {
    type Error = crate::codec::Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let bounded = &input[..input.len().min(super::MAX_HEADER_BYTES)];
        let (head, length) = parse_head(&Bytes::copy_from_slice(bounded))
            .map_err(|e| invalid(NAME, e.to_string()))?
            .ok_or_else(|| invalid(NAME, "incomplete HTTP/1 headers"))?;
        if length != input.len() {
            return Err(invalid(NAME, "header wire includes body or trailing bytes"));
        }
        Ok(Self { head })
    }
}
const HEADER_FIELDS: &[crate::layer::FieldSchema] = &[
    crate::protocol::common::structured::member("name", crate::field::FieldKind::Text, &[]),
    crate::protocol::common::structured::member("value", crate::field::FieldKind::Bytes, &[]),
];
reflective_layer! {
    fn http_schema() => { protocol: crate::layer::Id::new(NAME), name: "HTTP/1" }
    impl Http {
            "wire" => {kind:Bytes,derived:false,required:false,description:"Exact header bytes",get |layer| Some(FieldValue::Bytes(layer.head.wire().clone())),set |_layer,_value,name| read_only(http_schema(),name)},
            "method" => {kind:Text,derived:false,required:false,description:"Request method",get |layer| layer.head.method().map(|s|FieldValue::Text(s.to_owned())),set |_layer,_value,name| read_only(http_schema(),name)},
            "target" => {kind:Bytes,derived:false,required:false,description:"Exact request target",get |layer| match &layer.head.start {StartLine::Request {target,..}=>Some(FieldValue::Bytes(target.clone())),_=>None},set |_layer,_value,name| read_only(http_schema(),name)},
            "status" => {kind:Unsigned,derived:false,required:false,description:"Response status code",get |layer| layer.head.status().map(|n|FieldValue::Unsigned(u64::from(n))),set |_layer,_value,name| read_only(http_schema(),name)},
            "version" => {kind:Text,derived:false,required:false,description:"HTTP/1 version",get |layer| Some(FieldValue::Text(match &layer.head.start {StartLine::Request {version,..}|StartLine::Response {version,..}=>version.clone()})),set |_layer,_value,name| read_only(http_schema(),name)},
            "headers" => {kind:List,derived:false,required:false,description:"Ordered header names and exact values",children: HEADER_FIELDS,get |layer| Some(FieldValue::List(layer.head.headers.iter().map(|h|FieldValue::Object(BTreeMap::from([("name".to_owned(),FieldValue::Text(h.name.clone())),("value".to_owned(),FieldValue::Bytes(h.value.clone()))]))).collect())),set |_layer,_value,name| read_only(http_schema(),name)},
    }
    layout pub(crate) fn http_layout();
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HttpCodec;
impl LayerCodec for HttpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &http_schema().protocol
    }
    fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
        matches!(protocol.as_str(), NAME | "raw")
    }
    fn published_schema(&self) -> Option<&'static crate::layer::Schema> {
        Some(http_schema())
    }
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Http>(NAME, layer)?;
        ensure_encode_budget(NAME, layer.head.wire().len(), context)?;
        Ok(
            EncodedLayer::header(layer.head.wire().to_vec(), Box::new(layer.clone()))
                .with_fields(http_layout()),
        )
    }
    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Ok(Some((head, consumed))) = parse_head(&input) else {
            let mut raw = DecodedLayer::terminal(Box::new(Raw::new(input.clone())), input.len());
            raw.fields = raw_layout(input.len());
            return Ok(raw);
        };
        Ok(DecodedLayer {
            layer: Box::new(Http { head }),
            consumed,
            payload_len: input.len() - consumed,
            next: if consumed < input.len() {
                vec![Discriminator(0)]
            } else {
                Vec::new()
            },
            fields: http_layout(),
            diagnostics: Vec::new(),
            stop: false,
            network: None,
        })
    }
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        let Some(FieldValue::Bytes(wire)) = fields.get("wire") else {
            return Err(invalid(
                NAME,
                "HTTP/1 dissection requires retained header wire",
            ));
        };
        let mut layer = Http::try_from(wire.as_ref())?;
        for (name, value) in fields {
            if layer.field(name).as_ref() != Some(value) {
                layer.set_field(name, value.clone())?;
            }
        }
        Ok(Box::new(layer))
    }
}
