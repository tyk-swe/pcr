// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RTP v2 headers with exact extension, payload and padding bytes.
use crate::protocol::common::{
    ensure_encode_budget, invalid, make_layer, protocol, structured, typed_layer,
};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::{self, FieldValue},
    layer::{Layer, reflective_layer},
};
use bytes::Bytes;
use std::collections::BTreeMap;
const NAME: &str = "rtp";
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rtp {
    pub marker: bool,
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrcs: Vec<u32>,
    pub extension_present: bool,
    pub extension_profile: u16,
    pub extension: Bytes,
    pub payload: Bytes,
    pub padding: Bytes,
}
impl Rtp {
    fn set_csrcs(&mut self, value: FieldValue, name: &str) -> Result<(), field::Error> {
        let values = structured::list(value, 15, rtp_schema(), name)?;
        let mut csrcs = Vec::new();
        for value in values {
            let mut id = 0u32;
            crate::layer::reflect_set(&mut id, rtp_schema(), name, value)?;
            csrcs.push(id);
        }
        self.csrcs = csrcs;
        Ok(())
    }
}
reflective_layer! {
    fn rtp_schema()=>{protocol:protocol(NAME),name:"RTP"}
    impl Rtp {
        "marker"=>{kind:Bool,derived:false,required:false,description:"Marker bit",reflect:marker},
        "payload_type"=>{kind:Unsigned,derived:false,required:false,description:"Seven-bit payload type",reflect_bounded:payload_type,127_u64},
        "sequence"=>{kind:Unsigned,derived:false,required:false,description:"Sequence number",reflect:sequence,layout:(2,4)},
        "timestamp"=>{kind:Unsigned,derived:false,required:false,description:"RTP clock timestamp",reflect:timestamp,layout:(4,8)},
        "ssrc"=>{kind:Unsigned,derived:false,required:false,description:"Synchronization source",reflect:ssrc,layout:(8,12)},
        "csrcs"=>{kind:List,derived:false,required:false,description:"Contributing sources",get |layer|Some(FieldValue::List(layer.csrcs.iter().map(|id|FieldValue::Unsigned(u64::from(*id))).collect())),set |layer,value,name|layer.set_csrcs(value,name)},
        "extension_present"=>{kind:Bool,derived:false,required:false,description:"Extension bit including zero-length extensions",reflect:extension_present},
        "extension_profile"=>{kind:Unsigned,derived:false,required:false,description:"Extension profile identifier",get |layer|(layer.extension_present).then(||FieldValue::Unsigned(u64::from(layer.extension_profile))),set |layer,value,name|crate::layer::reflect_set(&mut layer.extension_profile,rtp_schema(),name,value)},
        "extension"=>{kind:Bytes,derived:false,required:false,description:"Exact word-aligned extension data",get |layer|(layer.extension_present).then(||FieldValue::Bytes(layer.extension.clone())),set |layer,value,name|crate::layer::reflect_set(&mut layer.extension,rtp_schema(),name,value)},
        "payload"=>{kind:Bytes,derived:false,required:false,description:"Exact media payload",reflect:payload},
        "padding"=>{kind:Bytes,derived:false,required:false,description:"Exact padding including final length octet",get |layer|(!layer.padding.is_empty()).then(||FieldValue::Bytes(layer.padding.clone())),set |layer,value,name|crate::layer::reflect_set(&mut layer.padding,rtp_schema(),name,value)},
    }
    layout fn rtp_layout();
}
fn wire(layer: &Rtp) -> Result<Vec<u8>, crate::codec::Error> {
    if layer.payload_type > 127
        || layer.csrcs.len() > 15
        || !layer.extension.len().is_multiple_of(4)
        || layer.extension.len() / 4 > 65535
        || !layer.extension_present && !layer.extension.is_empty()
        || !layer.padding.is_empty()
            && (layer.padding.len() > 255
                || layer.padding.last().copied() != Some(layer.padding.len() as u8))
    {
        return Err(invalid(
            NAME,
            "invalid payload type, CSRCs, extension or padding",
        ));
    }
    let mut wire = vec![
        0x80 | u8::from(!layer.padding.is_empty()) << 5
            | u8::from(layer.extension_present) << 4
            | layer.csrcs.len() as u8,
        u8::from(layer.marker) << 7 | layer.payload_type,
    ];
    wire.extend_from_slice(&layer.sequence.to_be_bytes());
    wire.extend_from_slice(&layer.timestamp.to_be_bytes());
    wire.extend_from_slice(&layer.ssrc.to_be_bytes());
    for csrc in &layer.csrcs {
        wire.extend_from_slice(&csrc.to_be_bytes());
    }
    if layer.extension_present {
        wire.extend_from_slice(&layer.extension_profile.to_be_bytes());
        wire.extend_from_slice(&((layer.extension.len() / 4) as u16).to_be_bytes());
        wire.extend_from_slice(&layer.extension);
    }
    wire.extend_from_slice(&layer.payload);
    wire.extend_from_slice(&layer.padding);
    Ok(wire)
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RtpCodec;
impl LayerCodec for RtpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &rtp_schema().protocol
    }
    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        if !payload.is_empty() {
            return Err(invalid(NAME, "RTP is a complete UDP payload"));
        }
        let layer = typed_layer::<Rtp>(NAME, layer)?;
        let contribution = [
            12,
            layer.csrcs.len().saturating_mul(4),
            usize::from(layer.extension_present) * 4,
            layer.extension.len(),
            layer.payload.len(),
            layer.padding.len(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or_else(|| invalid(NAME, "message length overflow"))?;
        ensure_encode_budget(NAME, contribution, context)?;
        let wire = wire(layer)?;
        Ok(EncodedLayer::header(wire, Box::new(layer.clone())).with_fields(rtp_layout()))
    }
    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        if input.len() < 12 || input[0] >> 6 != 2 {
            return Err(invalid(NAME, "truncated or non-v2 RTP header"));
        }
        let mut layer = Rtp {
            marker: input[1] & 128 != 0,
            payload_type: input[1] & 127,
            sequence: u16::from_be_bytes(input[2..4].try_into().unwrap()),
            timestamp: u32::from_be_bytes(input[4..8].try_into().unwrap()),
            ssrc: u32::from_be_bytes(input[8..12].try_into().unwrap()),
            extension_present: input[0] & 16 != 0,
            ..Rtp::default()
        };
        let count = usize::from(input[0] & 15);
        let mut index = 12 + 4 * count;
        if input.len() < index {
            return Err(invalid(NAME, "truncated CSRC list"));
        }
        for csrc in input[12..index].as_chunks::<4>().0 {
            layer.csrcs.push(u32::from_be_bytes(*csrc));
        }
        if layer.extension_present {
            if input.len() < index + 4 {
                return Err(invalid(NAME, "truncated extension header"));
            }
            layer.extension_profile =
                u16::from_be_bytes(input[index..index + 2].try_into().unwrap());
            let words = usize::from(u16::from_be_bytes(
                input[index + 2..index + 4].try_into().unwrap(),
            ));
            index += 4;
            let end = index + words * 4;
            if input.len() < end {
                return Err(invalid(NAME, "truncated extension"));
            }
            layer.extension = input.slice(index..end);
            index = end;
        }
        let padding = if input[0] & 32 != 0 {
            let count = usize::from(*input.last().unwrap());
            if count == 0 || count > input.len() - index {
                return Err(invalid(NAME, "invalid padding length"));
            }
            count
        } else {
            0
        };
        let end = input.len() - padding;
        layer.payload = input.slice(index..end);
        layer.padding = input.slice(end..);
        Ok(DecodedLayer {
            layer: Box::new(layer),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: rtp_layout(),
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        })
    }
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Rtp::default(), fields)
    }
}
