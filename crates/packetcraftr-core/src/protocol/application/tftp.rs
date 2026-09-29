// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RFC 1350 messages and RFC 2347 option negotiation.
use crate::protocol::common::{
    ensure_encode_budget, invalid, make_layer, protocol,
    structured::{self, Object},
    typed_layer,
};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::{self, FieldValue},
    layer::{Layer, reflective_layer},
};
use bytes::Bytes;
use std::collections::BTreeMap;
const NAME: &str = "tftp";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionPair {
    pub name: Bytes,
    pub value: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tftp {
    pub opcode: u16,
    pub filename: Bytes,
    pub mode: Bytes,
    pub options: Vec<OptionPair>,
    pub block: u16,
    pub data: Bytes,
    pub error_code: u16,
    pub error_message: Bytes,
}
impl Default for Tftp {
    fn default() -> Self {
        Self {
            opcode: 1,
            filename: Bytes::from_static(b"file"),
            mode: Bytes::from_static(b"octet"),
            options: Vec::new(),
            block: 0,
            data: Bytes::new(),
            error_code: 0,
            error_message: Bytes::new(),
        }
    }
}
impl Tftp {
    pub fn data(block: u16, data: Bytes) -> Self {
        Self {
            opcode: 3,
            block,
            data,
            ..Self::default()
        }
    }
    pub fn ack(block: u16) -> Self {
        Self {
            opcode: 4,
            block,
            ..Self::default()
        }
    }
    fn set_options(&mut self, value: FieldValue, name: &str) -> Result<(), field::Error> {
        let values = structured::list(value, 256, tftp_schema(), name)?;
        let mut options = Vec::new();
        for value in values {
            let mut obj = Object::new(value, tftp_schema(), name)?;
            options.push(OptionPair {
                name: obj.required_value("name")?,
                value: obj.required_value("value")?,
            });
            obj.finish()?;
        }
        self.options = options;
        Ok(())
    }
}
const OPTION_FIELDS: &[crate::layer::FieldSchema] = &[
    structured::member("name", crate::field::FieldKind::Bytes, &[]),
    structured::member("value", crate::field::FieldKind::Bytes, &[]),
];
reflective_layer! {
    fn tftp_schema()=>{protocol:protocol(NAME),name:"TFTP"}
    impl Tftp {
        "opcode"=>{kind:Unsigned,derived:false,required:false,description:"RRQ/WRQ/DATA/ACK/ERROR/OACK opcode",reflect:opcode,layout:(0,2)},
        "filename"=>{kind:Bytes,derived:false,required:false,description:"Exact requested filename",get |layer|(matches!(layer.opcode,1|2)).then(||FieldValue::Bytes(layer.filename.clone())),set |layer,value,name|crate::layer::reflect_set(&mut layer.filename,tftp_schema(),name,value)},
        "mode"=>{kind:Bytes,derived:false,required:false,description:"Exact transfer mode",get |layer|(matches!(layer.opcode,1|2)).then(||FieldValue::Bytes(layer.mode.clone())),set |layer,value,name|crate::layer::reflect_set(&mut layer.mode,tftp_schema(),name,value)},
        "options"=>{kind:List,derived:false,required:false,description:"Ordered option pairs",children:OPTION_FIELDS,get |layer|matches!(layer.opcode,1|2|6).then(||FieldValue::List(layer.options.iter().map(|option|structured::object([("name",FieldValue::Bytes(option.name.clone())),("value",FieldValue::Bytes(option.value.clone()))])).collect())),set |layer,value,name|layer.set_options(value,name)},
        "block"=>{kind:Unsigned,derived:false,required:false,description:"Block number",get |layer|(matches!(layer.opcode,3|4)).then(||FieldValue::Unsigned(u64::from(layer.block))),set |layer,value,name|crate::layer::reflect_set(&mut layer.block,tftp_schema(),name,value)},
        "data"=>{kind:Bytes,derived:false,required:false,description:"Exact DATA payload",get |layer|(layer.opcode==3).then(||FieldValue::Bytes(layer.data.clone())),set |layer,value,name|crate::layer::reflect_set(&mut layer.data,tftp_schema(),name,value)},
        "error_code"=>{kind:Unsigned,derived:false,required:false,description:"Error code",get |layer|(layer.opcode==5).then(||FieldValue::Unsigned(u64::from(layer.error_code))),set |layer,value,name|crate::layer::reflect_set(&mut layer.error_code,tftp_schema(),name,value)},
        "error_message"=>{kind:Bytes,derived:false,required:false,description:"Exact error description",get |layer|(layer.opcode==5).then(||FieldValue::Bytes(layer.error_message.clone())),set |layer,value,name|crate::layer::reflect_set(&mut layer.error_message,tftp_schema(),name,value)},
    }
    layout fn tftp_layout();
}
fn terminated(wire: &mut Vec<u8>, value: &[u8], empty: bool) -> Result<(), crate::codec::Error> {
    if (!empty && value.is_empty()) || value.contains(&0) {
        return Err(invalid(NAME, "invalid zero-terminated string"));
    }
    wire.extend_from_slice(value);
    wire.push(0);
    Ok(())
}
fn wire(layer: &Tftp) -> Result<Vec<u8>, crate::codec::Error> {
    let mut wire = layer.opcode.to_be_bytes().to_vec();
    match layer.opcode {
        1 | 2 => {
            terminated(&mut wire, &layer.filename, false)?;
            terminated(&mut wire, &layer.mode, false)?;
        }
        3 => {
            wire.extend_from_slice(&layer.block.to_be_bytes());
            wire.extend_from_slice(&layer.data);
        }
        4 => wire.extend_from_slice(&layer.block.to_be_bytes()),
        5 => {
            wire.extend_from_slice(&layer.error_code.to_be_bytes());
            terminated(&mut wire, &layer.error_message, true)?;
        }
        6 => {}
        _ => return Err(invalid(NAME, "unknown opcode")),
    }
    if matches!(layer.opcode, 1 | 2 | 6) {
        if layer.options.len() > 256 || layer.opcode == 6 && layer.options.is_empty() {
            return Err(invalid(NAME, "invalid option count"));
        }
        for option in &layer.options {
            terminated(&mut wire, &option.name, false)?;
            terminated(&mut wire, &option.value, false)?;
        }
    }
    Ok(wire)
}
fn string(input: &Bytes, index: &mut usize) -> Result<Bytes, crate::codec::Error> {
    let len = input[*index..]
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| invalid(NAME, "unterminated string"))?;
    let value = input.slice(*index..*index + len);
    *index += len + 1;
    Ok(value)
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TftpCodec;
impl LayerCodec for TftpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &tftp_schema().protocol
    }
    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        if !payload.is_empty() {
            return Err(invalid(NAME, "TFTP is a complete UDP payload"));
        }
        let layer = typed_layer::<Tftp>(NAME, layer)?;
        if layer.options.len() > 256 {
            return Err(invalid(NAME, "exceeds 256 options"));
        }
        let mut contribution = match layer.opcode {
            1 | 2 => layer
                .filename
                .len()
                .saturating_add(layer.mode.len())
                .saturating_add(4),
            3 => layer.data.len().saturating_add(4),
            4 => 4,
            5 => layer.error_message.len().saturating_add(5),
            _ => 2,
        };
        if matches!(layer.opcode, 1 | 2 | 6) {
            for option in &layer.options {
                contribution = contribution
                    .saturating_add(option.name.len())
                    .saturating_add(option.value.len())
                    .saturating_add(2);
            }
        }
        ensure_encode_budget(NAME, contribution, context)?;
        let wire = wire(layer)?;
        Ok(EncodedLayer::header(wire, Box::new(layer.clone())).with_fields(tftp_layout()))
    }
    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        if input.len() < 2 {
            return Err(invalid(NAME, "truncated opcode"));
        }
        let mut layer = Tftp {
            opcode: u16::from_be_bytes([input[0], input[1]]),
            ..Tftp::default()
        };
        let mut index = 2;
        match layer.opcode {
            1 | 2 => {
                layer.filename = string(&input, &mut index)?;
                layer.mode = string(&input, &mut index)?;
            }
            3..=5 => {
                if input.len() < 4 {
                    return Err(invalid(NAME, "truncated block or error code"));
                }
                let value = u16::from_be_bytes([input[2], input[3]]);
                index = 4;
                match layer.opcode {
                    3 => {
                        layer.block = value;
                        layer.data = input.slice(4..);
                        index = input.len();
                    }
                    4 => layer.block = value,
                    _ => {
                        layer.error_code = value;
                        layer.error_message = string(&input, &mut index)?;
                    }
                }
            }
            6 => {}
            _ => return Err(invalid(NAME, "unknown opcode")),
        }
        if matches!(layer.opcode, 1 | 2 | 6) {
            while index < input.len() {
                if layer.options.len() >= 256 {
                    return Err(invalid(NAME, "exceeds 256 options"));
                }
                layer.options.push(OptionPair {
                    name: string(&input, &mut index)?,
                    value: string(&input, &mut index)?,
                });
            }
        }
        if index != input.len() {
            return Err(invalid(NAME, "unexpected trailing bytes"));
        }
        wire(&layer)?;
        Ok(DecodedLayer {
            layer: Box::new(layer),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: tftp_layout(),
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        })
    }
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Tftp::default(), fields)
    }
}
