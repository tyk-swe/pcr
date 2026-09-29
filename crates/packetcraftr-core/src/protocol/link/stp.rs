// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Configuration, topology-change and rapid spanning-tree BPDUs.
use crate::protocol::common::{ensure_encode_budget, invalid, make_layer, protocol, typed_layer};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Layer, reflective_layer},
};
use bytes::Bytes;
use std::collections::BTreeMap;
const NAME: &str = "stp";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stp {
    pub version: u8,
    pub bpdu_type: u8,
    pub flags: u8,
    pub root_id: u64,
    pub root_path_cost: u32,
    pub bridge_id: u64,
    pub port_id: u16,
    pub message_age: u16,
    pub max_age: u16,
    pub hello_time: u16,
    pub forward_delay: u16,
    pub version1_length: u8,
    pub trailing: Bytes,
}
impl Default for Stp {
    fn default() -> Self {
        Self {
            version: 0,
            bpdu_type: 0,
            flags: 0,
            root_id: 0,
            root_path_cost: 0,
            bridge_id: 0,
            port_id: 0,
            message_age: 0,
            max_age: 20 * 256,
            hello_time: 2 * 256,
            forward_delay: 15 * 256,
            version1_length: 0,
            trailing: Bytes::new(),
        }
    }
}
impl Stp {
    pub fn topology_change() -> Self {
        Self {
            bpdu_type: 128,
            ..Self::default()
        }
    }
    pub fn rapid() -> Self {
        Self {
            version: 2,
            bpdu_type: 2,
            ..Self::default()
        }
    }
}
reflective_layer! {
    fn stp_schema()=>{protocol:protocol(NAME),name:"STP/RSTP"}
    impl Stp {
        "version"=>{kind:Unsigned,derived:false,required:false,description:"Protocol version",reflect:version,layout:(2,3)},
        "bpdu_type"=>{kind:Unsigned,derived:false,required:false,description:"Configuration (0), TCN (128), RSTP (2)",reflect:bpdu_type,layout:(3,4)},
        "flags"=>{kind:Unsigned,derived:false,required:false,description:"BPDU flags",get |layer|(layer.bpdu_type!=128).then(||FieldValue::Unsigned(u64::from(layer.flags))),set |layer,value,name|crate::layer::reflect_set(&mut layer.flags,stp_schema(),name,value)},
        "root_id"=>{kind:Unsigned,derived:false,required:false,description:"Root bridge identifier",get |layer|(layer.bpdu_type!=128).then(||FieldValue::Unsigned(layer.root_id)),set |layer,value,name|crate::layer::reflect_set(&mut layer.root_id,stp_schema(),name,value)},
        "root_path_cost"=>{kind:Unsigned,derived:false,required:false,description:"Path cost",get |layer|(layer.bpdu_type!=128).then(||FieldValue::Unsigned(u64::from(layer.root_path_cost))),set |layer,value,name|crate::layer::reflect_set(&mut layer.root_path_cost,stp_schema(),name,value)},
        "bridge_id"=>{kind:Unsigned,derived:false,required:false,description:"Bridge identifier",get |layer|(layer.bpdu_type!=128).then(||FieldValue::Unsigned(layer.bridge_id)),set |layer,value,name|crate::layer::reflect_set(&mut layer.bridge_id,stp_schema(),name,value)},
        "port_id"=>{kind:Unsigned,derived:false,required:false,description:"Port identifier",get |layer|(layer.bpdu_type!=128).then(||FieldValue::Unsigned(u64::from(layer.port_id))),set |layer,value,name|crate::layer::reflect_set(&mut layer.port_id,stp_schema(),name,value)},
        "message_age"=>{kind:Unsigned,derived:false,required:false,description:"Age in 1/256 seconds",get |layer|(layer.bpdu_type!=128).then(||FieldValue::Unsigned(u64::from(layer.message_age))),set |layer,value,name|crate::layer::reflect_set(&mut layer.message_age,stp_schema(),name,value)},
        "max_age"=>{kind:Unsigned,derived:false,required:false,description:"Maximum age in 1/256 seconds",get |layer|(layer.bpdu_type!=128).then(||FieldValue::Unsigned(u64::from(layer.max_age))),set |layer,value,name|crate::layer::reflect_set(&mut layer.max_age,stp_schema(),name,value)},
        "hello_time"=>{kind:Unsigned,derived:false,required:false,description:"Hello interval in 1/256 seconds",get |layer|(layer.bpdu_type!=128).then(||FieldValue::Unsigned(u64::from(layer.hello_time))),set |layer,value,name|crate::layer::reflect_set(&mut layer.hello_time,stp_schema(),name,value)},
        "forward_delay"=>{kind:Unsigned,derived:false,required:false,description:"Forward delay in 1/256 seconds",get |layer|(layer.bpdu_type!=128).then(||FieldValue::Unsigned(u64::from(layer.forward_delay))),set |layer,value,name|crate::layer::reflect_set(&mut layer.forward_delay,stp_schema(),name,value)},
        "version1_length"=>{kind:Unsigned,derived:false,required:false,description:"RSTP version-1 length",get |layer|(layer.version==2 && layer.bpdu_type==2).then(||FieldValue::Unsigned(u64::from(layer.version1_length))),set |layer,value,name|crate::layer::reflect_set(&mut layer.version1_length,stp_schema(),name,value)},
        "trailing"=>{kind:Bytes,derived:false,required:false,description:"Exact trailing bytes",reflect:trailing},
    }
    layout fn stp_layout();
}
fn size(layer: &Stp) -> Result<usize, crate::codec::Error> {
    match (layer.version, layer.bpdu_type) {
        (0, 128) => Ok(4),
        (0, 0) => Ok(35),
        (2, 2) if layer.version1_length == 0 => Ok(36),
        _ => Err(invalid(
            NAME,
            "unsupported BPDU version/type or RSTP version-1 length",
        )),
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StpCodec;
impl LayerCodec for StpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &stp_schema().protocol
    }
    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        if !payload.is_empty() {
            return Err(invalid(NAME, "BPDU is a complete LLC payload"));
        }
        let layer = typed_layer::<Stp>(NAME, layer)?;
        let len = size(layer)? + layer.trailing.len();
        ensure_encode_budget(NAME, len, context)?;
        let mut wire = vec![0, 0, layer.version, layer.bpdu_type];
        if layer.bpdu_type != 128 {
            wire.push(layer.flags);
            wire.extend_from_slice(&layer.root_id.to_be_bytes());
            wire.extend_from_slice(&layer.root_path_cost.to_be_bytes());
            wire.extend_from_slice(&layer.bridge_id.to_be_bytes());
            for v in [
                layer.port_id,
                layer.message_age,
                layer.max_age,
                layer.hello_time,
                layer.forward_delay,
            ] {
                wire.extend_from_slice(&v.to_be_bytes());
            }
            if layer.version == 2 {
                wire.push(layer.version1_length);
            }
        }
        wire.extend_from_slice(&layer.trailing);
        Ok(EncodedLayer::header(wire, Box::new(layer.clone())).with_fields(stp_layout()))
    }
    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        if input.len() < 4 || input[..2] != [0, 0] {
            return Err(invalid(
                NAME,
                "truncated BPDU or nonzero protocol identifier",
            ));
        }
        let mut layer = Stp {
            version: input[2],
            bpdu_type: input[3],
            ..Stp::default()
        };
        let len = size(&layer)?;
        if input.len() < len {
            return Err(invalid(NAME, "truncated BPDU"));
        }
        if layer.bpdu_type != 128 {
            layer.flags = input[4];
            layer.root_id = u64::from_be_bytes(input[5..13].try_into().unwrap());
            layer.root_path_cost = u32::from_be_bytes(input[13..17].try_into().unwrap());
            layer.bridge_id = u64::from_be_bytes(input[17..25].try_into().unwrap());
            layer.port_id = u16::from_be_bytes(input[25..27].try_into().unwrap());
            layer.message_age = u16::from_be_bytes(input[27..29].try_into().unwrap());
            layer.max_age = u16::from_be_bytes(input[29..31].try_into().unwrap());
            layer.hello_time = u16::from_be_bytes(input[31..33].try_into().unwrap());
            layer.forward_delay = u16::from_be_bytes(input[33..35].try_into().unwrap());
            if layer.version == 2 {
                layer.version1_length = input[35];
            }
        }
        size(&layer)?;
        layer.trailing = input.slice(len..);
        Ok(DecodedLayer {
            layer: Box::new(layer),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: stp_layout(),
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        })
    }
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Stp::default(), fields)
    }
}
