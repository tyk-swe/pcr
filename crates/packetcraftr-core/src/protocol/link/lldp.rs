// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IEEE 802.1AB LLDP TLVs, including exact unknown values.
use crate::protocol::common::{
    ensure_encode_budget, invalid, protocol,
    structured::{self, Object},
    typed_layer,
};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::{self, FieldValue},
    layer::{Layer, reflective_layer},
    registry::Discriminator,
};
use bytes::Bytes;
use std::collections::BTreeMap;
const NAME: &str = "lldp";
pub const MAX_TLVS: usize = 256;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tlv {
    pub kind: u8,
    pub value: Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lldp {
    pub tlvs: Vec<Tlv>,
}
impl Default for Lldp {
    fn default() -> Self {
        Self::new(
            7,
            Bytes::from_static(b"chassis"),
            7,
            Bytes::from_static(b"port"),
            120,
        )
    }
}
impl Lldp {
    /// Creates the three mandatory TLVs. End-of-LLDP is supplied by the encoder.
    pub fn new(
        chassis_subtype: u8,
        chassis: Bytes,
        port_subtype: u8,
        port: Bytes,
        ttl: u16,
    ) -> Self {
        let mut c = vec![chassis_subtype];
        c.extend_from_slice(&chassis);
        let mut p = vec![port_subtype];
        p.extend_from_slice(&port);
        Self {
            tlvs: vec![
                Tlv {
                    kind: 1,
                    value: c.into(),
                },
                Tlv {
                    kind: 2,
                    value: p.into(),
                },
                Tlv {
                    kind: 3,
                    value: Bytes::copy_from_slice(&ttl.to_be_bytes()),
                },
            ],
        }
    }
    pub fn ttl(&self) -> Option<u16> {
        self.tlvs
            .iter()
            .find(|tlv| tlv.kind == 3)
            .and_then(|tlv| tlv.value.as_ref().try_into().ok())
            .map(u16::from_be_bytes)
    }
    fn set_tlvs(&mut self, value: FieldValue, name: &str) -> Result<(), field::Error> {
        let values = structured::list(value, MAX_TLVS, lldp_schema(), name)?;
        let mut tlvs = Vec::new();
        for value in values {
            let mut obj = Object::new(value, lldp_schema(), name)?;
            tlvs.push(Tlv {
                kind: obj.required_value("kind")?,
                value: obj.required_value("value")?,
            });
            obj.finish()?;
        }
        self.tlvs = tlvs;
        Ok(())
    }
}
const TLV_FIELDS: &[crate::layer::FieldSchema] = &[
    structured::member("kind", crate::field::FieldKind::Unsigned, &[]),
    structured::member("value", crate::field::FieldKind::Bytes, &[]),
];
reflective_layer! {
    fn lldp_schema()=>{protocol:protocol(NAME),name:"LLDP"}
    impl Lldp {
        "tlvs"=>{kind:List,derived:false,required:false,description:"Ordered TLVs excluding the terminator",children:TLV_FIELDS,get |layer| Some(FieldValue::List(layer.tlvs.iter().map(|tlv|structured::object([("kind",FieldValue::Unsigned(u64::from(tlv.kind))),("value",FieldValue::Bytes(tlv.value.clone()))])).collect())),set |layer,value,name|layer.set_tlvs(value,name)},
        "ttl"=>{kind:Unsigned,derived:true,required:false,description:"Advertised lifetime in seconds",get |layer|layer.ttl().map(|ttl|FieldValue::Unsigned(u64::from(ttl))),set |_layer,_value,name|crate::protocol::common::read_only(lldp_schema(),name)},
    }
    layout fn lldp_layout();
}
fn validate(tlvs: &[Tlv]) -> Result<(), crate::codec::Error> {
    if !(3..=MAX_TLVS).contains(&tlvs.len()) || tlvs[..3].iter().map(|t| t.kind).ne([1, 2, 3]) {
        return Err(invalid(
            NAME,
            "requires ordered chassis ID, port ID and TTL TLVs within 256 TLVs",
        ));
    }
    for (index, tlv) in tlvs.iter().enumerate() {
        if tlv.kind == 0 || tlv.kind > 127 || tlv.value.len() > 511 {
            return Err(invalid(NAME, "invalid TLV kind or nine-bit length"));
        }
        if index >= 3 && matches!(tlv.kind, 1..=3) {
            return Err(invalid(NAME, "mandatory TLV is repeated"));
        }
        let valid = match tlv.kind {
            1 | 2 => {
                (2..=256).contains(&tlv.value.len())
                    && matches!(tlv.value[0], 1..=7)
                    && (!(tlv.kind == 1 && tlv.value[0] == 4 || tlv.kind == 2 && tlv.value[0] == 3)
                        || tlv.value.len() == 7)
            }
            3 => tlv.value.len() == 2,
            4..=6 => tlv.value.len() <= 255,
            7 => tlv.value.len() == 4,
            8 => {
                let value = &tlv.value;
                value.first().is_some_and(|length| {
                    (2..=31).contains(length)
                        && usize::from(*length) + 7 <= value.len()
                        && value[usize::from(*length) + 6] as usize + usize::from(*length) + 7
                            == value.len()
                })
            }
            127 => tlv.value.len() >= 4,
            _ => true,
        };
        if !valid {
            return Err(invalid(NAME, "malformed common TLV"));
        }
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LldpCodec;
impl LayerCodec for LldpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &lldp_schema().protocol
    }
    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        if !payload.is_empty()
            && context
                .child
                .is_some_and(|c| c.protocol_id().as_str() != "padding")
        {
            return Err(invalid(NAME, "LLDP only permits trailing padding"));
        }
        let layer = typed_layer::<Lldp>(NAME, layer)?;
        validate(&layer.tlvs)?;
        let length = layer
            .tlvs
            .iter()
            .map(|tlv| tlv.value.len() + 2)
            .sum::<usize>()
            + 2;
        ensure_encode_budget(NAME, length, context)?;
        let mut wire = Vec::with_capacity(length);
        for tlv in &layer.tlvs {
            wire.extend_from_slice(
                &((u16::from(tlv.kind) << 9) | tlv.value.len() as u16).to_be_bytes(),
            );
            wire.extend_from_slice(&tlv.value);
        }
        wire.extend_from_slice(&[0, 0]);
        Ok(EncodedLayer::header(wire, Box::new(layer.clone())).with_fields(lldp_layout()))
    }
    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let mut index = 0;
        let mut tlvs = Vec::new();
        loop {
            let head = input
                .get(index..index + 2)
                .ok_or_else(|| invalid(NAME, "truncated TLV header or missing terminator"))?;
            let h = u16::from_be_bytes([head[0], head[1]]);
            index += 2;
            let kind = (h >> 9) as u8;
            let len = usize::from(h & 511);
            if kind == 0 {
                if len != 0 {
                    return Err(invalid(NAME, "terminator has a value"));
                }
                break;
            }
            if tlvs.len() >= MAX_TLVS {
                return Err(invalid(NAME, "exceeds 256 TLVs"));
            }
            let end = index + len;
            if end > input.len() {
                return Err(invalid(NAME, "truncated TLV value"));
            }
            tlvs.push(Tlv {
                kind,
                value: input.slice(index..end),
            });
            index = end;
        }
        validate(&tlvs)?;
        Ok(DecodedLayer {
            layer: Box::new(Lldp { tlvs }),
            consumed: index,
            payload_len: input.len() - index,
            next: vec![Discriminator(0)],
            fields: lldp_layout(),
            diagnostics: Vec::new(),
            stop: index == input.len(),
            network: None,
        })
    }
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        let mut layer = Lldp::default();
        for (name, value) in fields {
            if !lldp_schema()
                .fields
                .iter()
                .any(|field| field.name == name && field.derived)
            {
                layer.set_field(name, value.clone())?;
            }
        }
        for (name, value) in fields {
            if layer.field(name).as_ref() != Some(value) {
                layer.set_field(name, value.clone())?;
            }
        }
        Ok(Box::new(layer))
    }
}
