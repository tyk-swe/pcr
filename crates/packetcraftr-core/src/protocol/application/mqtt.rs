// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! MQTT 3.1.1 control packets; TCP stream reassembly is intentionally external.
use crate::protocol::common::{ensure_encode_budget, invalid, protocol, read_only, typed_layer};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Layer, Raw, reflective_layer},
    registry::Discriminator,
};
use bytes::Bytes;
use std::collections::BTreeMap;
const NAME: &str = "mqtt";
pub const MAX_PACKET_BYTES: usize = 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mqtt {
    pub packet_type: u8,
    pub flags: u8,
    pub body: Bytes,
}
impl Default for Mqtt {
    fn default() -> Self {
        Self {
            packet_type: 12,
            flags: 0,
            body: Bytes::new(),
        }
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fields {
    pub topic: Option<Bytes>,
    pub packet_id: Option<u16>,
    pub payload: Option<Bytes>,
    pub client_id: Option<Bytes>,
}
fn utf8(value: &[u8]) -> Result<(), crate::codec::Error> {
    let text = std::str::from_utf8(value).map_err(|_| invalid(NAME, "invalid MQTT UTF-8"))?;
    if text.chars().any(|c| {
        c == '\0' || (0xfdd0..=0xfdef).contains(&(c as u32)) || c as u32 & 0xffff >= 0xfffe
    }) {
        return Err(invalid(NAME, "forbidden MQTT UTF-8 code point"));
    }
    Ok(())
}
fn string(wire: &mut Vec<u8>, value: &[u8]) -> Result<(), crate::codec::Error> {
    utf8(value)?;
    let len =
        u16::try_from(value.len()).map_err(|_| invalid(NAME, "string exceeds 65535 bytes"))?;
    wire.extend_from_slice(&len.to_be_bytes());
    wire.extend_from_slice(value);
    Ok(())
}
struct Cursor<'a> {
    body: &'a Bytes,
    index: usize,
}
impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8, crate::codec::Error> {
        let value = *self
            .body
            .get(self.index)
            .ok_or_else(|| invalid(NAME, "truncated control packet"))?;
        self.index += 1;
        Ok(value)
    }
    fn word(&mut self) -> Result<u16, crate::codec::Error> {
        Ok(u16::from_be_bytes([self.byte()?, self.byte()?]))
    }
    fn bytes(&mut self, len: usize) -> Result<Bytes, crate::codec::Error> {
        let end = self
            .index
            .checked_add(len)
            .filter(|end| *end <= self.body.len())
            .ok_or_else(|| invalid(NAME, "truncated control field"))?;
        let bytes = self.body.slice(self.index..end);
        self.index = end;
        Ok(bytes)
    }
    fn binary(&mut self) -> Result<Bytes, crate::codec::Error> {
        let len = usize::from(self.word()?);
        self.bytes(len)
    }
    fn text(&mut self) -> Result<Bytes, crate::codec::Error> {
        let value = self.binary()?;
        utf8(&value)?;
        Ok(value)
    }
    fn id(&mut self) -> Result<u16, crate::codec::Error> {
        let id = self.word()?;
        if id == 0 {
            return Err(invalid(NAME, "packet identifier is zero"));
        }
        Ok(id)
    }
}
impl Mqtt {
    pub fn connect(client_id: &str, keep_alive: u16) -> Result<Self, crate::codec::Error> {
        let mut body = Vec::new();
        string(&mut body, b"MQTT")?;
        body.extend_from_slice(&[4, 2]);
        body.extend_from_slice(&keep_alive.to_be_bytes());
        string(&mut body, client_id.as_bytes())?;
        Ok(Self {
            packet_type: 1,
            flags: 0,
            body: body.into(),
        })
    }
    pub fn publish(
        topic: &str,
        payload: Bytes,
        qos: u8,
        packet_id: Option<u16>,
        retain: bool,
    ) -> Result<Self, crate::codec::Error> {
        if qos > 2 || qos > 0 && packet_id.is_none_or(|id| id == 0) {
            return Err(invalid(
                NAME,
                "invalid publication QoS or packet identifier",
            ));
        }
        let mut body = Vec::new();
        string(&mut body, topic.as_bytes())?;
        if qos > 0 {
            body.extend_from_slice(&packet_id.unwrap().to_be_bytes());
        }
        body.extend_from_slice(&payload);
        let packet = Self {
            packet_type: 3,
            flags: qos << 1 | u8::from(retain),
            body: body.into(),
        };
        packet.fields()?;
        Ok(packet)
    }
    pub fn acknowledgement(packet_type: u8, packet_id: u16) -> Result<Self, crate::codec::Error> {
        let packet = Self {
            packet_type,
            flags: if packet_type == 6 { 2 } else { 0 },
            body: Bytes::copy_from_slice(&packet_id.to_be_bytes()),
        };
        packet.fields()?;
        Ok(packet)
    }
    pub fn subscribe(packet_id: u16, topics: &[(&str, u8)]) -> Result<Self, crate::codec::Error> {
        let mut body = packet_id.to_be_bytes().to_vec();
        for (topic, qos) in topics {
            string(&mut body, topic.as_bytes())?;
            body.push(*qos);
        }
        let packet = Self {
            packet_type: 8,
            flags: 2,
            body: body.into(),
        };
        packet.fields()?;
        Ok(packet)
    }
    pub fn fields(&self) -> Result<Fields, crate::codec::Error> {
        if !(1..=14).contains(&self.packet_type)
            || self.flags > 15
            || self.body.len() > MAX_PACKET_BYTES
            || self.body.len()
                + 1
                + if self.body.len() < 128 {
                    1
                } else if self.body.len() < 16384 {
                    2
                } else {
                    3
                }
                > MAX_PACKET_BYTES
        {
            return Err(invalid(NAME, "invalid control type, flags or packet size"));
        }
        let expected = if matches!(self.packet_type, 6 | 8 | 10) {
            2
        } else {
            0
        };
        if self.packet_type != 3 && self.flags != expected {
            return Err(invalid(NAME, "invalid fixed-header flags"));
        }
        let mut cursor = Cursor {
            body: &self.body,
            index: 0,
        };
        let mut fields = Fields::default();
        match self.packet_type {
            1 => {
                if cursor.text()?.as_ref() != b"MQTT" || cursor.byte() != Ok(4) {
                    return Err(invalid(NAME, "CONNECT protocol is not MQTT 3.1.1"));
                }
                let flags = cursor.byte()?;
                if flags & 64 != 0 && flags & 128 == 0
                    || flags & 1 != 0
                    || flags & 4 == 0 && flags & 0x38 != 0
                    || (flags >> 3 & 3) == 3
                {
                    return Err(invalid(NAME, "invalid CONNECT flags"));
                }
                cursor.word()?;
                let client = cursor.text()?;
                if client.is_empty() && flags & 2 == 0 {
                    return Err(invalid(NAME, "empty client ID requires clean session"));
                }
                fields.client_id = Some(client);
                if flags & 4 != 0 {
                    let topic = cursor.text()?;
                    if topic.is_empty() || topic.iter().any(|b| matches!(b, b'#' | b'+')) {
                        return Err(invalid(NAME, "invalid will topic"));
                    }
                    cursor.binary()?;
                }
                if flags & 128 != 0 {
                    cursor.text()?;
                }
                if flags & 64 != 0 {
                    cursor.binary()?;
                }
            }
            2 => {
                let flags = cursor.byte()?;
                let code = cursor.byte()?;
                if flags > 1 || code > 5 || code != 0 && flags != 0 {
                    return Err(invalid(NAME, "invalid CONNACK"));
                }
            }
            3 => {
                let qos = self.flags >> 1 & 3;
                if qos == 3 || qos == 0 && self.flags & 8 != 0 {
                    return Err(invalid(NAME, "invalid PUBLISH QoS/DUP"));
                }
                let topic = cursor.text()?;
                if topic.is_empty() || topic.iter().any(|b| matches!(b, b'#' | b'+')) {
                    return Err(invalid(NAME, "invalid publication topic"));
                }
                fields.topic = Some(topic);
                if qos > 0 {
                    fields.packet_id = Some(cursor.id()?);
                }
                fields.payload = Some(self.body.slice(cursor.index..));
                cursor.index = self.body.len();
            }
            4..=7 | 11 => fields.packet_id = Some(cursor.id()?),
            8 | 10 => {
                fields.packet_id = Some(cursor.id()?);
                let mut count = 0;
                while cursor.index < self.body.len() {
                    let topic = cursor.text()?;
                    if topic.is_empty()
                        || topic.split(|byte| *byte == b'/').any(|level| {
                            level.contains(&b'+') && level != b"+"
                                || level.contains(&b'#') && level != b"#"
                        })
                        || topic
                            .iter()
                            .position(|byte| *byte == b'#')
                            .is_some_and(|index| index + 1 != topic.len())
                    {
                        return Err(invalid(NAME, "invalid topic filter"));
                    }
                    if self.packet_type == 8 && cursor.byte()? > 2 {
                        return Err(invalid(NAME, "invalid subscription QoS"));
                    }
                    count += 1;
                }
                if count == 0 {
                    return Err(invalid(NAME, "missing topic filters"));
                }
            }
            9 => {
                fields.packet_id = Some(cursor.id()?);
                let mut count = 0;
                while cursor.index < self.body.len() {
                    if !matches!(cursor.byte()?, 0 | 1 | 2 | 128) {
                        return Err(invalid(NAME, "invalid SUBACK return code"));
                    }
                    count += 1;
                }
                if count == 0 {
                    return Err(invalid(NAME, "missing SUBACK codes"));
                }
            }
            12..=14 => {}
            _ => unreachable!(),
        }
        if cursor.index != self.body.len() {
            return Err(invalid(NAME, "unexpected trailing control bytes"));
        }
        Ok(fields)
    }
}
reflective_layer! {
    fn mqtt_schema()=>{protocol:protocol(NAME),name:"MQTT 3.1.1"}
    impl Mqtt {
        "packet_type"=>{kind:Unsigned,derived:false,required:false,description:"Control packet type (1..14)",reflect:packet_type},
        "flags"=>{kind:Unsigned,derived:false,required:false,description:"Exact fixed-header flag nibble",reflect_bounded:flags,15_u64},
        "body"=>{kind:Bytes,derived:false,required:false,description:"Exact variable header and payload",reflect:body},
        "topic"=>{kind:Bytes,derived:true,required:false,description:"Publication topic",get |layer|layer.fields().ok()?.topic.map(FieldValue::Bytes),set |_layer,_value,name|read_only(mqtt_schema(),name)},
        "packet_id"=>{kind:Unsigned,derived:true,required:false,description:"Packet identifier",get |layer|layer.fields().ok()?.packet_id.map(|id|FieldValue::Unsigned(u64::from(id))),set |_layer,_value,name|read_only(mqtt_schema(),name)},
        "payload"=>{kind:Bytes,derived:true,required:false,description:"Publication payload",get |layer|layer.fields().ok()?.payload.map(FieldValue::Bytes),set |_layer,_value,name|read_only(mqtt_schema(),name)},
        "client_id"=>{kind:Bytes,derived:true,required:false,description:"CONNECT client identifier",get |layer|layer.fields().ok()?.client_id.map(FieldValue::Bytes),set |_layer,_value,name|read_only(mqtt_schema(),name)},
    }
    layout fn mqtt_layout();
}
fn wire(layer: &Mqtt) -> Result<Vec<u8>, crate::codec::Error> {
    layer.fields()?;
    let mut wire = vec![layer.packet_type << 4 | layer.flags];
    let mut remaining = layer.body.len();
    loop {
        let mut byte = (remaining % 128) as u8;
        remaining /= 128;
        if remaining != 0 {
            byte |= 128;
        }
        wire.push(byte);
        if remaining == 0 {
            break;
        }
    }
    wire.extend_from_slice(&layer.body);
    if wire.len() > MAX_PACKET_BYTES {
        return Err(invalid(NAME, "exceeds 1 MiB packet limit"));
    }
    Ok(wire)
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MqttCodec;
impl LayerCodec for MqttCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &mqtt_schema().protocol
    }
    fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
        matches!(protocol.as_str(), NAME | "raw")
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
                .is_none_or(|child| child.protocol_id().as_str() != NAME)
        {
            return Err(invalid(
                NAME,
                "only another complete MQTT packet may follow",
            ));
        }
        let layer = typed_layer::<Mqtt>(NAME, layer)?;
        let wire = wire(layer)?;
        ensure_encode_budget(NAME, wire.len(), context)?;
        Ok(EncodedLayer::header(wire, Box::new(layer.clone())).with_fields(mqtt_layout()))
    }
    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        if input.is_empty() {
            return Ok(Raw::decoded(input));
        }
        let mut length = 0usize;
        let mut index = 1;
        let mut multiplier = 1;
        loop {
            let Some(byte) = input.get(index).copied() else {
                return Ok(Raw::decoded(input));
            };
            index += 1;
            length += usize::from(byte & 127) * multiplier;
            if byte & 128 == 0 {
                if index > 2 && byte == 0 {
                    return Err(invalid(NAME, "noncanonical remaining length"));
                }
                break;
            }
            if index == 5 {
                return Err(invalid(NAME, "remaining length exceeds four bytes"));
            }
            multiplier *= 128;
        }
        let end = index + length;
        if end > MAX_PACKET_BYTES {
            return Err(invalid(NAME, "exceeds 1 MiB packet limit"));
        }
        if end > input.len() {
            return Ok(Raw::decoded(input));
        }
        let layer = Mqtt {
            packet_type: input[0] >> 4,
            flags: input[0] & 15,
            body: input.slice(index..end),
        };
        layer.fields()?;
        Ok(DecodedLayer {
            layer: Box::new(layer),
            consumed: end,
            payload_len: input.len() - end,
            next: if end < input.len() {
                vec![Discriminator(0)]
            } else {
                Vec::new()
            },
            fields: mqtt_layout(),
            diagnostics: Vec::new(),
            stop: end == input.len(),
            network: None,
        })
    }
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        let mut layer = Mqtt::default();
        for (name, value) in fields {
            if !mqtt_schema()
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
