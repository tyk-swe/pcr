// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! MQTT 3.1.1 control packets (OASIS MQTT 3.1.1). MQTT 5 is not inferred.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

const SUBS: &[crate::layer::FieldSchema] = &[
    member("topic", field::Kind::Bytes, &[]),
    member("qos", field::Kind::Unsigned, &[]),
];
use crate::protocol::common::structured::member;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mqtt {
    pub packet_type: u8,
    pub flags: u8,
    pub connect_flags: u8,
    pub keep_alive: u16,
    pub client_id: Bytes,
    pub will_topic: Bytes,
    pub will_payload: Bytes,
    pub user_name: Bytes,
    pub password: Bytes,
    pub topic: Bytes,
    pub packet_id: u16,
    pub session_present: u8,
    pub return_code: u8,
    pub payload: Bytes,
    pub subscriptions: Records,
}
impl Default for Mqtt {
    fn default() -> Self {
        Self {
            packet_type: 12,
            flags: 0,
            connect_flags: 2,
            keep_alive: 60,
            client_id: Bytes::new(),
            will_topic: Bytes::new(),
            will_payload: Bytes::new(),
            user_name: Bytes::new(),
            password: Bytes::new(),
            topic: Bytes::new(),
            packet_id: 1,
            session_present: 0,
            return_code: 0,
            payload: Bytes::new(),
            subscriptions: Records::default(),
        }
    }
}
crate::reflective_layer! {
 fn mqtt_schema() => { protocol: crate::layer::Id::new("mqtt"), name: "Mqtt" }
 impl Mqtt {
    "packet_type" => { kind: Unsigned, derived: false, required: false, description: "MQTT control packet type 1 through 14", reflect: packet_type },
    "flags" => { kind: Unsigned, derived: false, required: false, description: "MQTT fixed header flags", reflect: flags },
    "connect_flags" => { kind: Unsigned, derived: false, required: false, description: "CONNECT flags", reflect: connect_flags },
    "keep_alive" => { kind: Unsigned, derived: false, required: false, description: "Keep-alive interval in seconds", reflect: keep_alive },
    "client_id" => { kind: Bytes, derived: false, required: false, description: "CONNECT client identifier", reflect: client_id },
    "will_topic" => { kind: Bytes, derived: false, required: false, description: "CONNECT will topic", reflect: will_topic },
    "will_payload" => { kind: Bytes, derived: false, required: false, description: "CONNECT will payload", reflect: will_payload },
    "user_name" => { kind: Bytes, derived: false, required: false, description: "CONNECT user name", reflect: user_name },
    "password" => { kind: Bytes, derived: false, required: false, description: "CONNECT password bytes", reflect: password },
    "topic" => { kind: Bytes, derived: false, required: false, description: "PUBLISH topic", reflect: topic },
    "packet_id" => { kind: Unsigned, derived: false, required: false, description: "Packet identifier", reflect: packet_id },
    "session_present" => { kind: Unsigned, derived: false, required: false, description: "CONNACK session-present flag", reflect: session_present },
    "return_code" => { kind: Unsigned, derived: false, required: false, description: "CONNACK return code", reflect: return_code },
    "payload" => { kind: Bytes, derived: false, required: false, description: "PUBLISH data or SUBACK return codes", reflect: payload },
    "subscriptions" => { kind: List, derived: false, required: false, description: "Ordered SUBSCRIBE or UNSUBSCRIBE topics", children: SUBS, reflect: subscriptions },
 }
 layout fn mqtt_layout();
}
fn mqtt_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = mqtt_layout();
    let mut fields = Vec::new();
    if !b.is_empty() {
        fields.push(crate::layout::FieldLayout {
            name: "packet_type",
            range: crate::layout::ByteRange::new(0, 1),
        });
    }
    if !b.is_empty() {
        fields.push(crate::layout::FieldLayout {
            name: "flags",
            range: crate::layout::ByteRange::new(0, 1),
        });
    }
    fields
}
message_codec!(MqttCodec, Mqtt, mqtt_schema, mqtt_layout_wire);

const NAME: &str = "mqtt";

/// Read a CONNECT's protocol level before selecting a version-specific parser.
/// The caller has already established the complete packet boundary.
pub(crate) fn connect_protocol_level(input: &[u8]) -> Option<u8> {
    let mut reader = Reader::new(NAME, input);
    if reader.u8().ok()? != 0x10 {
        return None;
    }
    for _ in 0..4 {
        if reader.u8().ok()? & 128 == 0 {
            let length = usize::from(reader.u16().ok()?);
            return match reader.take(length).ok()? {
                b"MQTT" | b"MQIsdp" => reader.u8().ok(),
                _ => None,
            };
        }
    }
    None
}

impl Mqtt {
    fn validate(&self) -> Result<(), Error> {
        if !(1..=14).contains(&self.packet_type) {
            return Err(unsupported(NAME, "unsupported control packet type"));
        }
        let expected = if matches!(self.packet_type, 6 | 8 | 10) {
            2
        } else {
            0
        };
        if self.packet_type != 3 && self.flags != expected
            || self.flags > 15
            || self.packet_type == 3
                && ((self.flags >> 1) & 3 == 3 || self.flags & 6 == 0 && self.flags & 8 != 0)
        {
            return Err(invalid(NAME, "invalid fixed header flags"));
        }
        Ok(())
    }
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        match self.packet_type {
            1 => {
                w.bytes16(b"MQTT")?;
                w.u8(4)?;
                w.u8(self.connect_flags)?;
                w.u16(self.keep_alive)?;
                w.bytes16(&self.client_id)?;
                if self.connect_flags & 4 != 0 {
                    w.bytes16(&self.will_topic)?;
                    w.bytes16(&self.will_payload)?;
                }
                if self.connect_flags & 128 != 0 {
                    w.bytes16(&self.user_name)?;
                }
                if self.connect_flags & 64 != 0 {
                    w.bytes16(&self.password)?;
                }
            }
            2 => {
                w.u8(self.session_present)?;
                w.u8(self.return_code)?;
            }
            3 => {
                w.bytes16(&self.topic)?;
                if self.flags & 6 != 0 {
                    w.u16(self.packet_id)?;
                }
                w.put(&self.payload)?;
            }
            4..=7 | 11 => w.u16(self.packet_id)?,
            8 | 10 => {
                w.u16(self.packet_id)?;
                if self.subscriptions.0.is_empty() || self.subscriptions.0.len() > MAX_RECORDS {
                    return Err(invalid(NAME, "empty or excessive topic list"));
                }
                for s in &self.subscriptions.0 {
                    w.bytes16(data(s, "topic", NAME)?)?;
                    if self.packet_type == 8 {
                        w.u8(u8::try_from(number(s, "qos", NAME)?)
                            .map_err(|_| invalid(NAME, "invalid QoS"))?)?;
                    }
                }
            }
            9 => {
                w.u16(self.packet_id)?;
                w.put(&self.payload)?;
            }
            12..=14 => {}
            _ => unreachable!(),
        }
        let mut head = Writer::new(NAME, c.remaining_packet_bytes);
        head.u8(self.packet_type << 4 | self.flags)?;
        let mut len = w.bytes.len();
        if len > 268435455 {
            return Err(invalid(NAME, "remaining length exceeds MQTT maximum"));
        }
        loop {
            let mut v = (len % 128) as u8;
            len /= 128;
            if len > 0 {
                v |= 128;
            }
            head.u8(v)?;
            if len == 0 {
                break;
            }
        }
        head.put(&w.bytes)?;
        Self::parse_wire(
            Bytes::copy_from_slice(&head.bytes),
            &DecodeContext {
                parent: None,
                registry: c.registry,
                network: None,
                hop_limit: None,
                discriminator: None,
            },
        )?;
        Ok(head.bytes)
    }
    fn parse_wire(b: Bytes, _c: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        let h = r.u8()?;
        let mut v = r.u8()?;
        while v & 128 != 0 {
            v = r.u8()?;
        }
        let mut s = Self {
            packet_type: h >> 4,
            flags: h & 15,
            ..Self::default()
        };
        s.validate()?;
        match s.packet_type {
            1 => {
                if r.bytes16()?.as_ref() != b"MQTT" || r.u8()? != 4 {
                    return Err(unsupported(NAME, "only MQTT 3.1.1 CONNECT is supported"));
                }
                s.connect_flags = r.u8()?;
                s.keep_alive = r.u16()?;
                s.client_id = r.bytes16()?;
                let flags = s.connect_flags;
                if flags & 2 == 0 && s.client_id.is_empty() {
                    return Err(invalid(
                        NAME,
                        "persistent sessions require a client identifier",
                    ));
                }
                if flags & 1 != 0
                    || flags & 4 == 0 && flags & 0x38 != 0
                    || (flags >> 3) & 3 == 3
                    || flags & 64 != 0 && flags & 128 == 0
                {
                    return Err(invalid(NAME, "invalid CONNECT flags"));
                }
                if flags & 4 != 0 {
                    s.will_topic = r.bytes16()?;
                    topic_name(&s.will_topic)?;
                    s.will_payload = r.bytes16()?;
                }
                if flags & 128 != 0 {
                    s.user_name = r.bytes16()?;
                }
                if flags & 64 != 0 {
                    s.password = r.bytes16()?;
                }
                for value in [&s.client_id, &s.will_topic, &s.user_name] {
                    mqtt_text(value)?;
                }
            }
            2 => {
                s.session_present = r.u8()?;
                s.return_code = r.u8()?;
                if s.session_present > 1
                    || s.return_code > 5
                    || s.return_code != 0 && s.session_present != 0
                {
                    return Err(invalid(NAME, "invalid CONNACK"));
                }
            }
            3 => {
                s.topic = r.bytes16()?;
                topic_name(&s.topic)?;
                if s.flags & 6 != 0 {
                    s.packet_id = r.u16()?;
                }
                s.payload = Bytes::copy_from_slice(r.rest());
            }
            4..=7 | 11 => s.packet_id = r.u16()?,
            8 | 10 => {
                s.packet_id = r.u16()?;
                while r.left() > 0 {
                    if s.subscriptions.0.len() == MAX_RECORDS {
                        return Err(invalid(NAME, "too many topics"));
                    }
                    let topic = r.bytes16()?;
                    mqtt_text(&topic)?;
                    if topic.is_empty() {
                        return Err(invalid(NAME, "empty subscription"));
                    }
                    let mut levels = topic.split(|b| *b == b'/').peekable();
                    while let Some(level) = levels.next() {
                        if level.contains(&b'+') && level != b"+"
                            || level.contains(&b'#') && (level != b"#" || levels.peek().is_some())
                        {
                            return Err(invalid(NAME, "invalid subscription wildcard"));
                        }
                    }
                    let mut item = record([("topic", topic.into())]);
                    if s.packet_type == 8 {
                        let qos = r.u8()?;
                        if qos > 2 {
                            return Err(invalid(NAME, "invalid subscription QoS"));
                        }
                        item.insert("qos".into(), qos.into());
                    }
                    s.subscriptions.0.push(item);
                }
                if s.subscriptions.0.is_empty() {
                    return Err(invalid(NAME, "empty subscription list"));
                }
            }
            9 => {
                s.packet_id = r.u16()?;
                s.payload = Bytes::copy_from_slice(r.rest());
                if s.payload.is_empty() || s.payload.iter().any(|v| !matches!(*v, 0..=2 | 128)) {
                    return Err(invalid(NAME, "invalid SUBACK return codes"));
                }
            }
            12..=14 => {}
            _ => unreachable!(),
        }
        if (matches!(s.packet_type, 4..=11) || s.packet_type == 3 && s.flags & 6 != 0)
            && s.packet_id == 0
        {
            return Err(invalid(NAME, "packet identifier cannot be zero"));
        }
        r.finish()?;
        Ok(s)
    }
}
fn mqtt_text(b: &[u8]) -> Result<(), Error> {
    let s = std::str::from_utf8(b).map_err(|_| invalid(NAME, "invalid UTF-8 string"))?;
    if s.contains('\0') {
        return Err(invalid(NAME, "NUL in UTF-8 string"));
    }
    Ok(())
}

fn topic_name(topic: &[u8]) -> Result<(), Error> {
    mqtt_text(topic)?;
    if topic.is_empty() || topic.contains(&b'#') || topic.contains(&b'+') {
        return Err(invalid(NAME, "invalid topic name"));
    }
    Ok(())
}
