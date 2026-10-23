// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! EtherNet/IP encapsulation and Common Packet Format. CIP services inside items remain opaque.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const ITEMS: &[crate::layer::FieldSchema] = &[
    member("kind", field::Kind::Unsigned, &[]),
    member("data", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthernetIp {
    pub command: u16,
    pub session: u32,
    pub status: u32,
    pub sender_context: Bytes,
    pub options: u32,
    pub protocol_version: u16,
    pub flags: u16,
    pub interface_handle: u32,
    pub timeout: u16,
    pub items: Records,
    pub data: Bytes,
}
impl Default for EthernetIp {
    fn default() -> Self {
        Self {
            command: 0x65,
            session: 0,
            status: 0,
            sender_context: Bytes::from_static(&[0; 8]),
            options: 0,
            protocol_version: 1,
            flags: 0,
            interface_handle: 0,
            timeout: 0,
            items: Records::default(),
            data: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn ethernetip_schema() => { protocol: crate::layer::Id::new("ethernet_ip"), name: "EthernetIp" }
 impl EthernetIp {
    "command" => { kind: Unsigned, derived: false, required: false, description: "command", reflect: command },
    "session" => { kind: Unsigned, derived: false, required: false, description: "session", reflect: session },
    "status" => { kind: Unsigned, derived: false, required: false, description: "status", reflect: status },
    "sender_context" => { kind: Bytes, derived: false, required: false, description: "sender context", reflect: sender_context },
    "options" => { kind: Unsigned, derived: false, required: false, description: "options", reflect: options },
    "protocol_version" => { kind: Unsigned, derived: false, required: false, description: "protocol version", reflect: protocol_version },
    "flags" => { kind: Unsigned, derived: false, required: false, description: "flags", reflect: flags },
    "interface_handle" => { kind: Unsigned, derived: false, required: false, description: "interface handle", reflect: interface_handle },
    "timeout" => { kind: Unsigned, derived: false, required: false, description: "timeout", reflect: timeout },
    "items" => { kind: List, derived: false, required: false, description: "Common Packet Format items", children: ITEMS, reflect: items },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
 layout fn ethernetip_layout();
}
fn ethernetip_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = ethernetip_layout();
    let mut fields = Vec::new();
    if 2 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "command",
            range: crate::layout::ByteRange::new(0, 2),
        });
    }
    if 8 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "session",
            range: crate::layout::ByteRange::new(4, 8),
        });
    }
    if 12 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "status",
            range: crate::layout::ByteRange::new(8, 12),
        });
    }
    if 20 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "sender_context",
            range: crate::layout::ByteRange::new(12, 20),
        });
    }
    if 24 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "options",
            range: crate::layout::ByteRange::new(20, 24),
        });
    }
    fields
}
message_codec!(
    EthernetIpCodec,
    EthernetIp,
    ethernetip_schema,
    ethernetip_layout_wire
);

const NAME: &str = "ethernet_ip";
impl EthernetIp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.sender_context.len() != 8 {
            return Err(invalid(NAME, "sender context requires eight bytes"));
        }
        let mut p = Writer::new(NAME, c.remaining_packet_bytes);
        match self.command {
            0x65 => {
                p.le16(self.protocol_version)?;
                p.le16(self.flags)?;
            }
            0x66 => {}
            0x6f | 0x70 => {
                p.le32(self.interface_handle)?;
                p.le16(self.timeout)?;
                p.le16(
                    u16::try_from(self.items.0.len())
                        .map_err(|_| invalid(NAME, "too many items"))?,
                )?;
                for r in &self.items.0 {
                    let v = data(r, "data", NAME)?;
                    p.le16(
                        u16::try_from(number(r, "kind", NAME)?)
                            .map_err(|_| invalid(NAME, "item kind overflow"))?,
                    )?;
                    p.le16(u16::try_from(v.len()).map_err(|_| invalid(NAME, "item too long"))?)?;
                    p.put(v)?;
                }
            }
            _ => p.put(&self.data)?,
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.le16(self.command)?;
        w.le16(u16::try_from(p.bytes.len()).map_err(|_| invalid(NAME, "payload too long"))?)?;
        w.le32(self.session)?;
        w.le32(self.status)?;
        w.put(&self.sender_context)?;
        w.le32(self.options)?;
        w.put(&p.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        let command = r.le16()?;
        let n = r.le16()? as usize;
        if n + 24 != b.len() {
            return Err(invalid(NAME, "encapsulation length mismatch"));
        }
        let mut s = Self {
            command,
            session: r.le32()?,
            status: r.le32()?,
            sender_context: Bytes::copy_from_slice(r.take(8)?),
            options: r.le32()?,
            ..Self::default()
        };
        match command {
            0x65 => {
                s.protocol_version = r.le16()?;
                s.flags = r.le16()?;
            }
            0x66 => {}
            0x6f | 0x70 => {
                s.interface_handle = r.le32()?;
                s.timeout = r.le16()?;
                let n = r.le16()? as usize;
                if n > MAX_RECORDS {
                    return Err(invalid(NAME, "too many CPF items"));
                }
                for _ in 0..n {
                    let kind = r.le16()?;
                    let len = r.le16()? as usize;
                    s.items.0.push(record([
                        ("kind", kind.into()),
                        ("data", Bytes::copy_from_slice(r.take(len)?).into()),
                    ]));
                }
            }
            _ => s.data = Bytes::copy_from_slice(r.rest()),
        }
        r.finish()?;
        Ok(s)
    }
}
