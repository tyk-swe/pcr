// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Memcached binary request/response envelope. ASCII and meta protocols remain raw.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::protocol::common::{invalid, unsupported};
use crate::protocol::message::{Reader, Writer, message_codec};
use bytes::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Memcached {
    pub magic: u8,
    pub opcode: u8,
    pub data_type: u8,
    pub status: u16,
    pub opaque: u32,
    pub cas: u64,
    pub extras: Bytes,
    pub key: Bytes,
    pub value: Bytes,
}
impl Default for Memcached {
    fn default() -> Self {
        Self {
            magic: 0x80,
            opcode: 10,
            data_type: 0,
            status: 0,
            opaque: 0,
            cas: 0,
            extras: Bytes::new(),
            key: Bytes::new(),
            value: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn memcached_schema() => { protocol: crate::protocol::BuiltinProtocol::Memcached.id(), name: "Memcached" }
 impl Memcached {
    "magic" => { kind: Unsigned, derived: false, required: false, description: "magic", reflect: magic },
    "opcode" => { kind: Unsigned, derived: false, required: false, description: "opcode", reflect: opcode },
    "data_type" => { kind: Unsigned, derived: false, required: false, description: "data type", reflect: data_type },
    "status" => { kind: Unsigned, derived: false, required: false, description: "status", reflect: status },
    "opaque" => { kind: Unsigned, derived: false, required: false, description: "opaque", reflect: opaque },
    "cas" => { kind: Unsigned, derived: false, required: false, description: "cas", reflect: cas },
    "extras" => { kind: Bytes, derived: false, required: false, description: "extras", reflect: extras },
    "key" => { kind: Bytes, derived: false, required: false, description: "key", reflect: key },
    "value" => { kind: Bytes, derived: false, required: false, description: "value", reflect: value },
 }
}
message_codec!(MemcachedCodec, Memcached, memcached_schema);

const NAME: &str = crate::protocol::BuiltinProtocol::Memcached.as_str();
impl Memcached {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if !matches!(self.magic, 0x80 | 0x81) {
            return Err(unsupported(NAME, "not binary protocol"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u8(self.magic)?;
        w.u8(self.opcode)?;
        w.u16(u16::try_from(self.key.len()).map_err(|_| invalid(NAME, "key too long"))?)?;
        w.u8(u8::try_from(self.extras.len()).map_err(|_| invalid(NAME, "extras too long"))?)?;
        w.u8(self.data_type)?;
        w.u16(self.status)?;
        let total = self
            .extras
            .len()
            .checked_add(self.key.len())
            .and_then(|n| n.checked_add(self.value.len()))
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| invalid(NAME, "body too long"))?;
        w.u32(total)?;
        w.u32(self.opaque)?;
        w.put(&self.cas.to_be_bytes())?;
        w.put(&self.extras)?;
        w.put(&self.key)?;
        w.put(&self.value)?;
        Ok(w.bytes)
    }
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        let mut r = Reader::new(NAME, &b);
        r.mark(0, 0..1);
        r.mark(1, 1..2);
        r.mark(2, 5..6);
        r.mark(3, 6..8);
        r.mark(4, 12..16);
        r.mark(5, 16..24);
        let magic = r.u8()?;
        if !matches!(magic, 0x80 | 0x81) {
            return Err(unsupported(NAME, "not binary protocol"));
        }
        let opcode = r.u8()?;
        let key_len = r.u16()? as usize;
        let extras_len = r.u8()? as usize;
        let data_type = r.u8()?;
        let status = r.u16()?;
        let total = r.u32()? as usize;
        let opaque = r.u32()?;
        let cas = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
        if extras_len + key_len > total {
            return Err(invalid(NAME, "key and extras exceed body"));
        }
        let extras = Bytes::copy_from_slice(r.take(extras_len)?);
        let key = Bytes::copy_from_slice(r.take(key_len)?);
        let value = Bytes::copy_from_slice(r.take(total - extras_len - key_len)?);
        r.finish()?;
        r.mark(6, 24..24 + extras_len);
        r.mark(7, 24 + extras_len..24 + extras_len + key_len);
        r.mark(8, 24 + extras_len + key_len..24 + total);
        Ok((
            Self {
                magic,
                opcode,
                data_type,
                status,
                opaque,
                cas,
                extras,
                key,
                value,
            },
            r.take_layouts(),
        ))
    }
}
