// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! PIMv2 (RFC 7761), Hello options and bounded Join/Prune envelopes. Other bodies retain their bytes.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::field;
use crate::protocol::common::{checksum_parts, invalid, transport_checksum_parts, unsupported};
use crate::protocol::message::{
    MAX_RECORDS, Reader, Records, Writer, checksum_value, data, message_codec, number, record,
};
use bytes::Bytes;

use crate::protocol::common::structured::member;
const OPTIONS: &[crate::layer::FieldSchema] = &[
    member("kind", field::Kind::Unsigned, &[]),
    member("value", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pim {
    pub message_type: u8,
    pub reserved: u8,
    pub checksum: field::WireValue<u16>,
    pub options: Records,
    pub data: Bytes,
}
impl Default for Pim {
    fn default() -> Self {
        Self {
            message_type: 0,
            reserved: 0,
            checksum: field::WireValue::Auto,
            options: Records::default(),
            data: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn pim_schema() => { protocol: crate::protocol::BuiltinProtocol::Pim.id(), name: "Pim" }
 impl Pim {
    "message_type" => { kind: Unsigned, derived: false, required: false, description: "message type", reflect: message_type },
    "reserved" => { kind: Unsigned, derived: false, required: false, description: "reserved", reflect: reserved },
    "checksum" => { kind: Unsigned, derived: true, required: false, description: "checksum", reflect: checksum },
    "options" => { kind: List, derived: false, required: false, description: "Ordered Hello options", children: OPTIONS, reflect: options },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
}
message_codec!(PimCodec, Pim, pim_schema);

const NAME: &str = crate::protocol::BuiltinProtocol::Pim.as_str();
impl Pim {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if !matches!(self.message_type, 0 | 3) {
            return Err(invalid(NAME, "message type overflow"));
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u8(0x20 | self.message_type)?;
        w.u8(self.reserved)?;
        w.u16(0)?;
        if self.message_type == 0 {
            for t in &self.options.0 {
                let v = data(t, "value", NAME)?;
                w.u16(
                    u16::try_from(number(t, "kind", NAME)?)
                        .map_err(|_| invalid(NAME, "option kind overflow"))?,
                )?;
                w.u16(u16::try_from(v.len()).map_err(|_| invalid(NAME, "option too long"))?)?;
                w.put(v)?;
            }
        } else {
            w.put(&self.data)?;
        }
        let network = c.network_envelope().ok();
        let sum = match network {
            Some(n) if n.source.is_ipv6() => transport_checksum_parts(NAME, n, 103, &[&w.bytes])?,
            _ => checksum_parts(&[&w.bytes]),
        };
        let sum = checksum_value(NAME, &self.checksum, sum, c)?;
        w.bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        Ok(w.bytes)
    }
    fn parse_wire(
        b: Bytes,
        c: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        let mut r = Reader::new(NAME, &b);
        r.mark(0, 0..1);
        r.mark(1, 1..2);
        r.mark(2, 2..4);
        let h = r.u8()?;
        if h >> 4 != 2 {
            return Err(unsupported(NAME, "only PIMv2"));
        }
        if !matches!(h & 15, 0 | 3) {
            return Err(unsupported(NAME, "only Hello and Join/Prune are supported"));
        }
        let mut s = Self {
            message_type: h & 15,
            reserved: r.u8()?,
            checksum: field::WireValue::Exact(r.u16()?),
            ..Self::default()
        };
        let sum = match c.network {
            Some(n) if n.source.is_ipv6() => transport_checksum_parts(NAME, n, 103, &[&b])?,
            _ => checksum_parts(&[&b]),
        };
        if sum != 0 {
            return Err(invalid(NAME, "PIM checksum mismatch"));
        }
        if s.message_type == 0 {
            while r.left() > 0 {
                if s.options.0.len() == MAX_RECORDS {
                    return Err(invalid(NAME, "too many options"));
                }
                let kind = r.u16()?;
                let n = r.u16()? as usize;
                s.options.0.push(record([
                    ("kind", kind.into()),
                    ("value", Bytes::copy_from_slice(r.take(n)?).into()),
                ]));
            }
        } else {
            s.data = Bytes::copy_from_slice(r.rest());
            if s.message_type == 3 {
                validate_join(&s.data)?;
            }
        }
        Ok((s, r.take_layouts()))
    }
}
fn address(r: &mut Reader<'_>, extra: usize) -> Result<(), Error> {
    let family = r.u8()?;
    if r.u8()? != 0 {
        return Err(unsupported(NAME, "non-native address encoding"));
    }
    let n = match family {
        1 => 4,
        2 => 16,
        _ => return Err(unsupported(NAME, "unknown address family")),
    };
    r.take(extra + n)?;
    Ok(())
}
fn validate_join(b: &[u8]) -> Result<(), Error> {
    let mut r = Reader::new(NAME, b);
    address(&mut r, 0)?;
    r.u8()?;
    let count = r.u8()?;
    r.u16()?;
    let mut entries = 0;
    for _ in 0..count {
        address(&mut r, 2)?;
        let count = usize::from(r.u16()?) + usize::from(r.u16()?);
        entries += count;
        if entries > MAX_RECORDS {
            return Err(invalid(NAME, "too many sources"));
        }
        for _ in 0..count {
            address(&mut r, 2)?;
        }
    }
    r.finish()
}
