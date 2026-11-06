// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! BGP-4 base messages (RFC 4271), with 4096-byte framing and byte-preserving path attributes.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::field;
use crate::protocol::common::{invalid, unsupported};
use crate::protocol::message::{
    MAX_RECORDS, Reader, Records, Writer, data, message_codec, number, record,
};
use bytes::Bytes;

use crate::protocol::common::structured::member;
const PARAMETERS: &[crate::layer::FieldSchema] = &[
    member("kind", field::Kind::Unsigned, &[]),
    member("value", field::Kind::Bytes, &[]),
];
const PREFIXES: &[crate::layer::FieldSchema] = &[
    member("length", field::Kind::Unsigned, &[]),
    member("prefix", field::Kind::Bytes, &[]),
];
const ATTRIBUTES: &[crate::layer::FieldSchema] = &[
    member("flags", field::Kind::Unsigned, &[]),
    member("kind", field::Kind::Unsigned, &[]),
    member("value", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bgp {
    pub message_type: u8,
    pub version: u8,
    pub my_as: u16,
    pub hold_time: u16,
    pub identifier: std::net::Ipv4Addr,
    pub parameters: Records,
    pub withdrawn: Records,
    pub attributes: Records,
    pub nlri: Records,
    pub error_code: u8,
    pub error_subcode: u8,
    pub data: Bytes,
}
impl Default for Bgp {
    fn default() -> Self {
        Self {
            message_type: 4,
            version: 4,
            my_as: 0,
            hold_time: 90,
            identifier: std::net::Ipv4Addr::UNSPECIFIED,
            parameters: Records::default(),
            withdrawn: Records::default(),
            attributes: Records::default(),
            nlri: Records::default(),
            error_code: 0,
            error_subcode: 0,
            data: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn bgp_schema() => { protocol: crate::protocol::BuiltinProtocol::Bgp.id(), name: "Bgp" }
 impl Bgp {
    "message_type" => { kind: Unsigned, derived: false, required: false, description: "message type", reflect: message_type },
    "version" => { kind: Unsigned, derived: false, required: false, description: "version", reflect: version },
    "my_as" => { kind: Unsigned, derived: false, required: false, description: "my as", reflect: my_as },
    "hold_time" => { kind: Unsigned, derived: false, required: false, description: "hold time", reflect: hold_time },
    "identifier" => { kind: Ipv4, derived: false, required: false, description: "identifier", reflect: identifier },
    "parameters" => { kind: List, derived: false, required: false, description: "Ordered OPEN optional parameters", children: PARAMETERS, reflect: parameters },
    "withdrawn" => { kind: List, derived: false, required: false, description: "Withdrawn IPv4 prefixes", children: PREFIXES, reflect: withdrawn },
    "attributes" => { kind: List, derived: false, required: false, description: "Ordered path attributes preserving flags and opaque value", children: ATTRIBUTES, reflect: attributes },
    "nlri" => { kind: List, derived: false, required: false, description: "Reachable IPv4 prefixes", children: PREFIXES, reflect: nlri },
    "error_code" => { kind: Unsigned, derived: false, required: false, description: "error code", reflect: error_code },
    "error_subcode" => { kind: Unsigned, derived: false, required: false, description: "error subcode", reflect: error_subcode },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
}
message_codec!(BgpCodec, Bgp, bgp_schema);

const NAME: &str = crate::protocol::BuiltinProtocol::Bgp.as_str();
impl Bgp {
    fn reject_uncarried_fields(&self) -> Result<(), Error> {
        let default = Self::default();
        let fields = [
            ("version", 1, self.version == default.version),
            ("my_as", 1, self.my_as == default.my_as),
            ("hold_time", 1, self.hold_time == default.hold_time),
            ("identifier", 1, self.identifier == default.identifier),
            ("parameters", 1, self.parameters == default.parameters),
            ("withdrawn", 2, self.withdrawn == default.withdrawn),
            ("attributes", 2, self.attributes == default.attributes),
            ("nlri", 2, self.nlri == default.nlri),
            ("error_code", 3, self.error_code == default.error_code),
            (
                "error_subcode",
                3,
                self.error_subcode == default.error_subcode,
            ),
            ("data", 3, self.data == default.data),
        ];
        if let Some((field, ..)) = fields
            .iter()
            .find(|(_, carried_by, unchanged)| *carried_by != self.message_type && !unchanged)
        {
            return Err(invalid(
                NAME,
                format!(
                    "message type {} does not carry field {field}",
                    self.message_type
                ),
            ));
        }
        Ok(())
    }

    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        let mut p = Writer::new(NAME, c.remaining_packet_bytes);
        match self.message_type {
            1 => {
                if self.version != 4 {
                    return Err(unsupported(NAME, "only BGP version 4"));
                }
                p.u8(4)?;
                p.u16(self.my_as)?;
                p.u16(self.hold_time)?;
                p.put(&self.identifier.octets())?;
                let mut opts = Writer::new(NAME, 255);
                for r in &self.parameters.0 {
                    let b = data(r, "value", NAME)?;
                    opts.u8(u8::try_from(number(r, "kind", NAME)?)
                        .map_err(|_| invalid(NAME, "parameter kind overflow"))?)?;
                    opts.u8(
                        u8::try_from(b.len()).map_err(|_| invalid(NAME, "parameter too long"))?
                    )?;
                    opts.put(b)?;
                }
                p.u8(opts.bytes.len() as u8)?;
                p.put(&opts.bytes)?;
            }
            2 => {
                let mut withdrawn = Writer::new(NAME, 4096);
                write_prefixes(&self.withdrawn, &mut withdrawn)?;
                p.u16(withdrawn.bytes.len() as u16)?;
                p.put(&withdrawn.bytes)?;
                let mut attrs = Writer::new(NAME, 4096);
                for r in &self.attributes.0 {
                    let flags = u8::try_from(number(r, "flags", NAME)?)
                        .map_err(|_| invalid(NAME, "attribute flags overflow"))?;
                    let value = data(r, "value", NAME)?;
                    attrs.u8(flags)?;
                    attrs.u8(u8::try_from(number(r, "kind", NAME)?)
                        .map_err(|_| invalid(NAME, "attribute kind overflow"))?)?;
                    if flags & 16 != 0 {
                        attrs.u16(
                            u16::try_from(value.len())
                                .map_err(|_| invalid(NAME, "attribute too long"))?,
                        )?;
                    } else {
                        attrs.u8(u8::try_from(value.len())
                            .map_err(|_| invalid(NAME, "attribute too long"))?)?;
                    }
                    attrs.put(value)?;
                }
                p.u16(attrs.bytes.len() as u16)?;
                p.put(&attrs.bytes)?;
                write_prefixes(&self.nlri, &mut p)?;
            }
            3 => {
                p.u8(self.error_code)?;
                p.u8(self.error_subcode)?;
                p.put(&self.data)?;
            }
            4 => {}
            _ => return Err(unsupported(NAME, "unsupported message type")),
        }
        self.reject_uncarried_fields()?;
        let mut w = Writer::new(NAME, c.remaining_packet_bytes.min(4096));
        w.put(&[255; 16])?;
        w.u16(
            (p.bytes.len() + 19)
                .try_into()
                .map_err(|_| invalid(NAME, "message too long"))?,
        )?;
        w.u8(self.message_type)?;
        w.put(&p.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        let mut r = Reader::new(NAME, &b);
        r.mark(0, 18..19);
        if r.take(16)? != [255; 16] {
            return Err(invalid(NAME, "invalid marker"));
        }
        let len = r.u16()? as usize;
        if len != b.len() || len > 4096 {
            return Err(invalid(NAME, "invalid length"));
        }
        let mut s = Self {
            message_type: r.u8()?,
            ..Self::default()
        };
        match s.message_type {
            1 => {
                s.version = r.u8()?;
                if s.version != 4 {
                    return Err(unsupported(NAME, "only BGP version 4"));
                }
                s.my_as = r.u16()?;
                s.hold_time = r.u16()?;
                s.identifier = std::net::Ipv4Addr::from(<[u8; 4]>::try_from(r.take(4)?).unwrap());
                let n = r.u8()? as usize;
                let mut opts = Reader::new(NAME, r.take(n)?);
                while opts.left() > 0 {
                    if s.parameters.0.len() == MAX_RECORDS {
                        return Err(invalid(NAME, "too many parameters"));
                    }
                    let kind = opts.u8()?;
                    let len = opts.u8()? as usize;
                    s.parameters.0.push(record([
                        ("kind", kind.into()),
                        ("value", Bytes::copy_from_slice(opts.take(len)?).into()),
                    ]));
                }
            }
            2 => {
                let n = r.u16()? as usize;
                s.withdrawn = read_prefixes(r.take(n)?)?;
                let n = r.u16()? as usize;
                let mut a = Reader::new(NAME, r.take(n)?);
                while a.left() > 0 {
                    if s.attributes.0.len() == MAX_RECORDS {
                        return Err(invalid(NAME, "too many attributes"));
                    }
                    let flags = a.u8()?;
                    let kind = a.u8()?;
                    let len = if flags & 16 != 0 {
                        a.u16()? as usize
                    } else {
                        a.u8()? as usize
                    };
                    s.attributes.0.push(record([
                        ("flags", flags.into()),
                        ("kind", kind.into()),
                        ("value", Bytes::copy_from_slice(a.take(len)?).into()),
                    ]));
                }
                s.nlri = read_prefixes(r.rest())?;
            }
            3 => {
                s.error_code = r.u8()?;
                s.error_subcode = r.u8()?;
                s.data = Bytes::copy_from_slice(r.rest());
            }
            4 => {}
            _ => return Err(unsupported(NAME, "unsupported message type")),
        }
        r.finish()?;
        Ok((s, r.take_layouts()))
    }
}
fn write_prefixes(records: &Records, w: &mut Writer) -> Result<(), Error> {
    for r in &records.0 {
        let bits = number(r, "length", NAME)?;
        let b = data(r, "prefix", NAME)?;
        if bits > 32 || b.len() != bits.div_ceil(8) as usize {
            return Err(invalid(NAME, "invalid IPv4 prefix"));
        }
        w.u8(bits as u8)?;
        w.put(b)?;
    }
    Ok(())
}
fn read_prefixes(b: &[u8]) -> Result<Records, Error> {
    let mut r = Reader::new(NAME, b);
    let mut v = Records::default();
    while r.left() > 0 {
        if v.0.len() == MAX_RECORDS {
            return Err(invalid(NAME, "too many prefixes"));
        }
        let bits = r.u8()?;
        if bits > 32 {
            return Err(invalid(NAME, "invalid prefix length"));
        }
        v.0.push(record([
            ("length", bits.into()),
            (
                "prefix",
                Bytes::copy_from_slice(r.take(usize::from(bits).div_ceil(8))?).into(),
            ),
        ]));
    }
    Ok(v)
}
