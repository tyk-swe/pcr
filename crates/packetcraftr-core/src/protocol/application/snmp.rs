// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! SNMPv1 and SNMPv2c BER PDUs (RFC 1157, RFC 3416); value envelopes preserve unknown ASN.1 types.

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use super::ber;
use crate::protocol::common::structured::member;
const VARBINDS: &[crate::layer::FieldSchema] = &[
    member("oid", field::Kind::Bytes, &[]),
    member("tag", field::Kind::Unsigned, &[]),
    member("value", field::Kind::Bytes, &[]),
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snmp {
    pub version: u8,
    pub community: Bytes,
    pub pdu_type: u8,
    pub request_id: i32,
    pub error_status: u32,
    pub error_index: u32,
    pub enterprise: Bytes,
    pub agent_address: std::net::Ipv4Addr,
    pub generic_trap: u32,
    pub specific_trap: u32,
    pub timestamp: u32,
    pub varbinds: Records,
}
impl Default for Snmp {
    fn default() -> Self {
        Self {
            version: 1,
            community: Bytes::from_static(b"public"),
            pdu_type: 0xa0,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            enterprise: Bytes::new(),
            agent_address: std::net::Ipv4Addr::UNSPECIFIED,
            generic_trap: 0,
            specific_trap: 0,
            timestamp: 0,
            varbinds: Records::default(),
        }
    }
}
crate::reflective_layer! {
 fn snmp_schema() => { protocol: crate::layer::Id::new("snmp"), name: "Snmp" }
 impl Snmp {
    "version" => { kind: Unsigned, derived: false, required: false, description: "version", reflect: version },
    "community" => { kind: Bytes, derived: false, required: false, description: "community", reflect: community },
    "pdu_type" => { kind: Unsigned, derived: false, required: false, description: "pdu type", reflect: pdu_type },
    "request_id" => { kind: Signed, derived: false, required: false, description: "request id", reflect: request_id },
    "error_status" => { kind: Unsigned, derived: false, required: false, description: "error status", reflect: error_status },
    "error_index" => { kind: Unsigned, derived: false, required: false, description: "error index", reflect: error_index },
    "enterprise" => { kind: Bytes, derived: false, required: false, description: "enterprise", reflect: enterprise },
    "agent_address" => { kind: Ipv4, derived: false, required: false, description: "agent address", reflect: agent_address },
    "generic_trap" => { kind: Unsigned, derived: false, required: false, description: "generic trap", reflect: generic_trap },
    "specific_trap" => { kind: Unsigned, derived: false, required: false, description: "specific trap", reflect: specific_trap },
    "timestamp" => { kind: Unsigned, derived: false, required: false, description: "timestamp", reflect: timestamp },
    "varbinds" => { kind: List, derived: false, required: false, description: "BER object identifier content and typed value envelopes", children: VARBINDS, reflect: varbinds },
 }
}
fn snmp_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let fields = Vec::new();
    let _ = b;
    fields
}
message_codec!(SnmpCodec, Snmp, snmp_schema, snmp_layout_wire);

const NAME: &str = "snmp";
impl Snmp {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.version > 1 {
            return Err(unsupported(NAME, "only SNMPv1/v2c"));
        }
        let max = c.remaining_packet_bytes;
        let mut body = Writer::new(NAME, max);
        ber::int(&mut body, 2, self.version.into())?;
        ber::put(&mut body, 4, &self.community)?;
        let mut pdu = Writer::new(NAME, max);
        if self.pdu_type == 0xa4 {
            if self.version != 0 {
                return Err(invalid(NAME, "v1 trap with v2c version"));
            }
            ber::put(&mut pdu, 6, &self.enterprise)?;
            ber::put(&mut pdu, 0x40, &self.agent_address.octets())?;
            ber::int(&mut pdu, 2, self.generic_trap.into())?;
            ber::int(&mut pdu, 2, self.specific_trap.into())?;
            ber::int(&mut pdu, 0x43, self.timestamp.into())?;
        } else {
            if !(0xa0..=0xa7).contains(&self.pdu_type) {
                return Err(unsupported(NAME, "unknown PDU"));
            }
            ber::int(&mut pdu, 2, self.request_id.into())?;
            ber::int(&mut pdu, 2, self.error_status.into())?;
            ber::int(&mut pdu, 2, self.error_index.into())?;
        }
        let mut binds = Writer::new(NAME, max);
        for r in &self.varbinds.0 {
            let mut v = Writer::new(NAME, max);
            ber::put(&mut v, 6, data(r, "oid", NAME)?)?;
            ber::put(
                &mut v,
                u8::try_from(number(r, "tag", NAME)?)
                    .map_err(|_| invalid(NAME, "value tag overflow"))?,
                data(r, "value", NAME)?,
            )?;
            ber::put(&mut binds, 0x30, &v.bytes)?;
        }
        ber::put(&mut pdu, 0x30, &binds.bytes)?;
        ber::put(&mut body, self.pdu_type, &pdu.bytes)?;
        let mut w = Writer::new(NAME, max);
        ber::put(&mut w, 0x30, &body.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        ber::validate(NAME, &b)?;
        let mut r = Reader::new(NAME, &b);
        let top = ber::expect(&mut r, 0x30)?;
        r.finish()?;
        let mut r = Reader::new(NAME, top);
        let version = ber::integer(ber::expect(&mut r, 2)?, NAME)?;
        if !(0..=1).contains(&version) {
            return Err(unsupported(NAME, "only SNMPv1/v2c"));
        }
        let community = Bytes::copy_from_slice(ber::expect(&mut r, 4)?);
        let (pdu_type, pdu) = ber::take(&mut r)?;
        r.finish()?;
        let mut s = Self {
            version: version as u8,
            community,
            pdu_type,
            ..Self::default()
        };
        let mut p = Reader::new(NAME, pdu);
        if pdu_type == 0xa4 {
            if version != 0 {
                return Err(invalid(NAME, "v1 trap with v2c version"));
            }
            s.enterprise = Bytes::copy_from_slice(ber::expect(&mut p, 6)?);
            s.agent_address = std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(ber::expect(&mut p, 0x40)?)
                    .map_err(|_| invalid(NAME, "invalid agent address"))?,
            );
            s.generic_trap = read_uint(&mut p, 2)?;
            s.specific_trap = read_uint(&mut p, 2)?;
            s.timestamp = read_uint(&mut p, 0x43)?;
        } else {
            if !(0xa0..=0xa7).contains(&pdu_type) {
                return Err(unsupported(NAME, "unknown PDU"));
            }
            s.request_id = i32::try_from(ber::integer(ber::expect(&mut p, 2)?, NAME)?)
                .map_err(|_| invalid(NAME, "request ID overflow"))?;
            s.error_status = read_uint(&mut p, 2)?;
            s.error_index = read_uint(&mut p, 2)?;
        }
        let mut binds = Reader::new(NAME, ber::expect(&mut p, 0x30)?);
        p.finish()?;
        while binds.left() > 0 {
            if s.varbinds.0.len() == MAX_RECORDS {
                return Err(invalid(NAME, "too many varbinds"));
            }
            let mut v = Reader::new(NAME, ber::expect(&mut binds, 0x30)?);
            let oid = Bytes::copy_from_slice(ber::expect(&mut v, 6)?);
            let (tag, value) = ber::take(&mut v)?;
            v.finish()?;
            s.varbinds.0.push(record([
                ("oid", oid.into()),
                ("tag", tag.into()),
                ("value", Bytes::copy_from_slice(value).into()),
            ]));
        }
        Ok(s)
    }
}
fn read_uint(r: &mut Reader<'_>, tag: u8) -> Result<u32, Error> {
    u32::try_from(ber::integer(ber::expect(r, tag)?, NAME)?)
        .map_err(|_| invalid(NAME, "unsigned integer overflow"))
}
