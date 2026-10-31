// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared OSPF header layout, neighbor lists, LSA envelopes, and opaque bodies
//! for versions 2 and 3.

use bytes::Bytes;

use crate::codec::Error;
use crate::field;
use crate::layout::{ByteRange, FieldLayout};
use crate::protocol::common::invalid;
use crate::protocol::common::structured::member;
use crate::protocol::message::{MAX_RECORDS, Reader, Records, Writer, data, number, record};

pub(crate) const NEIGHBORS: &[crate::layer::FieldSchema] =
    &[member("router_id", field::Kind::Unsigned, &[])];
pub(crate) const LSAS: &[crate::layer::FieldSchema] = &[
    member("header", field::Kind::Bytes, &[]),
    member("body", field::Kind::Bytes, &[]),
];

pub(crate) fn header_layout(b: &[u8]) -> Vec<FieldLayout> {
    let mut fields = Vec::new();
    if 2 <= b.len() {
        fields.push(FieldLayout {
            name: "packet_type",
            range: ByteRange::new(1, 2),
        });
    }
    if 8 <= b.len() {
        fields.push(FieldLayout {
            name: "router_id",
            range: ByteRange::new(4, 8),
        });
    }
    if 12 <= b.len() {
        fields.push(FieldLayout {
            name: "area_id",
            range: ByteRange::new(8, 12),
        });
    }
    if 14 <= b.len() {
        fields.push(FieldLayout {
            name: "checksum",
            range: ByteRange::new(12, 14),
        });
    }
    fields
}

pub(crate) fn encode_neighbors(
    p: &mut Writer,
    neighbors: &Records,
    name: &'static str,
) -> Result<(), Error> {
    for r in &neighbors.0 {
        p.u32(
            u32::try_from(number(r, "router_id", name)?)
                .map_err(|_| invalid(name, "router ID overflow"))?,
        )?;
    }
    Ok(())
}

pub(crate) fn parse_neighbors(r: &mut Reader<'_>, name: &'static str) -> Result<Records, Error> {
    let mut neighbors = Records::default();
    while r.left() > 0 {
        if neighbors.0.len() == MAX_RECORDS {
            return Err(invalid(name, "too many neighbors"));
        }
        neighbors.0.push(record([("router_id", r.u32()?.into())]));
    }
    Ok(neighbors)
}

pub(crate) fn encode_lsas(
    p: &mut Writer,
    lsas: &Records,
    packet_type: u8,
    name: &'static str,
) -> Result<(), Error> {
    if packet_type == 4 {
        p.u32(u32::try_from(lsas.0.len()).map_err(|_| invalid(name, "too many LSAs"))?)?;
    }
    for r in &lsas.0 {
        let h = data(r, "header", name)?;
        let b = data(r, "body", name)?;
        if h.len() != 20
            || packet_type == 5 && !b.is_empty()
            || packet_type == 4 && usize::from(u16::from_be_bytes([h[18], h[19]])) != 20 + b.len()
        {
            return Err(invalid(name, "invalid LSA envelope"));
        }
        p.put(h)?;
        p.put(b)?;
    }
    Ok(())
}

pub(crate) fn parse_lsas(
    r: &mut Reader<'_>,
    packet_type: u8,
    name: &'static str,
) -> Result<Records, Error> {
    let count = if packet_type == 4 {
        r.u32()? as usize
    } else {
        r.left() / 20
    };
    if count > MAX_RECORDS {
        return Err(invalid(name, "too many LSAs"));
    }
    let mut lsas = Records::default();
    for _ in 0..count {
        let h = r.take(20)?;
        let len = usize::from(u16::from_be_bytes([h[18], h[19]]));
        if len < 20 {
            return Err(invalid(name, "short LSA"));
        }
        let body = if packet_type == 4 {
            r.take(len - 20)?
        } else {
            &[]
        };
        lsas.0.push(record([
            ("header", Bytes::copy_from_slice(h).into()),
            ("body", Bytes::copy_from_slice(body).into()),
        ]));
    }
    Ok(lsas)
}

pub(crate) fn parse_opaque_body(
    r: &mut Reader<'_>,
    packet_type: u8,
    dd_minimum: usize,
    name: &'static str,
) -> Result<Bytes, Error> {
    match packet_type {
        2 if r.left() < dd_minimum || !(r.left() - dd_minimum).is_multiple_of(20) => {
            return Err(invalid(name, "invalid database description"));
        }
        3 if !r.left().is_multiple_of(12) => {
            return Err(invalid(name, "invalid link-state request"));
        }
        _ => {}
    }
    Ok(Bytes::copy_from_slice(r.rest()))
}
