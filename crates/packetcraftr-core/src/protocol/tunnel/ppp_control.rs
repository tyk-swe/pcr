// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! PPP control protocol header and ordered options; unrecognized option values remain opaque.

use std::marker::PhantomData;

use crate::codec::*;
use crate::field;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

use crate::protocol::common::structured::member;
const OPTIONS: &[crate::layer::FieldSchema] = &[
    member("kind", field::Kind::Unsigned, &[]),
    member("value", field::Kind::Bytes, &[]),
];

mod sealed {
    pub trait Sealed {}
}

/// PPP control protocol identity used to parameterize [`PppControl`].
pub trait ControlProtocol: sealed::Sealed {
    const NAME: &'static str;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Lcp;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ipcp;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ipv6cp;

impl sealed::Sealed for Lcp {}
impl sealed::Sealed for Ipcp {}
impl sealed::Sealed for Ipv6cp {}

impl ControlProtocol for Lcp {
    const NAME: &'static str = "ppp_lcp";
}
impl ControlProtocol for Ipcp {
    const NAME: &'static str = "ppp_ipcp";
}
impl ControlProtocol for Ipv6cp {
    const NAME: &'static str = "ppp_ipv6cp";
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PppControl<P: ControlProtocol> {
    pub code: u8,
    pub identifier: u8,
    pub options: Records,
    pub data: Bytes,
    marker: PhantomData<P>,
}
pub type PppLcp = PppControl<Lcp>;
pub type PppIpcp = PppControl<Ipcp>;
pub type PppIpv6cp = PppControl<Ipv6cp>;
impl<P: ControlProtocol> Default for PppControl<P> {
    fn default() -> Self {
        Self {
            code: 1,
            identifier: 0,
            options: Records::default(),
            data: Bytes::new(),
            marker: PhantomData,
        }
    }
}
macro_rules! ppp_control_layer {
    ($ty:ident, $marker:ident, $schema:ident, $name:literal, $codec:ident) => {
        crate::reflective_layer! {
         fn $schema() => { protocol: crate::layer::Id::new(<$marker as ControlProtocol>::NAME), name: $name }
         impl $ty {
            "code" => { kind: Unsigned, derived: false, required: false, description: "code", reflect: code },
            "identifier" => { kind: Unsigned, derived: false, required: false, description: "identifier", reflect: identifier },
            "options" => { kind: List, derived: false, required: false, description: "Ordered control protocol options", children: OPTIONS, reflect: options },
            "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
         }
        }
        message_codec!($codec, $ty, $schema, ppp_control_layout_wire);
    };
}
ppp_control_layer!(PppLcp, Lcp, ppplcp_schema, "PppLcp", PppLcpCodec);
ppp_control_layer!(PppIpcp, Ipcp, pppipcp_schema, "PppIpcp", PppIpcpCodec);
ppp_control_layer!(
    PppIpv6cp,
    Ipv6cp,
    pppipv6cp_schema,
    "PppIpv6cp",
    PppIpv6cpCodec
);

fn ppp_control_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let mut fields = Vec::new();
    if !b.is_empty() {
        fields.push(crate::layout::FieldLayout {
            name: "code",
            range: crate::layout::ByteRange::new(0, 1),
        });
    }
    if 2 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "identifier",
            range: crate::layout::ByteRange::new(1, 2),
        });
    }
    fields
}
impl<P: ControlProtocol> PppControl<P> {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.code == 0 {
            return Err(invalid(P::NAME, "zero code"));
        }
        let mut p = Writer::new(P::NAME, c.remaining_packet_bytes);
        if matches!(self.code, 1..=4) {
            if !self.data.is_empty() {
                return Err(invalid(P::NAME, "configuration uses options, not data"));
            }
            for item in &self.options.0 {
                let kind = u8::try_from(number(item, "kind", P::NAME)?)
                    .map_err(|_| invalid(P::NAME, "option kind overflow"))?;
                let b = data(item, "value", P::NAME)?;
                p.u8(kind)?;
                p.u8(u8::try_from(b.len() + 2)
                    .map_err(|_| invalid(P::NAME, "option length overflow"))?)?;
                p.put(b)?;
            }
        } else {
            if !self.options.0.is_empty() {
                return Err(invalid(P::NAME, "nonconfiguration message uses data"));
            }
            p.put(&self.data)?;
        }
        let mut w = Writer::new(P::NAME, c.remaining_packet_bytes);
        w.u8(self.code)?;
        w.u8(self.identifier)?;
        w.u16(
            u16::try_from(p.bytes.len() + 4)
                .map_err(|_| invalid(P::NAME, "message length overflow"))?,
        )?;
        w.put(&p.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(P::NAME, &b);
        let mut s = Self {
            code: r.u8()?,
            identifier: r.u8()?,
            ..Self::default()
        };
        let len = r.u16()? as usize;
        if len != b.len() || s.code == 0 {
            return Err(invalid(P::NAME, "invalid control header"));
        }
        if matches!(s.code, 1..=4) {
            while r.left() > 0 {
                if s.options.0.len() == MAX_RECORDS {
                    return Err(invalid(P::NAME, "too many options"));
                }
                let kind = r.u8()?;
                let len = r.u8()?;
                if len < 2 {
                    return Err(invalid(P::NAME, "option shorter than header"));
                }
                s.options.0.push(record([
                    ("kind", kind.into()),
                    (
                        "value",
                        Bytes::copy_from_slice(r.take(len as usize - 2)?).into(),
                    ),
                ]));
            }
        } else {
            s.data = Bytes::copy_from_slice(r.rest());
        }
        Ok(s)
    }
}
