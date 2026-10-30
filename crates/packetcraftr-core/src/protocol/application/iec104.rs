// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IEC 60870-5-104 I/S/U frames and ASDU headers using two-byte cause/common-address fields. Information objects retain their bytes.

use crate::codec::*;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Iec104 {
    pub frame_type: String,
    pub send_sequence: u16,
    pub receive_sequence: u16,
    pub u_control: u8,
    pub asdu_type: u8,
    pub variable_structure: u8,
    pub cause: u16,
    pub common_address: u16,
    pub objects: Bytes,
}
impl Default for Iec104 {
    fn default() -> Self {
        Self {
            frame_type: "i".into(),
            send_sequence: 0,
            receive_sequence: 0,
            u_control: 7,
            asdu_type: 100,
            variable_structure: 1,
            cause: 6,
            common_address: 1,
            objects: Bytes::from_static(&[0, 0, 0, 20]),
        }
    }
}
crate::reflective_layer! {
 fn iec104_schema() => { protocol: crate::layer::Id::new("iec104"), name: "Iec104" }
 impl Iec104 {
    "frame_type" => { kind: Text, derived: false, required: false, description: "i, s or u", reflect: frame_type },
    "send_sequence" => { kind: Unsigned, derived: false, required: false, description: "send sequence", reflect: send_sequence },
    "receive_sequence" => { kind: Unsigned, derived: false, required: false, description: "receive sequence", reflect: receive_sequence },
    "u_control" => { kind: Unsigned, derived: false, required: false, description: "u control", reflect: u_control },
    "asdu_type" => { kind: Unsigned, derived: false, required: false, description: "asdu type", reflect: asdu_type },
    "variable_structure" => { kind: Unsigned, derived: false, required: false, description: "variable structure", reflect: variable_structure },
    "cause" => { kind: Unsigned, derived: false, required: false, description: "cause", reflect: cause },
    "common_address" => { kind: Unsigned, derived: false, required: false, description: "common address", reflect: common_address },
    "objects" => { kind: Bytes, derived: false, required: false, description: "objects", reflect: objects },
 }
}
fn iec104_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let fields = Vec::new();
    let _ = b;
    fields
}
message_codec!(Iec104Codec, Iec104, iec104_schema, iec104_layout_wire);

const NAME: &str = "iec104";
impl Iec104 {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.send_sequence > 32767 || self.receive_sequence > 32767 {
            return Err(invalid(NAME, "sequence exceeds 15 bits"));
        }
        let mut p = Writer::new(NAME, 253);
        match self.frame_type.as_str() {
            "i" => {
                p.le16(self.send_sequence << 1)?;
                p.le16(self.receive_sequence << 1)?;
                p.u8(self.asdu_type)?;
                p.u8(self.variable_structure)?;
                p.le16(self.cause)?;
                p.le16(self.common_address)?;
                p.put(&self.objects)?;
            }
            "s" => {
                p.le16(1)?;
                p.le16(self.receive_sequence << 1)?;
            }
            "u" => {
                if !matches!(self.u_control, 7 | 11 | 19 | 35 | 67 | 131) {
                    return Err(invalid(NAME, "invalid U control"));
                }
                p.put(&[self.u_control, 0, 0, 0])?;
            }
            _ => return Err(invalid(NAME, "unknown frame type")),
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.put(&[0x68, p.bytes.len() as u8])?;
        w.put(&p.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        if r.u8()? != 0x68 {
            return Err(unsupported(NAME, "invalid APDU start"));
        }
        if r.u8()? as usize + 2 != b.len() {
            return Err(invalid(NAME, "APDU length mismatch"));
        }
        let control = r.take(4)?;
        let mut s = Self::default();
        if control[0] & 1 == 0 {
            s.frame_type = "i".into();
            s.send_sequence = u16::from_le_bytes([control[0], control[1]]) >> 1;
            if control[2] & 1 != 0 {
                return Err(invalid(NAME, "reserved receive bit"));
            }
            s.receive_sequence = u16::from_le_bytes([control[2], control[3]]) >> 1;
            s.asdu_type = r.u8()?;
            s.variable_structure = r.u8()?;
            s.cause = r.le16()?;
            s.common_address = r.le16()?;
            s.objects = Bytes::copy_from_slice(r.rest());
        } else if control[0] & 3 == 1 {
            if control[..2] != [1, 0] || control[2] & 1 != 0 {
                return Err(invalid(NAME, "invalid S control"));
            }
            s.frame_type = "s".into();
            s.receive_sequence = u16::from_le_bytes([control[2], control[3]]) >> 1;
        } else {
            if !matches!(control[0], 7 | 11 | 19 | 35 | 67 | 131) || control[1..] != [0, 0, 0] {
                return Err(invalid(NAME, "invalid U control"));
            }
            s.frame_type = "u".into();
            s.u_control = control[0];
        }
        r.finish()?;
        Ok(s)
    }
}
