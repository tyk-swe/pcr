// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IEC 60870-5-104 I/S/U frames and ASDU headers using two-byte cause/common-address fields. Information objects retain their bytes.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::field;
use crate::protocol::common::{invalid, out_of_range, unsupported, wrong_type};
use crate::protocol::message::{Reader, Writer, message_codec};
use bytes::Bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    I,
    S,
    U,
}

impl FrameType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::I => "i",
            Self::S => "s",
            Self::U => "u",
        }
    }
}

fn set_frame_type(layer: &mut Iec104, value: field::Value, name: &str) -> Result<(), field::Error> {
    let field::Value::Text(text) = value else {
        return Err(wrong_type(iec104_schema(), name, "text"));
    };
    layer.frame_type = match text.as_str() {
        _ if text.eq_ignore_ascii_case("i") => FrameType::I,
        _ if text.eq_ignore_ascii_case("s") => FrameType::S,
        _ if text.eq_ignore_ascii_case("u") => FrameType::U,
        _ => return Err(out_of_range(iec104_schema(), name)),
    };
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Iec104 {
    pub frame_type: FrameType,
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
            frame_type: FrameType::I,
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
 fn iec104_schema() => { protocol: crate::protocol::BuiltinProtocol::Iec104.id(), name: "Iec104" }
 impl Iec104 {
    "frame_type" => { kind: Text, derived: false, required: false, description: "i, s or u", get |layer| Some(field::Value::Text(layer.frame_type.as_str().to_owned())), set |layer, value, name| set_frame_type(layer, value, name) },
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
message_codec!(Iec104Codec, Iec104, iec104_schema);

const NAME: &str = crate::protocol::BuiltinProtocol::Iec104.as_str();
impl Iec104 {
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        if self.send_sequence > 32767 || self.receive_sequence > 32767 {
            return Err(invalid(NAME, "sequence exceeds 15 bits"));
        }
        let mut p = Writer::new(NAME, 253);
        match self.frame_type {
            FrameType::I => {
                p.le16(self.send_sequence << 1)?;
                p.le16(self.receive_sequence << 1)?;
                p.u8(self.asdu_type)?;
                p.u8(self.variable_structure)?;
                p.le16(self.cause)?;
                p.le16(self.common_address)?;
                p.put(&self.objects)?;
            }
            FrameType::S => {
                p.le16(1)?;
                p.le16(self.receive_sequence << 1)?;
            }
            FrameType::U => {
                if !matches!(self.u_control, 7 | 11 | 19 | 35 | 67 | 131) {
                    return Err(invalid(NAME, "invalid U control"));
                }
                p.put(&[self.u_control, 0, 0, 0])?;
            }
        }
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.put(&[0x68, p.bytes.len() as u8])?;
        w.put(&p.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
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
            s.frame_type = FrameType::I;
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
            s.frame_type = FrameType::S;
            s.receive_sequence = u16::from_le_bytes([control[2], control[3]]) >> 1;
        } else {
            if !matches!(control[0], 7 | 11 | 19 | 35 | 67 | 131) || control[1..] != [0, 0, 0] {
                return Err(invalid(NAME, "invalid U control"));
            }
            s.frame_type = FrameType::U;
            s.u_control = control[0];
        }
        r.finish()?;
        Ok((s, Vec::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Codec as _;
    use std::collections::BTreeMap;

    #[test]
    fn construction_rejects_unknown_frame_type() {
        let fields =
            BTreeMap::from([("frame_type".to_owned(), field::Value::Text("x".to_owned()))]);
        assert!(Iec104Codec.construct(&fields).is_err());
        let fields =
            BTreeMap::from([("frame_type".to_owned(), field::Value::Text("u".to_owned()))]);
        let layer = Iec104Codec.construct(&fields).unwrap();
        assert_eq!(
            layer.field_by_index(0),
            Some(field::Value::Text("u".to_owned()))
        );
    }
}
