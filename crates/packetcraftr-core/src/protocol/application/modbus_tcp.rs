// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Modbus TCP MBAP and common function PDUs. Packet-only decoding preserves direction-ambiguous PDUs as raw; interpret uses an established connection role.

use crate::codec::*;
use crate::protocol::common::*;
use crate::protocol::message::*;
use bytes::Bytes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModbusTcp {
    pub transaction_id: u16,
    pub unit_id: u8,
    pub function: u8,
    pub form: String,
    pub address: u16,
    pub quantity: u16,
    pub value: u16,
    pub exception_code: u8,
    pub data: Bytes,
}
impl Default for ModbusTcp {
    fn default() -> Self {
        Self {
            transaction_id: 0,
            unit_id: 1,
            function: 3,
            form: "request".into(),
            address: 0,
            quantity: 1,
            value: 0,
            exception_code: 1,
            data: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn modbustcp_schema() => { protocol: crate::layer::Id::new("modbus_tcp"), name: "ModbusTcp" }
 impl ModbusTcp {
    "transaction_id" => { kind: Unsigned, derived: false, required: false, description: "transaction id", reflect: transaction_id },
    "unit_id" => { kind: Unsigned, derived: false, required: false, description: "unit id", reflect: unit_id },
    "function" => { kind: Unsigned, derived: false, required: false, description: "function", reflect: function },
    "form" => { kind: Text, derived: false, required: false, description: "request, response, exception or raw (unknown direction)", reflect: form },
    "address" => { kind: Unsigned, derived: false, required: false, description: "address", reflect: address },
    "quantity" => { kind: Unsigned, derived: false, required: false, description: "quantity", reflect: quantity },
    "value" => { kind: Unsigned, derived: false, required: false, description: "value", reflect: value },
    "exception_code" => { kind: Unsigned, derived: false, required: false, description: "exception code", reflect: exception_code },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
 layout fn modbustcp_layout();
}
fn modbustcp_layout_wire(b: &[u8]) -> Vec<crate::layout::FieldLayout> {
    let _ = modbustcp_layout();
    let mut fields = Vec::new();
    if 2 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "transaction_id",
            range: crate::layout::ByteRange::new(0, 2),
        });
    }
    if 7 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "unit_id",
            range: crate::layout::ByteRange::new(6, 7),
        });
    }
    if 8 <= b.len() {
        fields.push(crate::layout::FieldLayout {
            name: "function",
            range: crate::layout::ByteRange::new(7, 8),
        });
    }
    fields
}
message_codec!(
    ModbusTcpCodec,
    ModbusTcp,
    modbustcp_schema,
    modbustcp_layout_wire
);

const NAME: &str = "modbus_tcp";
impl ModbusTcp {
    fn validate_fields(&self) -> Result<(), Error> {
        let quantity_limit = match (self.form.as_str(), self.function) {
            ("request", 1 | 2) => Some(2000),
            ("request", 3 | 4) => Some(125),
            ("request" | "response", 15) => Some(1968),
            ("request" | "response", 16) => Some(123),
            _ => None,
        };
        if quantity_limit.is_some_and(|limit| self.quantity == 0 || self.quantity > limit) {
            return Err(invalid(NAME, "quantity is outside the function's range"));
        }
        if matches!(self.form.as_str(), "request" | "response")
            && self.function == 5
            && !matches!(self.value, 0 | 0xff00)
        {
            return Err(invalid(NAME, "single-coil value must be 0x0000 or 0xff00"));
        }
        if self.form == "response"
            && matches!(self.function, 1..=4)
            && (self.data.is_empty()
                || self.data.len() > 250
                || (matches!(self.function, 3 | 4) && !self.data.len().is_multiple_of(2)))
        {
            return Err(invalid(NAME, "invalid read-response byte count"));
        }
        Ok(())
    }
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        self.validate_fields()?;
        let mut p = Writer::new(NAME, 252);
        let mut function = self.function;
        match self.form.as_str() {
            "raw" => p.put(&self.data)?,
            "exception" => {
                function |= 128;
                p.u8(self.exception_code)?;
            }
            "request" => match function {
                1..=4 => {
                    p.u16(self.address)?;
                    p.u16(self.quantity)?;
                }
                5 | 6 => {
                    p.u16(self.address)?;
                    p.u16(self.value)?;
                }
                15 | 16 => {
                    let count = if function == 15 {
                        usize::from(self.quantity).div_ceil(8)
                    } else {
                        usize::from(self.quantity) * 2
                    };
                    if self.quantity == 0 || self.data.len() != count {
                        return Err(invalid(NAME, "write quantity/data mismatch"));
                    }
                    p.u16(self.address)?;
                    p.u16(self.quantity)?;
                    p.u8(u8::try_from(count).map_err(|_| invalid(NAME, "write data too long"))?)?;
                    p.put(&self.data)?;
                }
                _ => return Err(unsupported(NAME, "unsupported request function")),
            },
            "response" => match function {
                1..=4 => {
                    p.u8(u8::try_from(self.data.len())
                        .map_err(|_| invalid(NAME, "response too long"))?)?;
                    p.put(&self.data)?;
                }
                5 | 6 => {
                    p.u16(self.address)?;
                    p.u16(self.value)?;
                }
                15 | 16 => {
                    p.u16(self.address)?;
                    p.u16(self.quantity)?;
                }
                _ => return Err(unsupported(NAME, "unsupported response function")),
            },
            _ => return Err(invalid(NAME, "unknown PDU form")),
        };
        let mut w = Writer::new(NAME, c.remaining_packet_bytes);
        w.u16(self.transaction_id)?;
        w.u16(0)?;
        w.u16((p.bytes.len() + 2) as u16)?;
        w.u8(self.unit_id)?;
        w.u8(function)?;
        w.put(&p.bytes)?;
        Ok(w.bytes)
    }
    fn parse_wire(b: Bytes, _: &DecodeContext<'_>) -> Result<Self, Error> {
        let mut r = Reader::new(NAME, &b);
        let transaction_id = r.u16()?;
        if r.u16()? != 0 {
            return Err(unsupported(NAME, "non-Modbus protocol identifier"));
        }
        if r.u16()? as usize + 6 != b.len() {
            return Err(invalid(NAME, "MBAP length mismatch"));
        }
        let unit_id = r.u8()?;
        let function = r.u8()?;
        let mut s = Self {
            transaction_id,
            unit_id,
            function,
            form: "raw".into(),
            data: Bytes::copy_from_slice(r.rest()),
            ..Self::default()
        };
        if function & 128 != 0 {
            if s.data.len() != 1 {
                return Err(invalid(NAME, "exception must contain one code"));
            }
            s.form = "exception".into();
            s.exception_code = s.data[0];
            s.data = Bytes::new();
        }
        Ok(s)
    }
    /// Interpret a direction-ambiguous PDU after its connection role is known.
    pub fn interpret(&mut self, response: bool) -> Result<(), Error> {
        if self.form != "raw" {
            return Ok(());
        }
        let mut r = Reader::new(NAME, &self.data);
        let mut result = self.clone();
        result.form = if response {
            "response".into()
        } else {
            "request".into()
        };
        match (self.function, response) {
            (1..=4, true) => {
                let n = r.u8()? as usize;
                result.data = Bytes::copy_from_slice(r.take(n)?);
            }
            (1..=4, false) | (15 | 16, true) => {
                result.address = r.u16()?;
                result.quantity = r.u16()?;
                if result.quantity == 0 {
                    return Err(invalid(NAME, "zero quantity"));
                }
                result.data = Bytes::new();
            }
            (5 | 6, _) => {
                result.address = r.u16()?;
                result.value = r.u16()?;
                result.data = Bytes::new();
            }
            (15 | 16, false) => {
                result.address = r.u16()?;
                result.quantity = r.u16()?;
                let n = r.u8()? as usize;
                let expected = if self.function == 15 {
                    usize::from(result.quantity).div_ceil(8)
                } else {
                    usize::from(result.quantity) * 2
                };
                if result.quantity == 0 || n != expected {
                    return Err(invalid(NAME, "write count mismatch"));
                }
                result.data = Bytes::copy_from_slice(r.take(n)?);
            }
            _ => return Ok(()),
        }
        r.finish()?;
        result.validate_fields()?;
        *self = result;
        Ok(())
    }
}
