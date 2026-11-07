// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Modbus TCP MBAP and common function PDUs. Packet-only decoding preserves direction-ambiguous PDUs as raw; interpret uses an established connection role.

use crate::codec::{DecodeContext, EncodeContext, Error};
use crate::field;
use crate::protocol::common::{invalid, out_of_range, unsupported, wrong_type};
use crate::protocol::message::{Reader, Writer, message_codec};
use bytes::Bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PduForm {
    Request,
    Response,
    Exception,
    /// Direction not yet known; the PDU body stays in `data`.
    Raw,
}

impl PduForm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Exception => "exception",
            Self::Raw => "raw",
        }
    }
}

fn set_form(layer: &mut ModbusTcp, value: field::Value, name: &str) -> Result<(), field::Error> {
    let field::Value::Text(text) = value else {
        return Err(wrong_type(modbustcp_schema(), name, "text"));
    };
    layer.form = match text.as_str() {
        _ if text.eq_ignore_ascii_case("request") => PduForm::Request,
        _ if text.eq_ignore_ascii_case("response") => PduForm::Response,
        _ if text.eq_ignore_ascii_case("exception") => PduForm::Exception,
        _ if text.eq_ignore_ascii_case("raw") => PduForm::Raw,
        _ => return Err(out_of_range(modbustcp_schema(), name)),
    };
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModbusTcp {
    pub transaction_id: u16,
    pub unit_id: u8,
    pub function: u8,
    pub form: PduForm,
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
            form: PduForm::Request,
            address: 0,
            quantity: 1,
            value: 0,
            exception_code: 1,
            data: Bytes::new(),
        }
    }
}
crate::reflective_layer! {
 fn modbustcp_schema() => { protocol: crate::protocol::BuiltinProtocol::ModbusTcp.id(), name: "ModbusTcp" }
 impl ModbusTcp {
    "transaction_id" => { kind: Unsigned, derived: false, required: false, description: "transaction id", reflect: transaction_id },
    "unit_id" => { kind: Unsigned, derived: false, required: false, description: "unit id", reflect: unit_id },
    "function" => { kind: Unsigned, derived: false, required: false, description: "function", reflect: function },
    "form" => { kind: Text, derived: false, required: false, description: "request, response, exception or raw (unknown direction)", get |layer| Some(field::Value::Text(layer.form.as_str().to_owned())), set |layer, value, name| set_form(layer, value, name) },
    "address" => { kind: Unsigned, derived: false, required: false, description: "address", reflect: address },
    "quantity" => { kind: Unsigned, derived: false, required: false, description: "quantity", reflect: quantity },
    "value" => { kind: Unsigned, derived: false, required: false, description: "value", reflect: value },
    "exception_code" => { kind: Unsigned, derived: false, required: false, description: "exception code", reflect: exception_code },
    "data" => { kind: Bytes, derived: false, required: false, description: "data", reflect: data },
 }
}
message_codec!(ModbusTcpCodec, ModbusTcp, modbustcp_schema);

const NAME: &str = crate::protocol::BuiltinProtocol::ModbusTcp.as_str();
impl ModbusTcp {
    pub(crate) fn interpret_layer(
        layer: &mut dyn crate::layer::Layer,
        response: bool,
    ) -> Option<Result<(), Error>> {
        layer
            .downcast_mut::<Self>()
            .map(|modbus| modbus.interpret(response))
    }
    fn validate_fields(&self) -> Result<(), Error> {
        let quantity_limit = match (self.form, self.function) {
            (PduForm::Request, 1 | 2) => Some(2000),
            (PduForm::Request, 3 | 4) => Some(125),
            (PduForm::Request | PduForm::Response, 15) => Some(1968),
            (PduForm::Request | PduForm::Response, 16) => Some(123),
            _ => None,
        };
        if quantity_limit.is_some_and(|limit| self.quantity == 0 || self.quantity > limit) {
            return Err(invalid(NAME, "quantity is outside the function's range"));
        }
        if matches!(self.form, PduForm::Request | PduForm::Response)
            && self.function == 5
            && !matches!(self.value, 0 | 0xff00)
        {
            return Err(invalid(NAME, "single-coil value must be 0x0000 or 0xff00"));
        }
        if self.form == PduForm::Response
            && matches!(self.function, 1..=4)
            && (self.data.is_empty()
                || self.data.len() > 250
                || (matches!(self.function, 3 | 4) && !self.data.len().is_multiple_of(2)))
        {
            return Err(invalid(NAME, "invalid read-response byte count"));
        }
        Ok(())
    }
    fn reject_uncarried_fields(&self) -> Result<(), Error> {
        let default = Self::default();
        let typed = matches!(self.form, PduForm::Request | PduForm::Response);
        let write_single = typed && matches!(self.function, 5 | 6);
        let write_multiple = typed && matches!(self.function, 15 | 16);
        let read_request = self.form == PduForm::Request && matches!(self.function, 1..=4);
        let fields = [
            (
                "address",
                read_request || write_single || write_multiple,
                self.address == default.address,
            ),
            (
                "quantity",
                read_request || write_multiple,
                self.quantity == default.quantity,
            ),
            ("value", write_single, self.value == default.value),
            (
                "exception_code",
                self.form == PduForm::Exception,
                self.exception_code == default.exception_code,
            ),
            (
                "data",
                self.form == PduForm::Raw
                    || self.form == PduForm::Request && write_multiple
                    || self.form == PduForm::Response && matches!(self.function, 1..=4),
                self.data == default.data,
            ),
        ];
        if let Some((field, ..)) = fields
            .iter()
            .find(|(_, carried, unchanged)| !carried && !unchanged)
        {
            return Err(invalid(
                NAME,
                format!(
                    "{field} is not part of {} function {}",
                    self.form.as_str(),
                    self.function
                ),
            ));
        }
        Ok(())
    }
    fn encode_wire(&self, c: &EncodeContext<'_>) -> Result<Vec<u8>, Error> {
        self.validate_fields()?;
        self.reject_uncarried_fields()?;
        let mut p = Writer::new(NAME, 252);
        let mut function = self.function;
        match self.form {
            PduForm::Raw => p.put(&self.data)?,
            PduForm::Exception => {
                function |= 128;
                p.u8(self.exception_code)?;
            }
            PduForm::Request => match function {
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
            PduForm::Response => match function {
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
    fn parse_wire(
        b: Bytes,
        _: &DecodeContext<'_>,
    ) -> Result<(Self, Vec<crate::layout::FieldLayout>), Error> {
        let mut r = Reader::new(NAME, &b);
        r.mark(0, 0..2);
        r.mark(1, 6..7);
        r.mark(2, 7..8);
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
            form: PduForm::Raw,
            data: Bytes::copy_from_slice(r.rest()),
            ..Self::default()
        };
        if function & 128 != 0 {
            if s.data.len() != 1 {
                return Err(invalid(NAME, "exception must contain one code"));
            }
            s.form = PduForm::Exception;
            s.exception_code = s.data[0];
            s.data = Bytes::new();
        }
        Ok((s, r.take_layouts()))
    }
    /// Interpret a direction-ambiguous PDU after its connection role is known.
    pub fn interpret(&mut self, response: bool) -> Result<(), Error> {
        if self.form != PduForm::Raw {
            return Ok(());
        }
        let mut r = Reader::new(NAME, &self.data);
        let mut result = self.clone();
        result.form = if response {
            PduForm::Response
        } else {
            PduForm::Request
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Codec as _;
    use std::collections::BTreeMap;

    #[test]
    fn construction_rejects_unknown_form() {
        let fields =
            BTreeMap::from([("form".to_owned(), field::Value::Text("sideways".to_owned()))]);
        assert!(ModbusTcpCodec.construct(&fields).is_err());
        let fields = BTreeMap::from([(
            "form".to_owned(),
            field::Value::Text("exception".to_owned()),
        )]);
        let layer = ModbusTcpCodec.construct(&fields).unwrap();
        assert_eq!(
            layer.field_by_index(3),
            Some(field::Value::Text("exception".to_owned()))
        );
    }
}
