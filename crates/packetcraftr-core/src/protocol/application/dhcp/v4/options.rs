// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::super::{Budget, Error, extend, take};
use bytes::Bytes;
use std::net::Ipv4Addr;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Option4 {
    pub code: u8,
    pub value: Value4,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value4 {
    MessageType(u8),
    Address(Ipv4Addr),
    Addresses(Vec<Ipv4Addr>),
    Seconds(u32),
    Number(u16),
    Codes(Bytes),
    Text(Bytes),
    ClientIdentifier {
        hardware_type: u8,
        identifier: Bytes,
    },
    Overload(u8),
    Raw(Bytes),
}
impl Option4 {
    pub fn message_type(value: u8) -> Self {
        Self {
            code: 53,
            value: Value4::MessageType(value),
        }
    }
    pub fn server_identifier(value: Ipv4Addr) -> Self {
        Self {
            code: 54,
            value: Value4::Address(value),
        }
    }
    pub fn lease_time(seconds: u32) -> Self {
        Self {
            code: 51,
            value: Value4::Seconds(seconds),
        }
    }
    pub fn requested_address(value: Ipv4Addr) -> Self {
        Self {
            code: 50,
            value: Value4::Address(value),
        }
    }
    pub fn parameter_request(codes: impl Into<Bytes>) -> Self {
        Self {
            code: 55,
            value: Value4::Codes(codes.into()),
        }
    }
    pub fn raw(code: u8, data: impl Into<Bytes>) -> Self {
        Self {
            code,
            value: Value4::Raw(data.into()),
        }
    }
    pub fn data(&self) -> Result<Bytes, Error> {
        let mut output = Vec::new();
        match (&self.value, self.code) {
            (Value4::MessageType(value), 53) => output.push(*value),
            (Value4::Address(value), 1 | 16 | 28 | 32 | 50 | 54) => {
                output.extend_from_slice(&value.octets())
            }
            (Value4::Addresses(values), 3..=11 | 41 | 42 | 44 | 45 | 48 | 49 | 65 | 68..=76) => {
                if values.is_empty() || values.len() > 63 {
                    return Err(Error::Limit("IPv4 option addresses"));
                }
                for value in values {
                    output.extend_from_slice(&value.octets());
                }
            }
            (Value4::Seconds(value), 24 | 35 | 38 | 51 | 58 | 59) => {
                output.extend_from_slice(&value.to_be_bytes())
            }
            (Value4::Number(value), 13 | 22 | 26 | 57) => {
                output.extend_from_slice(&value.to_be_bytes())
            }
            (Value4::Codes(value), 55)
            | (Value4::Text(value), 12 | 14 | 15 | 17 | 18 | 40 | 56 | 60 | 64 | 66 | 67) => {
                extend(&mut output, value, 255)?
            }
            (
                Value4::ClientIdentifier {
                    hardware_type,
                    identifier,
                },
                61,
            ) => {
                if identifier.is_empty() {
                    return Err(Error::Invalid("empty client identifier"));
                }
                output.push(*hardware_type);
                extend(&mut output, identifier, 255)?;
            }
            (Value4::Overload(value), 52) if (1..=3).contains(value) => output.push(*value),
            (Value4::Raw(value), code) if !matches!(code, 0 | 255) => {
                extend(&mut output, value, 255)?
            }
            _ => {
                return Err(Error::Invalid(
                    "DHCPv4 option code and typed value disagree",
                ));
            }
        }
        if output.len() > 255 {
            return Err(Error::Limit("DHCPv4 option bytes"));
        }
        Ok(output.into())
    }
}
/// Noncanonical fixed-width bodies remain raw, including pieces of RFC 3396
/// concatenated options. TLV truncation still fails before reading past input.
fn value(code: u8, data: Bytes) -> Value4 {
    match (code, data.len()) {
        (53, 1) => Value4::MessageType(data[0]),
        (52, 1) if (1..=3).contains(&data[0]) => Value4::Overload(data[0]),
        (1 | 16 | 28 | 32 | 50 | 54, 4) => {
            Value4::Address(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
        }
        (3..=11 | 41 | 42 | 44 | 45 | 48 | 49 | 65 | 68..=76, n) if n > 0 && n % 4 == 0 => {
            Value4::Addresses(
                data.as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
                    .collect(),
            )
        }
        (24 | 35 | 38 | 51 | 58 | 59, 4) => Value4::Seconds(u32::from_be_bytes(
            data.as_ref().try_into().expect("four bytes"),
        )),
        (13 | 22 | 26 | 57, 2) => Value4::Number(u16::from_be_bytes(
            data.as_ref().try_into().expect("two bytes"),
        )),
        (55, _) => Value4::Codes(data),
        (12 | 14 | 15 | 17 | 18 | 40 | 56 | 60 | 64 | 66 | 67, _) => Value4::Text(data),
        (61, n) if n >= 2 => Value4::ClientIdentifier {
            hardware_type: data[0],
            identifier: data.slice(1..),
        },
        _ => Value4::Raw(data),
    }
}
pub(super) fn decode(bytes: &Bytes, budget: &mut Budget) -> Result<(Vec<Option4>, Bytes), Error> {
    let mut position = 0;
    let mut options = Vec::new();
    while position < bytes.len() {
        let code = bytes[position];
        position += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            return Ok((options, bytes.slice(position..)));
        }
        budget.option(0)?;
        let length = usize::from(*take(bytes, position, 1)?.first().expect("one byte"));
        position += 1;
        take(bytes, position, length)?;
        options.push(Option4 {
            code,
            value: value(code, bytes.slice(position..position + length)),
        });
        position += length;
    }
    Err(Error::Invalid("DHCPv4 option area has no end marker"))
}
pub(super) fn encode(
    options: &[Option4],
    budget: &mut Budget,
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    for option in options {
        budget.option(0)?;
        let data = option.data()?;
        extend(&mut output, &[option.code, data.len() as u8], maximum)?;
        extend(&mut output, &data, maximum)?;
    }
    extend(&mut output, &[255], maximum)?;
    Ok(output)
}

pub(super) fn overload(options: &[Option4]) -> Result<u8, Error> {
    let mut found = options.iter().filter(|option| option.code == 52);
    let Some(first) = found.next() else {
        return Ok(0);
    };
    if found.next().is_some() {
        return Err(Error::Invalid("ambiguous repeated overload option"));
    }
    Ok(if let Value4::Overload(value) = first.value {
        value
    } else {
        0
    })
}
