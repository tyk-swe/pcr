// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use bytes::Bytes;

use super::super::codec::{self as shared, Budget, Message, extend, take, u16_at, u32_at};
use super::super::{Error, Limits};
use super::reflection::{layout, schema};
use super::{Dhcpv4, Option4, Value4};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Id, Layer, Schema},
    layout::FieldLayout,
    protocol::BuiltinProtocol,
};

const NAME: &str = BuiltinProtocol::Dhcpv4.as_str();
const MAGIC_COOKIE: &[u8; 4] = b"\x63\x82\x53\x63";

impl TryFrom<Bytes> for Dhcpv4 {
    type Error = Error;

    fn try_from(wire: Bytes) -> Result<Self, Self::Error> {
        Self::from_wire_with_limits(wire, Limits::default())
    }
}

impl TryFrom<Vec<u8>> for Dhcpv4 {
    type Error = Error;

    fn try_from(wire: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(Bytes::from(wire))
    }
}

impl TryFrom<&[u8]> for Dhcpv4 {
    type Error = Error;

    fn try_from(wire: &[u8]) -> Result<Self, Self::Error> {
        Budget::new(Limits::default(), wire.len())?;
        Self::try_from(Bytes::copy_from_slice(wire))
    }
}

impl Dhcpv4 {
    pub fn from_wire_with_limits(wire: impl Into<Bytes>, limits: Limits) -> Result<Self, Error> {
        let wire = wire.into();
        let mut budget = Budget::new(limits, wire.len())?;
        take(&wire, 0, 240)?;
        if &wire[236..240] != MAGIC_COOKIE {
            return Err(Error::Invalid("DHCPv4 magic cookie"));
        }
        if wire[2] > 16 {
            return Err(Error::Invalid("hardware address length exceeds chaddr"));
        }
        let (options, trailing) = decode_options(&wire.slice(240..), &mut budget)?;
        let overload = overload(&options)?;
        let file_options = if overload & 1 != 0 {
            decode_options(&wire.slice(108..236), &mut budget)?.0
        } else {
            Vec::new()
        };
        let server_name_options = if overload & 2 != 0 {
            decode_options(&wire.slice(44..108), &mut budget)?.0
        } else {
            Vec::new()
        };
        let address = |offset| {
            Ipv4Addr::from(<[u8; 4]>::try_from(&wire[offset..offset + 4]).expect("fixed address"))
        };
        Ok(Self {
            operation: wire[0],
            hardware_type: wire[1],
            hardware_length: wire[2],
            hops: wire[3],
            transaction_id: u32_at(&wire, 4)?,
            seconds: u16_at(&wire, 8)?,
            flags: u16_at(&wire, 10)?,
            client_address: address(12),
            your_address: address(16),
            server_address: address(20),
            gateway_address: address(24),
            client_hardware_address: wire[28..44].try_into().expect("fixed chaddr"),
            server_name: wire[44..108].try_into().expect("fixed sname"),
            boot_file: wire[108..236].try_into().expect("fixed file"),
            options,
            file_options,
            server_name_options,
            trailing,
            wire,
        })
    }
    pub fn to_wire(&self) -> Result<Bytes, Error> {
        self.to_wire_with_limits(Limits::default())
    }
    pub fn to_wire_with_limits(&self, limits: Limits) -> Result<Bytes, Error> {
        if !self.wire.is_empty()
            && Self::from_wire_with_limits(self.wire.clone(), limits)
                .is_ok_and(|original| original == *self)
        {
            return Ok(self.wire.clone());
        }
        if self.hardware_length > 16 {
            return Err(Error::Invalid("hardware address length exceeds chaddr"));
        }
        let mut budget = Budget::new(limits, 240)?;
        let maximum = budget.limits.max_message_bytes;
        if self
            .options
            .len()
            .saturating_add(self.file_options.len())
            .saturating_add(self.server_name_options.len())
            > budget.limits.max_options
        {
            return Err(Error::Limit("option count"));
        }
        let mut primary = self.options.clone();
        let existing = overload(&primary)?;
        let needed = u8::from(!self.file_options.is_empty())
            | (u8::from(!self.server_name_options.is_empty()) << 1);
        if existing != 0 && needed & !existing != 0 {
            return Err(Error::Invalid(
                "overload option disagrees with option areas",
            ));
        }
        if existing == 0 && needed != 0 {
            primary.push(Option4 {
                code: 52,
                value: Value4::Overload(needed),
            });
        }
        let overload = existing | needed;
        let mut output = Vec::new();
        extend(
            &mut output,
            &[
                self.operation,
                self.hardware_type,
                self.hardware_length,
                self.hops,
            ],
            maximum,
        )?;
        extend(&mut output, &self.transaction_id.to_be_bytes(), maximum)?;
        extend(&mut output, &self.seconds.to_be_bytes(), maximum)?;
        extend(&mut output, &self.flags.to_be_bytes(), maximum)?;
        for address in [
            self.client_address,
            self.your_address,
            self.server_address,
            self.gateway_address,
        ] {
            extend(&mut output, &address.octets(), maximum)?;
        }
        extend(&mut output, &self.client_hardware_address, maximum)?;
        let mut sname = self.server_name;
        let mut file = self.boot_file;
        if overload & 1 != 0 {
            let encoded = encode_options(&self.file_options, &mut budget, 128)?;
            file[..encoded.len()].copy_from_slice(&encoded);
        }
        if overload & 2 != 0 {
            let encoded = encode_options(&self.server_name_options, &mut budget, 64)?;
            sname[..encoded.len()].copy_from_slice(&encoded);
        }
        extend(&mut output, &sname, maximum)?;
        extend(&mut output, &file, maximum)?;
        extend(&mut output, MAGIC_COOKIE, maximum)?;
        let encoded = encode_options(&primary, &mut budget, maximum.saturating_sub(output.len()))?;
        extend(&mut output, &encoded, maximum)?;
        extend(&mut output, &self.trailing, maximum)?;
        let wire: Bytes = output.into();
        Self::from_wire_with_limits(wire.clone(), limits)?;
        Ok(wire)
    }
}
impl Option4 {
    pub fn data(&self) -> Result<Bytes, Error> {
        let mut output = Vec::new();
        match (&self.value, self.code) {
            (Value4::MessageType(value), 53) => output.push(*value),
            (Value4::Address(value), 1 | 16 | 28 | 32 | 50 | 54) => {
                output.extend_from_slice(&value.octets());
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
                output.extend_from_slice(&value.to_be_bytes());
            }
            (Value4::Number(value), 13 | 22 | 26 | 57) => {
                output.extend_from_slice(&value.to_be_bytes());
            }
            (Value4::Codes(value), 55)
            | (Value4::Text(value), 12 | 14 | 15 | 17 | 18 | 40 | 56 | 60 | 64 | 66 | 67) => {
                extend(&mut output, value, 255)?;
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
                extend(&mut output, value, 255)?;
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
fn decode_options(bytes: &Bytes, budget: &mut Budget) -> Result<(Vec<Option4>, Bytes), Error> {
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
fn encode_options(
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

fn overload(options: &[Option4]) -> Result<u8, Error> {
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

impl Message for Dhcpv4 {
    const NAME: &'static str = NAME;

    fn decode_wire(wire: Bytes) -> Result<Self, Error> {
        Self::try_from(wire)
    }

    fn encode_wire(&self, limits: Limits) -> Result<Bytes, Error> {
        self.to_wire_with_limits(limits)
    }

    fn layout() -> Vec<FieldLayout> {
        layout()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Dhcpv4Codec;

impl LayerCodec for Dhcpv4Codec {
    fn protocol_id(&self) -> &'static Id {
        &schema().protocol
    }

    fn published_schema(&self) -> Option<&'static Schema> {
        Some(schema())
    }

    fn accepts_decoded_protocol(&self, protocol: &Id) -> bool {
        matches!(protocol.as_str(), NAME | "raw")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        shared::encode::<Dhcpv4>(layer, payload, context)
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        if input.get(236..240) != Some(MAGIC_COOKIE.as_slice()) {
            return Ok(shared::raw(input));
        }
        shared::decode::<Dhcpv4>(input)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        shared::make_layer::<Dhcpv4>(fields)
    }
}
