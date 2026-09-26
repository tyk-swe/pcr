// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use bytes::Bytes;

use super::super::codec::{self as shared, Budget, Message, extend, take, u16_at, u32_at};
use super::super::{Error, Limit, Limits};
use super::reflection::{layout, schema};
use super::{Dhcpv6, Duid, Option6, Value6};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Id, Layer, Schema},
    layout::FieldLayout,
    protocol::BuiltinProtocol,
};

const NAME: &str = BuiltinProtocol::Dhcpv6.as_str();

impl TryFrom<Bytes> for Dhcpv6 {
    type Error = Error;

    fn try_from(wire: Bytes) -> Result<Self, Self::Error> {
        Self::from_wire_with_limits(wire, Limits::default())
    }
}

impl TryFrom<Vec<u8>> for Dhcpv6 {
    type Error = Error;

    fn try_from(wire: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(Bytes::from(wire))
    }
}

impl TryFrom<&[u8]> for Dhcpv6 {
    type Error = Error;

    fn try_from(wire: &[u8]) -> Result<Self, Self::Error> {
        Budget::new(Limits::default(), wire.len())?;
        Self::try_from(Bytes::copy_from_slice(wire))
    }
}

impl Dhcpv6 {
    pub fn from_wire_with_limits(wire: impl Into<Bytes>, limits: Limits) -> Result<Self, Error> {
        let wire = wire.into();
        let mut budget = Budget::new(limits, wire.len())?;
        Self::decode(wire, &mut budget, 0)
    }
    fn decode(wire: Bytes, budget: &mut Budget, depth: usize) -> Result<Self, Error> {
        if depth > budget.limits.max_nesting {
            return Err(Error::Limit(Limit::RelayNesting));
        }
        take(&wire, 0, 4)?;
        let message_type = wire[0];
        let mut message = Self {
            message_type,
            ..Default::default()
        };
        let offset = if message.is_relay() {
            take(&wire, 0, 34)?;
            message.hop_count = wire[1];
            message.link_address =
                Ipv6Addr::from(<[u8; 16]>::try_from(&wire[2..18]).expect("relay link address"));
            message.peer_address =
                Ipv6Addr::from(<[u8; 16]>::try_from(&wire[18..34]).expect("relay peer address"));
            34
        } else {
            message.transaction_id = u32::from_be_bytes([0, wire[1], wire[2], wire[3]]);
            4
        };
        message.options = decode_options(&wire.slice(offset..), budget, depth)?;
        message.wire = wire;
        Ok(message)
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
        let mut budget = Budget::new(limits, 0)?;
        let wire: Bytes = self.encode(&mut budget, 0)?.into();
        Self::from_wire_with_limits(wire.clone(), limits)?;
        Ok(wire)
    }
    fn encode(&self, budget: &mut Budget, depth: usize) -> Result<Vec<u8>, Error> {
        if depth > budget.limits.max_nesting {
            return Err(Error::Limit(Limit::RelayNesting));
        }
        let maximum = budget.limits.max_message_bytes;
        let mut output = Vec::new();
        extend(&mut output, &[self.message_type], maximum)?;
        if self.is_relay() {
            if self.transaction_id != 0 {
                return Err(Error::Invalid("relay message has no transaction ID field"));
            }
            extend(&mut output, &[self.hop_count], maximum)?;
            extend(&mut output, &self.link_address.octets(), maximum)?;
            extend(&mut output, &self.peer_address.octets(), maximum)?;
        } else {
            if self.transaction_id > 0xffffff {
                return Err(Error::Invalid("DHCPv6 transaction ID exceeds 24 bits"));
            }
            if self.hop_count != 0
                || !self.link_address.is_unspecified()
                || !self.peer_address.is_unspecified()
            {
                return Err(Error::Invalid("ordinary message has no relay fields"));
            }
            extend(
                &mut output,
                &self.transaction_id.to_be_bytes()[1..],
                maximum,
            )?;
        }
        let options = encode_options(
            &self.options,
            budget,
            depth,
            maximum.saturating_sub(output.len()),
        )?;
        extend(&mut output, &options, maximum)?;
        Ok(output)
    }
}
impl Option6 {
    pub fn data(&self) -> Result<Bytes, Error> {
        let mut budget = Budget::new(Limits::default(), 0)?;
        budget.option(0)?;
        encode_value(self, &mut budget, 0).map(Into::into)
    }
}
fn decode_options(bytes: &Bytes, budget: &mut Budget, depth: usize) -> Result<Vec<Option6>, Error> {
    let mut position = 0;
    let mut options = Vec::new();
    while position < bytes.len() {
        budget.option(depth)?;
        let code = u16_at(bytes, position)?;
        let length = usize::from(u16_at(bytes, position + 2)?);
        position += 4;
        take(bytes, position, length)?;
        let data = bytes.slice(position..position + length);
        position += length;
        let value = match code {
            1 | 2 => Value6::Identifier(Duid {
                kind: u16_at(&data, 0)?,
                data: data.slice(2..),
            }),
            3 | 25 => {
                take(&data, 0, 12)?;
                Value6::Association {
                    iaid: u32_at(&data, 0)?,
                    t1: u32_at(&data, 4)?,
                    t2: u32_at(&data, 8)?,
                    options: decode_options(&data.slice(12..), budget, depth + 1)?,
                }
            }
            4 => {
                take(&data, 0, 4)?;
                Value6::TemporaryAssociation {
                    iaid: u32_at(&data, 0)?,
                    options: decode_options(&data.slice(4..), budget, depth + 1)?,
                }
            }
            5 => {
                take(&data, 0, 24)?;
                Value6::Address {
                    address: Ipv6Addr::from(
                        <[u8; 16]>::try_from(&data[..16]).expect("IPv6 address"),
                    ),
                    preferred_lifetime: u32_at(&data, 16)?,
                    valid_lifetime: u32_at(&data, 20)?,
                    options: decode_options(&data.slice(24..), budget, depth + 1)?,
                }
            }
            26 => {
                take(&data, 0, 25)?;
                if data[8] > 128 {
                    Value6::Raw(data)
                } else {
                    Value6::Prefix {
                        preferred_lifetime: u32_at(&data, 0)?,
                        valid_lifetime: u32_at(&data, 4)?,
                        prefix_length: data[8],
                        prefix: Ipv6Addr::from(
                            <[u8; 16]>::try_from(&data[9..25]).expect("IPv6 prefix"),
                        ),
                        options: decode_options(&data.slice(25..), budget, depth + 1)?,
                    }
                }
            }
            6 if length % 2 == 0 => Value6::Requested(
                data.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_be_bytes([b[0], b[1]]))
                    .collect(),
            ),
            7 | 19 if length == 1 => Value6::Byte(data[0]),
            8 if length == 2 => Value6::Number(u16_at(&data, 0)?),
            32 | 82 | 83 if length == 4 => Value6::Seconds(u32_at(&data, 0)?),
            9 => Value6::Relay(Box::new(Dhcpv6::decode(data.clone(), budget, depth + 1)?)),
            13 => Value6::Status {
                code: u16_at(&data, 0)?,
                message: data.slice(2..),
            },
            12 | 23
                if (code == 12 && length == 16)
                    || (code == 23 && length > 0 && length % 16 == 0) =>
            {
                Value6::Addresses(
                    data.as_chunks::<16>()
                        .0
                        .iter()
                        .map(|b| Ipv6Addr::from(*b))
                        .collect(),
                )
            }
            14 | 20 if length == 0 => Value6::Flag,
            _ => Value6::Raw(data),
        };
        options.push(Option6 { code, value });
    }
    Ok(options)
}
fn encode_options(
    options: &[Option6],
    budget: &mut Budget,
    depth: usize,
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    for option in options {
        budget.option(depth)?;
        let data = encode_value(option, budget, depth)?;
        let length =
            u16::try_from(data.len()).map_err(|_| Error::Limit(Limit::Dhcpv6OptionBytes))?;
        extend(&mut output, &option.code.to_be_bytes(), maximum)?;
        extend(&mut output, &length.to_be_bytes(), maximum)?;
        extend(&mut output, &data, maximum)?;
    }
    Ok(output)
}
fn encode_value(option: &Option6, budget: &mut Budget, depth: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let maximum = budget.limits.max_message_bytes.min(65_535);
    match (&option.value, option.code) {
        (Value6::Identifier(duid), 1 | 2) => {
            extend(&mut output, &duid.kind.to_be_bytes(), maximum)?;
            extend(&mut output, &duid.data, maximum)?;
        }
        (
            Value6::Association {
                iaid,
                t1,
                t2,
                options,
            },
            3 | 25,
        ) => {
            for value in [iaid, t1, t2] {
                extend(&mut output, &value.to_be_bytes(), maximum)?;
            }
            let nested = encode_options(
                options,
                budget,
                depth + 1,
                maximum.saturating_sub(output.len()),
            )?;
            extend(&mut output, &nested, maximum)?;
        }
        (Value6::TemporaryAssociation { iaid, options }, 4) => {
            extend(&mut output, &iaid.to_be_bytes(), maximum)?;
            let nested = encode_options(
                options,
                budget,
                depth + 1,
                maximum.saturating_sub(output.len()),
            )?;
            extend(&mut output, &nested, maximum)?;
        }
        (
            Value6::Address {
                address,
                preferred_lifetime,
                valid_lifetime,
                options,
            },
            5,
        ) => {
            extend(&mut output, &address.octets(), maximum)?;
            extend(&mut output, &preferred_lifetime.to_be_bytes(), maximum)?;
            extend(&mut output, &valid_lifetime.to_be_bytes(), maximum)?;
            let nested = encode_options(
                options,
                budget,
                depth + 1,
                maximum.saturating_sub(output.len()),
            )?;
            extend(&mut output, &nested, maximum)?;
        }
        (
            Value6::Prefix {
                prefix,
                prefix_length,
                preferred_lifetime,
                valid_lifetime,
                options,
            },
            26,
        ) => {
            if *prefix_length > 128 {
                return Err(Error::Invalid("IPv6 delegated prefix length"));
            }
            extend(&mut output, &preferred_lifetime.to_be_bytes(), maximum)?;
            extend(&mut output, &valid_lifetime.to_be_bytes(), maximum)?;
            extend(&mut output, &[*prefix_length], maximum)?;
            extend(&mut output, &prefix.octets(), maximum)?;
            let nested = encode_options(
                options,
                budget,
                depth + 1,
                maximum.saturating_sub(output.len()),
            )?;
            extend(&mut output, &nested, maximum)?;
        }
        (Value6::Requested(codes), 6) => {
            for code in codes {
                extend(&mut output, &code.to_be_bytes(), maximum)?;
            }
        }
        (Value6::Byte(value), 7 | 19) => extend(&mut output, &[*value], maximum)?,
        (Value6::Number(value), 8) => extend(&mut output, &value.to_be_bytes(), maximum)?,
        (Value6::Seconds(value), 32 | 82 | 83) => {
            extend(&mut output, &value.to_be_bytes(), maximum)?;
        }
        (Value6::Relay(message), 9) => {
            let message = message.encode(budget, depth + 1)?;
            extend(&mut output, &message, maximum)?;
        }
        (Value6::Status { code, message }, 13) => {
            extend(&mut output, &code.to_be_bytes(), maximum)?;
            extend(&mut output, message, maximum)?;
        }
        (Value6::Addresses(addresses), 12 | 23) => {
            if addresses.is_empty() || (option.code == 12 && addresses.len() != 1) {
                return Err(Error::Invalid("DHCPv6 address option count"));
            }
            for address in addresses {
                extend(&mut output, &address.octets(), maximum)?;
            }
        }
        (Value6::Flag, 14 | 20) => {}
        (Value6::Raw(data), _) => extend(&mut output, data, maximum)?,
        _ => {
            return Err(Error::Invalid(
                "DHCPv6 option code and typed value disagree",
            ));
        }
    }
    Ok(output)
}

impl Message for Dhcpv6 {
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
pub(crate) struct Dhcpv6Codec;

impl LayerCodec for Dhcpv6Codec {
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
        shared::encode::<Dhcpv6>(layer, payload, context)
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        if input.len() < 4 {
            return Ok(shared::raw(input));
        }
        shared::decode::<Dhcpv6>(input)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        shared::make_layer::<Dhcpv6>(fields)
    }
}
