// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    super::{Budget, Error, Limits, extend, take, u16_at, u32_at},
    Dhcpv6,
};
use bytes::Bytes;
use std::net::Ipv6Addr;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Duid {
    pub kind: u16,
    pub data: Bytes,
}
impl Duid {
    fn with_identifier(kind: u16, prefix: &[u8], identifier: &[u8]) -> Result<Self, Error> {
        if identifier.is_empty() {
            return Err(Error::Invalid("empty DUID identifier"));
        }
        if prefix.len().saturating_add(identifier.len()) > 65_533 {
            return Err(Error::Limit("DUID bytes"));
        }
        let mut data = prefix.to_vec();
        data.extend_from_slice(identifier);
        Ok(Self {
            kind,
            data: data.into(),
        })
    }
    pub fn link_layer(hardware_type: u16, address: impl AsRef<[u8]>) -> Result<Self, Error> {
        Self::with_identifier(3, &hardware_type.to_be_bytes(), address.as_ref())
    }
    pub fn link_layer_time(
        hardware_type: u16,
        time: u32,
        address: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        let mut prefix = [0; 6];
        prefix[..2].copy_from_slice(&hardware_type.to_be_bytes());
        prefix[2..].copy_from_slice(&time.to_be_bytes());
        Self::with_identifier(1, &prefix, address.as_ref())
    }
    pub fn enterprise(enterprise: u32, identifier: impl AsRef<[u8]>) -> Result<Self, Error> {
        Self::with_identifier(2, &enterprise.to_be_bytes(), identifier.as_ref())
    }
    pub fn uuid(uuid: [u8; 16]) -> Self {
        Self {
            kind: 4,
            data: Bytes::copy_from_slice(&uuid),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Option6 {
    pub code: u16,
    pub value: Value6,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value6 {
    Identifier(Duid),
    Association {
        iaid: u32,
        t1: u32,
        t2: u32,
        options: Vec<Option6>,
    },
    /// Historical IA_TA, retained for captures predating RFC 9915.
    TemporaryAssociation {
        iaid: u32,
        options: Vec<Option6>,
    },
    Address {
        address: Ipv6Addr,
        preferred_lifetime: u32,
        valid_lifetime: u32,
        options: Vec<Option6>,
    },
    Prefix {
        prefix: Ipv6Addr,
        prefix_length: u8,
        preferred_lifetime: u32,
        valid_lifetime: u32,
        options: Vec<Option6>,
    },
    Requested(Vec<u16>),
    Byte(u8),
    Number(u16),
    Seconds(u32),
    Relay(Box<Dhcpv6>),
    Status {
        code: u16,
        message: Bytes,
    },
    /// DNS servers or the historical Server Unicast option.
    Addresses(Vec<Ipv6Addr>),
    Flag,
    Raw(Bytes),
}
impl Option6 {
    pub fn client_identifier(duid: Duid) -> Self {
        Self {
            code: 1,
            value: Value6::Identifier(duid),
        }
    }
    pub fn server_identifier(duid: Duid) -> Self {
        Self {
            code: 2,
            value: Value6::Identifier(duid),
        }
    }
    pub fn ia_na(iaid: u32, t1: u32, t2: u32, options: Vec<Option6>) -> Self {
        Self {
            code: 3,
            value: Value6::Association {
                iaid,
                t1,
                t2,
                options,
            },
        }
    }
    pub fn ia_pd(iaid: u32, t1: u32, t2: u32, options: Vec<Option6>) -> Self {
        Self {
            code: 25,
            value: Value6::Association {
                iaid,
                t1,
                t2,
                options,
            },
        }
    }
    pub fn address(address: Ipv6Addr, preferred_lifetime: u32, valid_lifetime: u32) -> Self {
        Self {
            code: 5,
            value: Value6::Address {
                address,
                preferred_lifetime,
                valid_lifetime,
                options: Vec::new(),
            },
        }
    }
    pub fn raw(code: u16, data: impl Into<Bytes>) -> Self {
        Self {
            code,
            value: Value6::Raw(data.into()),
        }
    }
    pub fn data(&self) -> Result<Bytes, Error> {
        let mut budget = Budget::new(Limits::default(), 0)?;
        budget.option(0)?;
        encode_value(self, &mut budget, 0).map(Into::into)
    }
}
pub(super) fn decode(
    bytes: &Bytes,
    budget: &mut Budget,
    depth: usize,
) -> Result<Vec<Option6>, Error> {
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
                    options: decode(&data.slice(12..), budget, depth + 1)?,
                }
            }
            4 => {
                take(&data, 0, 4)?;
                Value6::TemporaryAssociation {
                    iaid: u32_at(&data, 0)?,
                    options: decode(&data.slice(4..), budget, depth + 1)?,
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
                    options: decode(&data.slice(24..), budget, depth + 1)?,
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
                        options: decode(&data.slice(25..), budget, depth + 1)?,
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
pub(super) fn encode(
    options: &[Option6],
    budget: &mut Budget,
    depth: usize,
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    for option in options {
        budget.option(depth)?;
        let data = encode_value(option, budget, depth)?;
        let length = u16::try_from(data.len()).map_err(|_| Error::Limit("DHCPv6 option bytes"))?;
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
            let nested = encode(
                options,
                budget,
                depth + 1,
                maximum.saturating_sub(output.len()),
            )?;
            extend(&mut output, &nested, maximum)?;
        }
        (Value6::TemporaryAssociation { iaid, options }, 4) => {
            extend(&mut output, &iaid.to_be_bytes(), maximum)?;
            let nested = encode(
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
            let nested = encode(
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
            let nested = encode(
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
            extend(&mut output, &value.to_be_bytes(), maximum)?
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
