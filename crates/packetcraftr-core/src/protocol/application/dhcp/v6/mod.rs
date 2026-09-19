// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod options;
mod reflection;
use super::{Budget, Error, Limits, extend, take};
use bytes::Bytes;
pub use options::{Duid, Option6, Value6};
pub(super) use reflection::{layout, schema};
use std::net::Ipv6Addr;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dhcpv6 {
    pub message_type: u8,
    pub transaction_id: u32,
    pub hop_count: u8,
    pub link_address: Ipv6Addr,
    pub peer_address: Ipv6Addr,
    pub options: Vec<Option6>,
    wire: Bytes,
}
impl Default for Dhcpv6 {
    fn default() -> Self {
        Self {
            message_type: 1,
            transaction_id: 0,
            hop_count: 0,
            link_address: Ipv6Addr::UNSPECIFIED,
            peer_address: Ipv6Addr::UNSPECIFIED,
            options: Vec::new(),
            wire: Bytes::new(),
        }
    }
}
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
        Self::try_from(Bytes::copy_from_slice(wire))
    }
}

impl Dhcpv6 {
    pub fn relay_forward(
        hop_count: u8,
        link_address: Ipv6Addr,
        peer_address: Ipv6Addr,
        message: Self,
    ) -> Self {
        Self {
            message_type: 12,
            hop_count,
            link_address,
            peer_address,
            options: vec![Option6 {
                code: 9,
                value: Value6::Relay(Box::new(message)),
            }],
            ..Default::default()
        }
    }
    pub fn is_relay(&self) -> bool {
        matches!(self.message_type, 12 | 13)
    }
    pub fn wire(&self) -> &Bytes {
        &self.wire
    }
    pub fn edit(&mut self, edit: impl FnOnce(&mut Self)) {
        self.wire = Bytes::new();
        edit(self);
    }
    pub fn from_wire_with_limits(wire: impl Into<Bytes>, limits: Limits) -> Result<Self, Error> {
        let wire = wire.into();
        let mut budget = Budget::new(limits, wire.len())?;
        Self::decode(wire, &mut budget, 0)
    }
    fn decode(wire: Bytes, budget: &mut Budget, depth: usize) -> Result<Self, Error> {
        if depth > budget.limits.max_nesting {
            return Err(Error::Limit("relay nesting"));
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
        message.options = options::decode(&wire.slice(offset..), budget, depth)?;
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
            return Err(Error::Limit("relay nesting"));
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
        let options = options::encode(
            &self.options,
            budget,
            depth,
            maximum.saturating_sub(output.len()),
        )?;
        extend(&mut output, &options, maximum)?;
        Ok(output)
    }
}
