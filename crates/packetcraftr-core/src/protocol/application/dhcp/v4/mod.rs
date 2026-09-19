// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod options;
mod reflection;
use super::{Budget, Error, Limits, extend, take, u16_at, u32_at};
use bytes::Bytes;
pub use options::{Option4, Value4};
pub(super) use reflection::{layout, schema};
use std::net::Ipv4Addr;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dhcpv4 {
    pub operation: u8,
    pub hardware_type: u8,
    pub hardware_length: u8,
    pub hops: u8,
    pub transaction_id: u32,
    pub seconds: u16,
    pub flags: u16,
    pub client_address: Ipv4Addr,
    pub your_address: Ipv4Addr,
    pub server_address: Ipv4Addr,
    pub gateway_address: Ipv4Addr,
    pub client_hardware_address: [u8; 16],
    pub server_name: [u8; 64],
    pub boot_file: [u8; 128],
    pub options: Vec<Option4>,
    pub file_options: Vec<Option4>,
    pub server_name_options: Vec<Option4>,
    trailing: Bytes,
    wire: Bytes,
}
impl Default for Dhcpv4 {
    fn default() -> Self {
        Self {
            operation: 1,
            hardware_type: 1,
            hardware_length: 6,
            hops: 0,
            transaction_id: 0,
            seconds: 0,
            flags: 0,
            client_address: Ipv4Addr::UNSPECIFIED,
            your_address: Ipv4Addr::UNSPECIFIED,
            server_address: Ipv4Addr::UNSPECIFIED,
            gateway_address: Ipv4Addr::UNSPECIFIED,
            client_hardware_address: [0; 16],
            server_name: [0; 64],
            boot_file: [0; 128],
            options: vec![Option4::message_type(1)],
            file_options: Vec::new(),
            server_name_options: Vec::new(),
            trailing: Bytes::new(),
            wire: Bytes::new(),
        }
    }
}
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
    pub fn wire(&self) -> &Bytes {
        &self.wire
    }
    pub fn edit(&mut self, edit: impl FnOnce(&mut Self)) {
        self.wire = Bytes::new();
        edit(self);
    }
    pub fn message_type(&self) -> Option<u8> {
        self.all_options().find_map(|option| {
            if let Value4::MessageType(value) = option.value {
                Some(value)
            } else {
                None
            }
        })
    }
    pub fn all_options(&self) -> impl Iterator<Item = &Option4> {
        self.options
            .iter()
            .chain(&self.file_options)
            .chain(&self.server_name_options)
    }
    pub fn from_wire_with_limits(wire: impl Into<Bytes>, limits: Limits) -> Result<Self, Error> {
        let wire = wire.into();
        let mut budget = Budget::new(limits, wire.len())?;
        take(&wire, 0, 240)?;
        if &wire[236..240] != b"\x63\x82\x53\x63" {
            return Err(Error::Invalid("DHCPv4 magic cookie"));
        }
        if wire[2] > 16 {
            return Err(Error::Invalid("hardware address length exceeds chaddr"));
        }
        let (options, trailing) = options::decode(&wire.slice(240..), &mut budget)?;
        let overload = options::overload(&options)?;
        let file_options = if overload & 1 != 0 {
            options::decode(&wire.slice(108..236), &mut budget)?.0
        } else {
            Vec::new()
        };
        let server_name_options = if overload & 2 != 0 {
            options::decode(&wire.slice(44..108), &mut budget)?.0
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
        let existing = options::overload(&primary)?;
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
            let encoded = options::encode(&self.file_options, &mut budget, 128)?;
            file[..encoded.len()].copy_from_slice(&encoded);
        }
        if overload & 2 != 0 {
            let encoded = options::encode(&self.server_name_options, &mut budget, 64)?;
            sname[..encoded.len()].copy_from_slice(&encoded);
        }
        extend(&mut output, &sname, maximum)?;
        extend(&mut output, &file, maximum)?;
        extend(&mut output, b"\x63\x82\x53\x63", maximum)?;
        let encoded = options::encode(&primary, &mut budget, maximum.saturating_sub(output.len()))?;
        extend(&mut output, &encoded, maximum)?;
        extend(&mut output, &self.trailing, maximum)?;
        let wire: Bytes = output.into();
        Self::from_wire_with_limits(wire.clone(), limits)?;
        Ok(wire)
    }
}
