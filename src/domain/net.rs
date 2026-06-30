// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct MacAddress([u8; 6]);

impl MacAddress {
    pub(crate) fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub(crate) fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddress {
    type Err = MacAddressParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts = value.split([':', '-']).collect::<Vec<_>>();
        if parts.len() != 6 {
            return Err(MacAddressParseError);
        }

        let mut octets = [0u8; 6];
        for (index, part) in parts.into_iter().enumerate() {
            if part.len() != 2 {
                return Err(MacAddressParseError);
            }
            octets[index] = u8::from_str_radix(part, 16).map_err(|_| MacAddressParseError)?;
        }

        Ok(Self(octets))
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid MAC address")]
pub(crate) struct MacAddressParseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct EtherType(pub u16);

impl EtherType {
    pub(crate) const IPV4: Self = Self(0x0800);
    pub(crate) const IPV6: Self = Self(0x86dd);
    pub(crate) const ARP: Self = Self(0x0806);
    pub(crate) const VLAN: Self = Self(0x8100);
    pub(crate) const PPPOE_DISCOVERY: Self = Self(0x8863);
    pub(crate) const PPPOE_SESSION: Self = Self(0x8864);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct IpProtocol(pub u8);
