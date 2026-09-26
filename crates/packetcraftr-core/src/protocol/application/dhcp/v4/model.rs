// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
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
    pub(super) trailing: Bytes,
    pub(super) wire: Bytes,
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
}
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
}
