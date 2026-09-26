// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use std::net::Ipv6Addr;

use super::super::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dhcpv6 {
    pub message_type: u8,
    pub transaction_id: u32,
    pub hop_count: u8,
    pub link_address: Ipv6Addr,
    pub peer_address: Ipv6Addr,
    pub options: Vec<Option6>,
    pub(super) wire: Bytes,
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
}
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
    pub fn ia_na(iaid: u32, t1: u32, t2: u32, options: Vec<Self>) -> Self {
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
    pub fn ia_pd(iaid: u32, t1: u32, t2: u32, options: Vec<Self>) -> Self {
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
}
