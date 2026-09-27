// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::frame::LinkType;
use crate::protocol::BuiltinProtocol;

impl LinkType {
    pub const NULL: Self = Self(0);
    pub const ETHERNET: Self = Self(1);
    /// BSD raw-IP DLT, distinct from the IANA-assigned raw LINKTYPE.
    pub const BSD_RAW: Self = Self(12);
    pub const RAW: Self = Self(101);
    pub const LOOP: Self = Self(108);
    pub const LINUX_SLL: Self = Self(113);
    pub const IPV4: Self = Self(228);
    pub const IPV6: Self = Self(229);
    pub const LINUX_SLL2: Self = Self(276);

    /// The first link type listed for a root protocol is what [`Self::for_root_protocol`] returns.
    pub const BUILTIN_ROOTS: &'static [(Self, BuiltinProtocol)] = &[
        (Self::NULL, BuiltinProtocol::BsdNull),
        (Self::ETHERNET, BuiltinProtocol::Ethernet),
        (Self::RAW, BuiltinProtocol::RawIp),
        (Self::BSD_RAW, BuiltinProtocol::RawIp),
        (Self::LOOP, BuiltinProtocol::BsdLoop),
        (Self::LINUX_SLL, BuiltinProtocol::LinuxSll),
        (Self::IPV4, BuiltinProtocol::Ipv4),
        (Self::IPV6, BuiltinProtocol::Ipv6),
        (Self::LINUX_SLL2, BuiltinProtocol::LinuxSll2),
    ];

    pub fn root_protocol(self) -> Option<BuiltinProtocol> {
        Self::BUILTIN_ROOTS
            .iter()
            .find(|(link_type, _)| *link_type == self)
            .map(|(_, protocol)| *protocol)
    }

    pub fn for_root_protocol(protocol: BuiltinProtocol) -> Option<Self> {
        Self::BUILTIN_ROOTS
            .iter()
            .find(|(_, root)| *root == protocol)
            .map(|(link_type, _)| *link_type)
    }

    pub fn is_raw_ip(self) -> bool {
        matches!(
            self.root_protocol(),
            Some(BuiltinProtocol::RawIp | BuiltinProtocol::Ipv4 | BuiltinProtocol::Ipv6)
        )
    }
}
