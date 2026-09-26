// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Link-type numbers and the one link-type ↔ root-protocol mapping.
//!
//! [`LinkType`] stays a model type beside [`Frame`](crate::frame::Frame), so
//! frames and registries can carry any numeric link type. The numbers core
//! knows and the protocol that decodes each one are defined only here.

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

    /// Every link type the default registry decodes, with its root protocol.
    ///
    /// Each edge is typed, so a protocol rename cannot leave a string binding
    /// behind. When several link types share a root protocol, the first one
    /// listed is the one [`Self::for_root_protocol`] returns: raw IP is
    /// written as [`Self::RAW`], and [`Self::BSD_RAW`] is only read.
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

    /// The built-in protocol that decodes the first byte of a frame with this
    /// link type, or `None` for a link type core does not decode.
    pub fn root_protocol(self) -> Option<BuiltinProtocol> {
        Self::BUILTIN_ROOTS
            .iter()
            .find(|(link_type, _)| *link_type == self)
            .map(|(_, protocol)| *protocol)
    }

    /// The link type a capture file records for a frame whose outermost layer
    /// is `protocol`, or `None` when the protocol cannot start a frame.
    pub fn for_root_protocol(protocol: BuiltinProtocol) -> Option<Self> {
        Self::BUILTIN_ROOTS
            .iter()
            .find(|(_, root)| *root == protocol)
            .map(|(link_type, _)| *link_type)
    }

    /// Whether frames of this link type begin directly with an IP header:
    /// the root protocol is raw IP, IPv4, or IPv6.
    pub fn is_raw_ip(self) -> bool {
        matches!(
            self.root_protocol(),
            Some(BuiltinProtocol::RawIp | BuiltinProtocol::Ipv4 | BuiltinProtocol::Ipv6)
        )
    }
}
