// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture-link header models.

mod bsd;
mod sll;

pub use bsd::{BsdLoop, BsdNull, ByteOrder};
pub(crate) use bsd::{BsdLoopCodec, BsdNullCodec};
pub use sll::{LinuxSll, LinuxSll2};
pub(crate) use sll::{LinuxSll2Codec, LinuxSllCodec};

use crate::frame::LinkType;
use crate::protocol::BuiltinProtocol;

/// One numeric DLT/LINKTYPE binding in the default registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureRoot {
    pub link_type: LinkType,
    pub protocol: BuiltinProtocol,
}

const fn capture_root(link_type: LinkType, protocol: BuiltinProtocol) -> CaptureRoot {
    CaptureRoot {
        link_type,
        protocol,
    }
}

/// Every numeric capture root registered by the default built-in module.
///
/// Capture topology remains separate from identity metadata, but every edge is
/// typed so a protocol rename cannot silently leave a string binding behind.
pub const BUILTIN_CAPTURE_ROOTS: &[CaptureRoot] = &[
    capture_root(LinkType::NULL, BuiltinProtocol::BsdNull),
    capture_root(LinkType::ETHERNET, BuiltinProtocol::Ethernet),
    capture_root(LinkType::BSD_RAW, BuiltinProtocol::RawIp),
    capture_root(LinkType::RAW, BuiltinProtocol::RawIp),
    capture_root(LinkType::LOOP, BuiltinProtocol::BsdLoop),
    capture_root(LinkType::LINUX_SLL, BuiltinProtocol::LinuxSll),
    capture_root(LinkType::IPV4, BuiltinProtocol::Ipv4),
    capture_root(LinkType::IPV6, BuiltinProtocol::Ipv6),
    capture_root(LinkType::LINUX_SLL2, BuiltinProtocol::LinuxSll2),
];
