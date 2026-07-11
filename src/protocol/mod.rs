// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Built-in protocol models and deterministic registration.

mod builtin_impl;

pub mod capture {
    //! Capture-link header models.

    pub use super::builtin_impl::{
        BsdLoop, BsdNull, CaptureByteOrder as ByteOrder, LinuxSll, LinuxSll2,
    };
}

pub mod link {
    //! Link-layer protocol models.

    pub use super::builtin_impl::{Arp, Ethernet, Vlan, Vlan8021ad};
}

pub mod network {
    //! Network-layer protocol models.

    pub use super::builtin_impl::{Ipv4, Ipv6};
}

pub mod ipv6 {
    //! IPv6 extension-header models.

    pub use super::builtin_impl::{
        DestinationOptions, HopByHop, Ipv6Fragment as Fragment, SegmentRoutingHeader,
    };
}

pub mod transport {
    //! Transport protocol models.

    pub use super::builtin_impl::{Tcp, Udp};
}

pub mod icmp {
    //! Internet Control Message Protocol models.

    pub use super::builtin_impl::{Icmpv4, Icmpv6};
}

pub mod builtin {
    //! Deterministic built-in protocol registration.

    pub use super::builtin_impl::{default_registry as registry, BuiltinProtocols as Module};
}

pub mod support {
    //! Versioned built-in capability information.

    pub use super::builtin_impl::{
        CaptureRootByteOrder as CaptureByteOrder, CaptureRootSupport as CaptureRoot,
        ProtocolFallbackSupport as Fallback, ProtocolSupport as Protocol,
        ProtocolSupportManifest as Manifest, WorkflowProtocolSupport as Workflow,
        BUILTIN_CAPTURE_ROOTS, BUILTIN_PROTOCOLS, BUILTIN_PROTOCOL_SUPPORT,
        PROTOCOL_SUPPORT_SCHEMA_V1, STABLE_WORKFLOW_PROTOCOLS,
    };
}

/// Flat implementation vocabulary used only by other library domains.
#[allow(unused_imports)]
pub(crate) mod internal {
    pub(crate) use super::builtin_impl::{
        default_registry, Arp, BsdLoop, BsdNull, BuiltinProtocols, CaptureByteOrder,
        CaptureRootByteOrder, CaptureRootSupport, DestinationOptions, Ethernet, HopByHop, Icmpv4,
        Icmpv6, Ipv4, Ipv6, Ipv6Fragment, LinuxSll, LinuxSll2, ProtocolFallbackSupport,
        ProtocolSupport, ProtocolSupportManifest, SegmentRoutingHeader, Tcp, Udp, Vlan, Vlan8021ad,
        WorkflowProtocolSupport, BUILTIN_CAPTURE_ROOTS, BUILTIN_PROTOCOLS,
        BUILTIN_PROTOCOL_SUPPORT, PROTOCOL_SUPPORT_SCHEMA_V1, STABLE_WORKFLOW_PROTOCOLS,
    };
}
