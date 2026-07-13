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

    pub use super::builtin_impl::{BuiltinProtocols as Module, default_registry as registry};
}

pub mod support {
    //! Versioned built-in capability information.

    pub use super::builtin_impl::{
        BUILTIN_CAPTURE_ROOTS, BUILTIN_PROTOCOL_SUPPORT, BUILTIN_PROTOCOLS,
        CaptureRootByteOrder as CaptureByteOrder, CaptureRootSupport as CaptureRoot,
        PROTOCOL_SUPPORT_SCHEMA_V1, ProtocolFallbackSupport as Fallback,
        ProtocolSupport as Protocol, ProtocolSupportManifest as Manifest,
        STABLE_WORKFLOW_PROTOCOLS, WorkflowProtocolSupport as Workflow,
    };
}

/// Flat implementation vocabulary used only by other library domains.
pub(crate) mod internal {
    #[cfg(test)]
    pub(crate) use super::builtin_impl::{
        Arp, SegmentRoutingHeader, Vlan, Vlan8021ad, default_registry,
    };
    pub(crate) use super::builtin_impl::{
        Ethernet, Icmpv4, Icmpv6, Ipv4, Ipv4OptionsError, Ipv6, Tcp, Udp,
        ipv4_source_route_destinations,
    };
}
