// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet construction, dissection, capture I/O, and policy-gated network
//! workflows.
//!
//! This crate is a façade. Every implementation lives in a member crate of the
//! `packetcraftr` workspace; the modules below re-export those crates under
//! their canonical domain names and map the public Cargo features onto them.
//!
//! # Domain map
//!
//! - [`capture`] reads and writes bounded classic PCAP and PCAPNG streams;
//! - [`client`] plans and executes policy-gated send and exchange operations;
//! - [`error`] provides the shared classified error vocabulary;
//! - [`net`] defines interfaces, routes, providers, and native I/O boundaries;
//! - [`output`] defines render-neutral output models and versioned envelopes;
//! - [`packet`] owns layers, documents, registries, exact building, and bounded
//!   dissection;
//! - [`policy`] owns the non-bypassable traffic-authorization boundary;
//! - [`protocol`] supplies the built-in codecs, matchers, capture roots, and
//!   capability manifest;
//! - [`session`] provides bounded fragment and transport reassembly state; and
//! - [`workflow`] implements replay, scan, traceroute, DNS, and fuzz workflows.
//!
//! The packet and protocol domains are runtime-neutral. Native availability is
//! selected separately through Cargo features and the providers in [`net`].
//! Consumers that need the exact built-in build, dissect, matcher, capture-root,
//! or workflow matrix should inspect
//! [`protocol::support::BUILTIN_PROTOCOL_SUPPORT`] instead of inferring support
//! from a protocol type's presence.
//!
//! ```
//! use std::sync::Arc;
//! use packetcraftr::{packet::{build, layer::Raw, Packet}, protocol};
//!
//! let registry = Arc::new(protocol::builtin::registry()?);
//! let mut packet = Packet::new();
//! packet.push(Raw::new(vec![0xde, 0xad, 0xbe, 0xef]));
//! let built = build::Builder::new(registry).build(
//!     packet,
//!     build::Context::default(),
//!     build::Options::default(),
//! )?;
//! assert_eq!(built.bytes.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![warn(unreachable_pub)]
#![deny(unsafe_code)]

pub use packetcraftr_capture as capture;
pub use packetcraftr_output as output;
pub use packetcraftr_packet as packet;
pub use packetcraftr_policy as policy;
pub use packetcraftr_protocols as protocol;
pub use packetcraftr_session as session;

/// Shared classified failure taxonomy.
pub mod error {
    pub use packetcraftr_model::error::{Category, Classification, Classified, Kind};
}

/// Live network interfaces, routing, neighbor discovery, transmission, and
/// capture.
///
/// Platform-neutral contracts come from `packetcraftr-net`; the `System*`
/// providers that select an operating-system backend come from
/// `packetcraftr-net-native`. They are presented together here because callers
/// compose them as one domain.
pub mod net {
    pub use packetcraftr_net::{Error, Stats, exchange, link};

    /// Owned live-capture sessions and bounded queue configuration.
    pub mod capture {
        pub use packetcraftr_net::capture::*;
        pub use packetcraftr_net_native::capture::SystemProvider;
    }

    /// Interface discovery and portable interface descriptions.
    pub mod interface {
        pub use packetcraftr_net::interface::*;
        pub use packetcraftr_net_native::interface::SystemProvider;
    }

    /// Bounded, capture-before-send ARP and IPv6 Neighbor Discovery.
    pub mod neighbor {
        pub use packetcraftr_net::neighbor::*;
        pub use packetcraftr_net_native::neighbor::SystemResolver;
    }

    /// Passive route planning, neighbor materialization, and route providers.
    pub mod route {
        pub use packetcraftr_net::route::*;
        pub use packetcraftr_net_native::route::{SystemError, SystemProvider};
    }

    /// Typed Layer 2 and Layer 3 transmission contracts.
    pub mod transmit {
        pub use packetcraftr_net::transmit::*;
        pub use packetcraftr_net_native::transmit::{SystemLayer2, SystemLayer3};
    }
}

/// Policy-gated packet transmission and response exchange.
pub mod client {
    pub use packetcraftr_client::{Error, Stats, exchange, send};

    #[doc(inline)]
    pub use packetcraftr_client::Client;
}

/// Bounded, policy-gated network workflows.
///
/// The engines come from `packetcraftr-workflow`; the concrete client-backed
/// executors and the native replay transmitter come from
/// `packetcraftr-workflow-client`.
pub mod workflow {
    pub use packetcraftr_workflow::{
        AddressFamily, BoundaryError, PolicyAuthorizer, Stats, clock, target,
    };

    /// Bounded DNS query construction, validation, and retry execution.
    pub mod dns {
        pub use packetcraftr_workflow::dns::*;
        pub use packetcraftr_workflow_client::dns::ClientExecutor;
    }

    /// Deterministic, bounded, field-aware packet mutation.
    pub mod fuzz {
        pub use packetcraftr_workflow::fuzz::*;
        pub use packetcraftr_workflow_client::fuzz::ClientExecutor;
    }

    /// Bounded, policy-gated capture replay.
    pub mod replay {
        pub use packetcraftr_workflow::replay::*;
        pub use packetcraftr_workflow_client::replay::SystemTransmitter;
    }

    /// Bounded structured scanning.
    pub mod scan {
        pub use packetcraftr_workflow::scan::*;
        pub use packetcraftr_workflow_client::scan::ClientExecutor;
    }

    /// Bounded, structured traceroute.
    pub mod traceroute {
        pub use packetcraftr_workflow::traceroute::*;
        pub use packetcraftr_workflow_client::traceroute::ClientExecutor;
    }
}
