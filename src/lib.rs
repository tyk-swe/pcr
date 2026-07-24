// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet construction, dissection, capture I/O, and policy-gated network
//! workflows.
//!
//! # Domain map
//!
//! The crate keeps its public surface in nine canonical domains:
//!
//! - [`capture`] reads and writes bounded classic PCAP and PCAPNG streams;
//! - [`client`] plans and executes policy-gated send and exchange operations;
//! - [`error`] provides the shared classified error vocabulary;
//! - [`net`] defines interfaces, routes, providers, and native I/O boundaries;
//! - [`output`] defines render-neutral output models and versioned envelopes;
//! - [`packet`] owns layers, documents, registries, exact building, and bounded
//!   dissection;
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

pub mod capture;
pub mod client;
pub mod error;
pub mod net;
pub mod output;
pub mod packet;
pub mod protocol;
pub mod session;
pub mod workflow;
