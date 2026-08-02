// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet construction, dissection, capture I/O, and policy-gated network
//! workflows.
//!
//! PacketcraftR is a network protocol analysis toolkit for engineers debugging
//! protocol behaviour, validating encoders and decoders against the wire
//! format, and testing parser robustness against malformed input. Building,
//! dissection, capture-file I/O, and fuzz-case generation are offline and
//! runtime-neutral; the live paths are separate, require operation
//! authorization through [`client::policy::Policy`], and run under finite
//! packet, byte, duration, and evidence budgets.
//!
//! # Domain map
//!
//! Each domain is an independently compiled crate in the `packetcraftr`
//! workspace; this crate re-exports all ten under their canonical names, so
//! `packetcraftr::packet` and `packetcraftr_packet` name the same items.
//! Depend on the individual crates instead to compile only part of the stack.
//!
//! The ten canonical domains are:
//!
//! - [`analysis`] runs bounded offline capture analysis, expert diagnostics,
//!   and stream reassembly;
//! - [`capture`] reads and writes bounded classic PCAP and PCAPNG streams;
//! - [`client`] plans and executes policy-gated send and exchange operations;
//! - [`error`] provides the shared classified error vocabulary;
//! - [`net`] defines interfaces, routes, providers, and native I/O boundaries;
//! - [`output`] defines render-neutral output models and versioned envelopes;
//! - [`packet`] owns layers, documents, registries, exact building, and bounded
//!   dissection;
//! - [`protocol`] supplies the built-in codecs, matchers, capture roots, and
//!   capability tables;
//! - [`reassembly`] provides bounded fragment and transport reassembly state;
//!   and
//! - [`workflow`] implements replay, scan, traceroute, DNS, and fuzz workflows.
//!
//! [`analysis`] and [`workflow`] are separate crates because the offline and
//! live halves of the toolkit must not blur: [`analysis`] depends on neither
//! [`client`] nor [`net`], so it cannot acquire a resolver, route, capture, or
//! transmission seam without that dependency edge appearing first.
//!
//! The packet and protocol domains are runtime-neutral. Native availability is
//! selected separately through Cargo features and the providers in [`net`].
//! Consumers that need exact built-in codec or capture-root capabilities should
//! inspect [`protocol::support::BUILTIN_PROTOCOLS`] and
//! [`protocol::support::BUILTIN_CAPTURE_ROOTS`].
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

#![forbid(unsafe_code)]

pub use packetcraftr_analysis as analysis;
pub use packetcraftr_capture as capture;
pub use packetcraftr_client as client;
pub use packetcraftr_error as error;
pub use packetcraftr_net as net;
pub use packetcraftr_output as output;
pub use packetcraftr_packet as packet;
pub use packetcraftr_protocol as protocol;
pub use packetcraftr_reassembly as reassembly;
pub use packetcraftr_workflow as workflow;
