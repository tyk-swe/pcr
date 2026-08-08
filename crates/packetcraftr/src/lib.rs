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
//! authorization through [`live::policy::Policy`], and run under finite
//! packet, byte, duration, and evidence budgets.
//!
//! # Domain map
//!
//! The workspace's domains are independently compiled where their dependency
//! boundaries require it. This facade also owns the render-neutral [`output`]
//! module. Depend on an individual domain crate to compile only part of the
//! stack.
//!
//! The current facade exposes these responsibility-oriented domains:
//!
//! - [`packet`] owns budgets, errors, frames, packet mechanics, built-in
//!   protocols, and deterministic offline fuzz campaigns;
//! - [`analysis`] owns bounded PCAP/PCAPNG I/O, offline analysis, expert
//!   diagnostics, following, statistics, and reassembly;
//! - [`network`] defines interfaces, links, neighbors, routes, capture,
//!   transmission, and native I/O boundaries;
//! - [`live`] owns policy-gated send, exchange, replay, scan, traceroute, DNS,
//!   and live fuzz execution;
//! - [`output`] defines render-neutral output models and versioned envelopes;
//!   it is implemented by this facade crate.
//!
//! [`analysis`] and [`live`] are separate crates because the offline and live
//! halves of the toolkit must not blur: [`analysis`] depends on neither
//! [`network`] nor [`live`], so it cannot acquire a resolver, route, capture,
//! or transmission seam without that dependency edge appearing first.
//!
//! The packet domain is runtime-neutral. Native availability is selected
//! separately through Cargo features and the providers in [`network`].
//! Consumers that need exact built-in codec or capture-root capabilities should
//! inspect [`packet::protocol::support::BUILTIN_PROTOCOLS`] and
//! [`packet::protocol::support::BUILTIN_CAPTURE_ROOTS`].
//!
//! ```text
//! use std::sync::Arc;
//! use packetcraftr::{packet::{build, layer::Raw, Packet}, packet::protocol as protocol};
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
pub use packetcraftr_live as live;
pub use packetcraftr_network as network;
pub use packetcraftr_packet as packet;

pub mod output;
