// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet construction, offline analysis, native networking, and policy-gated
//! live workflows.
//!
//! - [`packet`]: packet mechanics, codecs, budgets, and offline fuzzing.
//! - [`analysis`]: bounded capture I/O and offline analysis.
//! - [`network`]: native I/O boundaries.
//! - [`live`]: policy-gated, budgeted live workflows.
//! - [`output`]: versioned render-neutral output.
//!
//! [`analysis`] depends on neither [`network`] nor [`live`]. [`live`] workflows
//! require [`live::policy::Policy`] and finite packet, byte, duration, and
//! evidence budgets.
//!
//! Built-in protocol and capture-root support are listed in
//! [`packet::protocol::support::BUILTIN_PROTOCOLS`] and
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
