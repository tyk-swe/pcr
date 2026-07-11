// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! PacketcraftR's runtime-neutral packet model, protocol registry, exact builder,
//! bounded dissector, offline capture I/O, session stages, and high-level client.
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
