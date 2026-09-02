// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Built-in protocol models, deterministic registration, and capability data.
//!
//! The default registry covers capture roots for BSD NULL/LOOP, Linux cooked
//! capture, raw IP, Ethernet, IPv4, and IPv6. Its packet families include
//! Ethernet and VLAN framing, ARP, IPv4 and IPv6 (including nested IPv4/IPv6),
//! GRE, IGMP, ICMPv4/ICMPv6, selected IPv6 extension headers, TCP, UDP, SCTP,
//! and raw/malformed/padding preservation layers. DNS-over-UDP payloads expose
//! a bounded typed header/question summary while retaining their full wire
//! image for exact round trips.
//!
//! [`BuiltinProtocol`] names every built-in protocol and reports its
//! construction, exact-round-trip, and matcher capabilities;
//! [`capture::BUILTIN_CAPTURE_ROOTS`] reports capture bindings.
//! [`builtin::registry`] constructs the immutable default registry.
//!
//! The built-ins focus on packet headers and bounded framing. SCTP chunks are
//! validated opaque bytes rather than typed chunk models, and other application
//! payloads use [`crate::layer::Raw`]. Unknown
//! discriminators and malformed bytes are preserved by the registry.

pub mod application;
pub mod builtin;
pub mod capture;
mod catalog;
mod common;
pub mod gre;
pub mod icmp;
pub mod ipv6;
pub mod link;
mod matcher;
pub mod network;
pub mod raw;
pub mod transport;
pub mod tunnel;

pub use catalog::BuiltinProtocol;
pub use common::{ChecksumAccumulator, checksum, checksum_parts};

pub use matcher::{QuotedIcmpError, QuotedProbeTransport, quoted_icmp_error_kind};
