// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Built-in protocol models, deterministic registration, and capability data.
//!
//! The default registry covers capture roots for BSD NULL/LOOP, Linux cooked
//! capture, raw IP, Ethernet, IPv4, and IPv6. Its packet families include
//! Ethernet and VLAN framing, ARP, IPv4 and IPv6 (including nested IPv4/IPv6),
//! GRE, IGMP, ICMPv4/ICMPv6, selected IPv6 extension headers, TCP, UDP, SCTP,
//! and raw/malformed/padding preservation layers.
//!
//! Protocol presence does not imply support in every workflow. Use
//! [`support::BUILTIN_PROTOCOL_SUPPORT`] for the versioned build, dissect,
//! exact-round-trip, matcher, capture-root, fallback, and workflow matrix, and
//! [`builtin::registry`] to construct the immutable default registry.
//!
//! The built-ins focus on packet headers and bounded framing. SCTP chunks are
//! validated opaque bytes rather than typed chunk models, DNS messages are
//! owned by the DNS workflow rather than registered as an application codec,
//! and other application payloads use [`crate::packet::layer::Raw`]. Unknown
//! discriminators and malformed bytes follow the fallback policy declared in
//! the capability manifest.

pub mod builtin;
pub mod capture;
mod common;
pub mod gre;
pub mod icmp;
pub mod ipv6;
pub mod link;
mod matcher;
pub mod network;
mod raw;
pub mod support;
pub mod transport;

pub(crate) use matcher::{QuotedIcmpError, QuotedProbeTransport, quoted_icmp_error_kind};
