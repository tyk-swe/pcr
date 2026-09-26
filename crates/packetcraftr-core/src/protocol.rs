// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Built-in packet models, registration, and capabilities. [`BuiltinProtocol`]
//! identifies a built-in layer by its concrete type and reports construction,
//! round-trip, and matcher support;
//! [`LinkType::BUILTIN_ROOTS`](crate::frame::LinkType::BUILTIN_ROOTS) lists
//! capture bindings.
//! [`builtin::registry`] provides the immutable default registry, and
//! [`semantics`] interprets the routing fields of built-in layers.
//!
//! Protocol models are grouped by layer: [`capture`] link headers, [`link`],
//! [`network`] (IPv4, IPv6 and its extension headers, ICMP, IGMP),
//! [`transport`], [`tunnel`] (including GRE), and [`application`].
//!
//! Each protocol is one `<proto>.rs` holding its model, its
//! `reflective_layer!`, and its codec. A large protocol becomes a directory:
//! `<proto>.rs` keeps the docs, the protocol's `Error` and limits, and the
//! re-exports, with `model`, `codec`, and `reflection` submodules (TCP, DNS,
//! HTTP, TLS, and DHCPv4/DHCPv6, which share DHCP's `Error` and limits). Wire
//! APIs return the protocol's own `Error`.
//!
//! [`headers`] walks raw link, VLAN, and IP header bytes for code that must
//! edit or inspect bytes a codec round trip would not reproduce.
//!
//! The built-in registry carries a
//! [`ResponseMatcher`](crate::matcher::ResponseMatcher) for each protocol whose
//! [`BuiltinProtocol::has_matcher`] is true. Live workflows that
//! classify responses themselves use the same correlation through
//! [`quoted_icmp_error`] and [`transport_tuple_reversed`].
//!
//! Codecs preserve unknown and malformed bytes. SCTP chunks remain validated
//! opaque bytes; unrecognized application payloads use [`crate::layer::Raw`].

pub mod application;
pub mod builtin;
pub mod capture;
mod catalog;
mod common;
pub mod headers;
pub mod link;
mod matcher;
pub mod network;
pub mod semantics;
pub mod transport;
pub mod tunnel;

pub use catalog::{BuiltinProtocol, UnknownProtocolName};
pub use common::{ChecksumAccumulator, checksum, checksum_parts};
pub(crate) use common::{network_from_addresses, transport_checksum};

pub use matcher::{IcmpErrorKind, QuotedTransport, quoted_icmp_error, transport_tuple_reversed};
