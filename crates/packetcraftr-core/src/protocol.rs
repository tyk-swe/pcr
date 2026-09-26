// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Built-in packet models, registration, and capabilities. [`BuiltinProtocol`]
//! reports construction, round-trip, and matcher support;
//! [`LinkType::BUILTIN_ROOTS`](crate::frame::LinkType::BUILTIN_ROOTS) lists
//! capture bindings.
//! [`builtin::registry`] provides the immutable default registry, and
//! [`semantics`] interprets the routing fields of built-in layers.
//!
//! Protocol models are grouped by layer: [`capture`] link headers, [`link`],
//! [`network`] (IPv4, IPv6 and its extension headers, ICMP, IGMP),
//! [`transport`], [`tunnel`] (including GRE), and [`application`].
//!
//! Codecs preserve unknown and malformed bytes. SCTP chunks remain validated
//! opaque bytes; unrecognized application payloads use [`crate::layer::Raw`].

pub mod application;
pub mod builtin;
pub mod capture;
mod catalog;
mod common;
pub mod link;
mod matcher;
pub mod network;
pub mod semantics;
pub mod transport;
pub mod tunnel;

pub use catalog::{BuiltinProtocol, UnknownProtocolName};
pub use common::{ChecksumAccumulator, checksum, checksum_parts};
pub(crate) use common::{network_from_addresses, transport_checksum};

pub use matcher::{
    QuotedIcmpError, QuotedProbeTransport, quoted_icmp_error_kind, transport_tuple_reversed,
};
