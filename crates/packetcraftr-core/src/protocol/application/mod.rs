// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded application payload layers.

pub mod dhcp;
pub mod dns;
pub mod http;
pub mod tls;

pub(crate) use dhcp::{Dhcpv4Codec, Dhcpv6Codec};
pub(crate) use dns::DnsCodec;
pub(crate) use http::HttpCodec;
pub(crate) use tls::codec::TlsCodec;
