// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded application payload layers.

pub mod dns;
pub mod tls;

pub(crate) use dns::DnsCodec;
pub(crate) use tls::codec::TlsCodec;
