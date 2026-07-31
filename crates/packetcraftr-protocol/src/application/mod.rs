// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded application payload layers.

mod dns;

pub use dns::Dns;
pub(crate) use dns::DnsCodec;
