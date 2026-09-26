// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DHCPv4 (BOOTP) messages with lossless options, including RFC 2131
//! option overloading.

mod codec;
mod model;
mod reflection;

pub(crate) use codec::Dhcpv4Codec;
pub use model::{Dhcpv4, Option4, Value4};
