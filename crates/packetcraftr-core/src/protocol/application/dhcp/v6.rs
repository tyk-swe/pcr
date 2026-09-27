// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod codec;
mod model;
mod reflection;

pub(crate) use codec::Dhcpv6Codec;
pub use model::{Dhcpv6, Duid, Option6, Value6};
