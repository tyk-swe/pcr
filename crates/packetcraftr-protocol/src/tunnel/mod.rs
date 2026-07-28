// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Tunnel and overlay encapsulation layers.

mod vxlan;

pub use vxlan::Vxlan;
pub(crate) use vxlan::VxlanCodec;
