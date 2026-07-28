// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Tunnel and overlay encapsulation layers.

mod geneve;
mod vxlan;

pub use geneve::Geneve;
pub(crate) use geneve::GeneveCodec;
pub use vxlan::Vxlan;
pub(crate) use vxlan::VxlanCodec;
