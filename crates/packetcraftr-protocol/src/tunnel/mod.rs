// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Tunnel and overlay encapsulation layers.

mod geneve;
mod mpls;
mod vxlan;

pub use geneve::Geneve;
pub(crate) use geneve::GeneveCodec;
pub use mpls::Mpls;
pub(crate) use mpls::{MPLS_BOTTOM_RAW, MPLS_BOTTOM_VERSION_BASE, MPLS_NEXT_LABEL, MplsCodec};
pub use vxlan::Vxlan;
pub(crate) use vxlan::VxlanCodec;
