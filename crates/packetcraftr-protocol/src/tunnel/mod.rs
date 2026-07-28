// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Tunnel and overlay encapsulation layers.

mod geneve;
mod ipsec;
mod mpls;
mod pppoe;
mod vxlan;

pub use geneve::Geneve;
pub(crate) use geneve::GeneveCodec;
pub use ipsec::{Ah, Esp};
pub(crate) use ipsec::{AhCodec, EspCodec};
pub use mpls::Mpls;
pub(crate) use mpls::{MPLS_BOTTOM_RAW, MPLS_BOTTOM_VERSION_BASE, MPLS_NEXT_LABEL, MplsCodec};
pub(crate) use pppoe::{PPPOE_DISCOVERY, PPPOE_SESSION, PppCodec, PppoeCodec};
pub use pppoe::{Ppp, Pppoe};
pub use vxlan::Vxlan;
pub(crate) use vxlan::VxlanCodec;
