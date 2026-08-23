// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Tunnel and overlay encapsulation layers.

mod erspan;
mod geneve;
pub mod gre;
mod ipsec;
mod l2tp;
mod mpls;
mod pppoe;
mod vxlan;

pub(crate) use erspan::ErspanCodec;
pub use erspan::{Erspan, ErspanType3};
pub use geneve::Geneve;
pub(crate) use geneve::GeneveCodec;
pub use ipsec::{Ah, Esp};
pub(crate) use ipsec::{AhCodec, EspCodec};
pub use l2tp::L2tpv3;
pub(crate) use l2tp::L2tpv3Codec;
pub use mpls::Mpls;
pub(crate) use mpls::{MPLS_BOTTOM_RAW, MPLS_BOTTOM_VERSION_BASE, MPLS_NEXT_LABEL, MplsCodec};
pub(crate) use pppoe::{PPPOE_DISCOVERY, PPPOE_SESSION, PppCodec, PppoeCodec};
pub use pppoe::{Ppp, Pppoe};
pub use vxlan::Vxlan;
pub(crate) use vxlan::VxlanCodec;
