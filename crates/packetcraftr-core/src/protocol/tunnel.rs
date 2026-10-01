// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod erspan;
mod etherip;
mod geneve;
mod gre;
mod gtpu;
mod ipsec;
mod l2tp;
mod mpls;
mod pppoe;
mod vxlan;

pub(crate) use erspan::ErspanCodec;
pub use erspan::{Erspan, ErspanType3};
pub use etherip::Etherip;
pub(crate) use etherip::EtheripCodec;
pub use geneve::Geneve;
pub(crate) use geneve::GeneveCodec;
pub use gre::Gre;
pub(crate) use gre::GreCodec;
pub use gtpu::Gtpu;
pub(crate) use gtpu::{GTPU_IP_VERSION_BASE, GTPU_OTHER_PAYLOAD, GtpuCodec};
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

const VNI_MAX: u32 = 0x00ff_ffff;
