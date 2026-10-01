// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod arp;
mod eapol;
mod ether_type;
mod ethernet;
mod llc;
mod lldp;
mod stp;
mod vlan;

pub use arp::Arp;
pub(crate) use arp::ArpCodec;
pub use eapol::Eapol;
pub(crate) use eapol::EapolCodec;
pub use ethernet::Ethernet;
pub(crate) use ethernet::EthernetCodec;
pub(crate) use llc::{LLC_FRAME_DISCRIMINATOR, LlcCodec, SnapCodec};
pub use llc::{Llc, Snap};
pub use lldp::Lldp;
pub(crate) use lldp::LldpCodec;
pub use stp::Stp;
pub(crate) use stp::StpCodec;
pub use vlan::{Vlan, Vlan8021ad};
pub(crate) use vlan::{Vlan8021adCodec, VlanCodec};
