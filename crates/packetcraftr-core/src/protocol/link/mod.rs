// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Link-layer protocol models.

mod arp;
mod ethernet;
mod llc;
mod vlan;

pub use arp::Arp;
pub(crate) use arp::ArpCodec;
pub use ethernet::Ethernet;
pub(crate) use ethernet::EthernetCodec;
pub(crate) use llc::{LLC_FRAME_DISCRIMINATOR, LlcCodec, SnapCodec};
pub use llc::{Llc, Snap};
pub use vlan::{Vlan, Vlan8021ad};
pub(crate) use vlan::{Vlan8021adCodec, VlanCodec};
