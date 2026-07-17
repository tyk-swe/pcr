//! Link-layer protocol models.

mod model;

pub use model::{Arp, Ethernet, Vlan, Vlan8021ad};
pub(crate) use model::{ArpCodec, EthernetCodec, Vlan8021adCodec, VlanCodec};
