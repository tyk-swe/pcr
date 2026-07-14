use std::net::IpAddr;
use std::time::Instant;

use crate::capture::{Frame, LinkType};
use crate::net::{
    link::MacAddress,
    route::{InterfaceId, NeighborRequest, NeighborVlanTag},
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct NeighborCacheKey {
    interface: InterfaceId,
    interface_source: IpAddr,
    interface_mac: MacAddress,
    target: IpAddr,
    vlan_tags: Vec<NeighborVlanTag>,
    link_type: LinkType,
}

impl From<&NeighborRequest> for NeighborCacheKey {
    fn from(request: &NeighborRequest) -> Self {
        Self {
            interface: request.interface.clone(),
            interface_source: request.interface_source,
            interface_mac: request.interface_mac,
            target: request.target,
            vlan_tags: request.vlan_tags.clone(),
            link_type: request.link_type,
        }
    }
}

#[derive(Debug)]
pub(super) struct NeighborCacheEntry {
    pub(super) mac_address: MacAddress,
    pub(super) inserted_at: Instant,
    pub(super) expires_at: Instant,
}

pub(super) struct NeighborExchangeOutcome {
    pub(super) mac_address: Option<MacAddress>,
    pub(super) attempts: u32,
    pub(super) captured: Vec<Frame>,
    pub(super) evidence_truncated: bool,
}
