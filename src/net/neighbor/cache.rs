#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct NeighborCacheKey {
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
struct NeighborCacheEntry {
    mac_address: MacAddress,
    inserted_at: Instant,
    expires_at: Instant,
}

struct NeighborExchangeOutcome {
    mac_address: Option<MacAddress>,
    attempts: u32,
    captured: Vec<Frame>,
    evidence_truncated: bool,
}
