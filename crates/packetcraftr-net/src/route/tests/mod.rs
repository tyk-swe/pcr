// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;

use super::models::{LinkCapability, LinkMode, MacAddress};
use super::{
    DestinationScope, InterfaceId, NeighborError, NeighborRequest, NeighborResolution,
    NeighborResolver, NeighborVlanKind, NeighborVlanTag, PlanError, PlanOptions, RouteDecision,
    RoutePlanner, RouteProvider, RouteSelectionReason,
};
#[cfg(not(feature = "native-route"))]
use super::{NativeRouteError, SystemRouteProvider};
use crate::capture::CaptureStatistics;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_packet::{Packet, field::WireValue, layer::Raw};
use packetcraftr_protocol::{
    gre::Gre,
    ipv6::SegmentRoutingHeader,
    link::{Arp, Ethernet, Vlan, Vlan8021ad},
    network::{Ipv4, Ipv6},
    transport::Udp,
    tunnel::Vxlan,
};

struct FixedRoute(RouteDecision);

impl RouteProvider for FixedRoute {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        Ok(self.0.clone())
    }
}

struct PreferenceAwareRoute;

impl RouteProvider for PreferenceAwareRoute {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        let mut decision = route(None);
        if let Some(preferred_source) = preferred_source {
            decision.selected_address = Some(preferred_source);
            decision.preferred_source = Some(preferred_source);
        }
        Ok(decision)
    }
}

struct InterfaceOnlyRoute {
    decision: RouteDecision,
    ip_lookups: AtomicUsize,
    interface_lookups: AtomicUsize,
}

impl InterfaceOnlyRoute {
    fn new(decision: RouteDecision) -> Self {
        Self {
            decision,
            ip_lookups: AtomicUsize::new(0),
            interface_lookups: AtomicUsize::new(0),
        }
    }
}

impl RouteProvider for InterfaceOnlyRoute {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        self.ip_lookups.fetch_add(1, Ordering::SeqCst);
        Ok(self.decision.clone())
    }

    fn lookup_interface(
        &self,
        _interface: &InterfaceId,
    ) -> Result<Option<RouteDecision>, Self::Error> {
        self.interface_lookups.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.decision.clone()))
    }
}

struct NeverResolve;

impl NeighborResolver for NeverResolve {
    fn resolve_request(
        &self,
        _request: &NeighborRequest,
    ) -> Result<NeighborResolution, NeighborError> {
        unreachable!("invalid plan must fail before calling the resolver")
    }
}

struct RecordingResolver {
    request: Mutex<Option<NeighborRequest>>,
    resolution: NeighborResolution,
}

impl NeighborResolver for RecordingResolver {
    fn resolve_request(
        &self,
        request: &NeighborRequest,
    ) -> Result<NeighborResolution, NeighborError> {
        *self.request.lock().unwrap() = Some(request.clone());
        Ok(self.resolution.clone())
    }
}

fn route(next_hop: Option<IpAddr>) -> RouteDecision {
    RouteDecision {
        interface: InterfaceId {
            name: "test0".to_owned(),
            index: 7,
        },
        source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
        selected_address: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        preferred_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        next_hop,
        selection_reason: if next_hop.is_some() {
            RouteSelectionReason::Gateway
        } else {
            RouteSelectionReason::OnLink
        },
        destination_scope: DestinationScope::Global,
        mtu: 1500,
        capability: LinkCapability::Layer2And3,
        link_type: LinkType::ETHERNET,
    }
}

fn canonical_link_intent_packets() -> Vec<(&'static str, Packet)> {
    let network_layer = || Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 10),
        destination: Ipv4Addr::new(198, 51, 100, 1),
        ..Ipv4::default()
    };

    let mut ethernet = Packet::new();
    ethernet.push(Ethernet::default()).push(network_layer());

    let mut customer_vlan_root = Packet::new();
    customer_vlan_root
        .push(Vlan::default())
        .push(network_layer());

    let mut service_vlan_root = Packet::new();
    service_vlan_root
        .push(Vlan8021ad::default())
        .push(network_layer());

    let mut ethernet_stacked = Packet::new();
    ethernet_stacked
        .push(Ethernet::default())
        .push(Vlan8021ad {
            vlan_id: 100,
            ..Vlan8021ad::default()
        })
        .push(Vlan {
            vlan_id: 200,
            ..Vlan::default()
        })
        .push(network_layer());

    let mut vlan_rooted_stacked = Packet::new();
    vlan_rooted_stacked
        .push(Vlan8021ad {
            vlan_id: 100,
            ..Vlan8021ad::default()
        })
        .push(Vlan {
            vlan_id: 200,
            ..Vlan::default()
        })
        .push(network_layer());

    // This deliberately unusual order proves canonical link intent wins
    // over the otherwise Layer 3-capable IP-root Auto branch.
    let mut ip_root_with_service_vlan = Packet::new();
    ip_root_with_service_vlan
        .push(network_layer())
        .push(Vlan8021ad::default());

    vec![
        ("ethernet", ethernet),
        ("vlan", customer_vlan_root),
        ("vlan8021ad", service_vlan_root),
        ("ethernet-stacked-vlan", ethernet_stacked),
        ("vlan-rooted-stacked-vlan", vlan_rooted_stacked),
        ("ip-root-with-service-vlan", ip_root_with_service_vlan),
    ]
}

mod link_intent;
mod materialization;
mod source_routing;
