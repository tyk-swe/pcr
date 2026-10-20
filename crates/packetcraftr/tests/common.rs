// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Shared provider fixtures for policy and DNS cancellation contracts.

#[path = "common/dns.rs"]
pub(crate) mod dns;
#[path = "common/scanner_fixture.rs"]
pub(crate) mod scanner_fixture;

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use packetcraftr::ProviderSet;
use packetcraftr::target::{Hostname, Resolver};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::Error as LiveIoError;
use packetcraftr_netio::capture;
use packetcraftr_netio::interface::{self, Id as InterfaceId};
use packetcraftr_netio::link::Capability as LinkCapability;
use packetcraftr_netio::route::Decision;
use packetcraftr_netio::route::Provider;
use packetcraftr_netio::route::Scope;
use packetcraftr_netio::route::SelectionReason;
use packetcraftr_netio::tcp;
use packetcraftr_netio::transmit;

pub(crate) const INTERFACE_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
pub(crate) const SELECTED_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

pub(crate) type FakeProviders<R, I> =
    ProviderSet<R, Interfaces, I, I, ScriptedTcp, ScriptedResolver>;

pub(crate) fn providers<R, I: Clone>(route: R, io: I) -> FakeProviders<R, I> {
    ProviderSet {
        udp: (),
        route,
        interface: Interfaces::default(),
        capture: io.clone(),
        transmit: io,
        tcp: ScriptedTcp::default(),
        resolver: ScriptedResolver::default(),
    }
}

pub(crate) fn fixture_interface() -> interface::Info {
    interface::Info {
        id: InterfaceId {
            name: "fixture0".to_owned(),
            index: 1,
        },
        description: None,
        mac_address: Some(INTERFACE_MAC),
        addresses: Vec::new(),
        flags: interface::Flags::default(),
        mtu: Some(1_500),
        capability: LinkCapability::Layer2AndLayer3,
        link_type: LinkType::ETHERNET,
    }
}

#[derive(Clone)]
pub(crate) struct Interfaces {
    pub(crate) list: Vec<interface::Info>,
    pub(crate) steps: Steps,
}

impl Default for Interfaces {
    fn default() -> Self {
        Self {
            list: vec![fixture_interface()],
            steps: Steps::default(),
        }
    }
}

impl interface::Provider for Interfaces {
    fn interfaces(&self, _deadline: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        self.steps.push(Step::Interfaces);
        Ok(self.list.clone())
    }
}

#[derive(Clone, Default)]
pub(crate) struct ScriptedTcp {
    pub(crate) steps: Steps,
}

impl tcp::Provider for ScriptedTcp {
    type Stream = tcp::SystemStream;

    fn connect(
        &self,
        endpoint: SocketAddr,
        _deadline: &Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        self.steps.push(Step::Connect(endpoint));
        Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "fixture refusal").into())
    }
}

#[derive(Clone, Default)]
pub(crate) struct ScriptedResolver {
    pub(crate) steps: Steps,
}

impl Resolver for ScriptedResolver {
    fn resolve(
        &self,
        hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, packetcraftr::target::Error> {
        self.steps.push(Step::Resolve(hostname.to_string()));
        Ok(Vec::new())
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct FixedRoutes;

impl Provider for FixedRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
        _deadline: &Deadline,
    ) -> Result<Decision, Self::Error> {
        Ok(Decision {
            interface: InterfaceId {
                name: "fixture0".to_owned(),
                index: 1,
            },
            source_mac: Some(INTERFACE_MAC),
            selected_source: Some(IpAddr::V4(SELECTED_SOURCE)),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Link,
            mtu: 1_500,
            capability: LinkCapability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        })
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct NeverTransmit;

impl transmit::Provider for NeverTransmit {
    fn send(&self, _frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        unreachable!("a refused wire must not reach transmission")
    }
}

impl capture::Provider for NeverTransmit {
    type Capture = IdleCapture;

    fn arm_capture(
        &self,
        request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Self::Capture, LiveIoError> {
        Ok(IdleCapture(capture::Metadata {
            interface: request.interface.clone(),
            link_type: LinkType::ETHERNET,
            snap_length: request.limits.snap_length,
            native: Default::default(),
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    Interfaces,
    Connect(SocketAddr),
    Resolve(String),
}

#[derive(Clone, Default)]
pub(crate) struct Steps(Arc<Mutex<Vec<Step>>>);

impl Steps {
    pub(crate) fn push(&self, step: Step) {
        self.0.lock().expect("steps lock").push(step);
    }

    pub(crate) fn take(&self) -> Vec<Step> {
        std::mem::take(&mut *self.0.lock().expect("steps lock"))
    }
}

pub(crate) struct IdleCapture(capture::Metadata);

impl capture::Session for IdleCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.0
    }

    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
}
