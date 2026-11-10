// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{BoundaryError, Classification, Code, Kind};
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;
use packetcraftr_core::protocol::builtin;
use packetcraftr_netio::{
    Error as LiveIoError, capture, interface, link::Capability, route, transmit,
};

use crate::policy::{DestinationConstraint, Policy};
use crate::providers::{PacketProviders, TargetProviders, TcpProviders};
use crate::{Client, Delivery, ProviderSet, Sink};

#[derive(Clone)]
struct Routes(Arc<Mutex<route::Decision>>);

impl route::Provider for Routes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&interface::Id>,
        _preferred_source: Option<IpAddr>,
        _deadline: &Deadline,
    ) -> Result<route::Decision, Self::Error> {
        Ok(self.0.lock().expect("route lock").clone())
    }
}

struct Interfaces(interface::Id);

impl interface::Provider for Interfaces {
    fn interfaces(&self, _deadline: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        Ok(vec![interface::Info {
            id: self.0.clone(),
            description: None,
            mac_address: None,
            addresses: Vec::new(),
            flags: interface::Flags::default(),
            mtu: Some(1_500),
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::RAW,
        }])
    }
}

#[derive(Clone, Default)]
struct Transmit(Arc<AtomicUsize>);

impl transmit::Provider for Transmit {
    fn send(&self, outbound: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(
            transmit::Submission::start()
                .complete(outbound.bytes().len(), outbound.bytes().clone()),
        )
    }
}

struct SilentCapture(interface::Id);

struct SilentSession(capture::Metadata);

impl capture::Provider for SilentCapture {
    type Capture = SilentSession;

    fn arm_capture(
        &self,
        _request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Self::Capture, LiveIoError> {
        Ok(SilentSession(capture::Metadata {
            interface: self.0.clone(),
            link_type: LinkType::RAW,
            snap_length: 65_535,
            native: capture::RealizedSettings::default(),
        }))
    }
}

impl capture::Session for SilentSession {
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
        std::thread::sleep(Duration::from_millis(1));
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
}

pub(crate) fn client(
    destination: IpAddr,
) -> (
    Client<impl PacketProviders + TargetProviders + TcpProviders>,
    Arc<AtomicUsize>,
) {
    let id = interface::Id {
        index: 1,
        name: "workflow-test0".to_owned(),
    };
    let routes = Routes(Arc::new(Mutex::new(route::Decision {
        interface: id.clone(),
        source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
        selected_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        preferred_source: None,
        next_hop: None,
        selection_reason: route::SelectionReason::OnLink,
        destination_scope: route::Scope::Private,
        mtu: 1_500,
        capability: Capability::Layer2AndLayer3,
        link_type: LinkType::RAW,
    })));
    let transmit = Transmit::default();
    let sends = Arc::clone(&transmit.0);
    let providers =
        ProviderSet::packet(routes, Interfaces(id.clone()), SilentCapture(id), transmit)
            .with_tcp(packetcraftr_netio::tcp::SystemProvider)
            .with_resolver(crate::target::SystemResolver);
    let client = Client::new(
        builtin::registry(),
        Policy {
            allowed_destinations: vec![DestinationConstraint::Exact(destination)],
            ..Policy::default()
        },
        providers,
    );
    (client, sends)
}

pub(crate) struct FailSink<E> {
    calls: Arc<AtomicUsize>,
    event: PhantomData<fn(E)>,
}

pub(crate) fn fail_sink<E>(calls: &Arc<AtomicUsize>) -> FailSink<E> {
    FailSink {
        calls: Arc::clone(calls),
        event: PhantomData,
    }
}

impl<E: Send + 'static> Sink<E> for FailSink<E> {
    type Ack = ();

    fn delivery(&self) -> Delivery {
        Delivery::Cooperative
    }

    fn publish(&mut self, _event: E) -> Result<Self::Ack, BoundaryError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Err(BoundaryError::new(
            "test sink refused the first event",
            Classification::new(Code::IoTest, Kind::Io, None),
            Vec::new(),
        ))
    }
}
