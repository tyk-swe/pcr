// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::convert::Infallible;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{BoundaryError, Classification, Code, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
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
struct Transmit {
    sends: Arc<AtomicUsize>,
    replies: Arc<Mutex<VecDeque<Frame>>>,
    reply_sends: Arc<[bool]>,
}

fn reply_frame(bytes: &[u8]) -> Option<Frame> {
    if bytes.len() < 28 || bytes[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(bytes[0] & 0x0f) * 4;
    if header_len < 20 || bytes.len() < header_len + 8 || bytes[9] != 17 {
        return None;
    }
    let mut response = bytes.to_vec();
    response[12..16].copy_from_slice(&bytes[16..20]);
    response[16..20].copy_from_slice(&bytes[12..16]);
    response[header_len..header_len + 2].copy_from_slice(&bytes[header_len + 2..header_len + 4]);
    response[header_len + 2..header_len + 4].copy_from_slice(&bytes[header_len..header_len + 2]);
    Frame::new(Some(std::time::SystemTime::now()), LinkType::RAW, response).ok()
}

impl transmit::Provider for Transmit {
    fn send(&self, outbound: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        let index = self.sends.fetch_add(1, Ordering::Relaxed);
        if self.reply_sends.get(index).copied().unwrap_or(false)
            && let Some(frame) = reply_frame(outbound.bytes())
        {
            self.replies.lock().expect("reply lock").push_back(frame);
        }
        Ok(
            transmit::Submission::start()
                .complete(outbound.bytes().len(), outbound.bytes().clone()),
        )
    }
}

struct SilentCapture {
    id: interface::Id,
    replies: Arc<Mutex<VecDeque<Frame>>>,
}

struct SilentSession {
    metadata: capture::Metadata,
    replies: Arc<Mutex<VecDeque<Frame>>>,
}

impl capture::Provider for SilentCapture {
    type Capture = SilentSession;

    fn arm_capture(
        &self,
        _request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Self::Capture, LiveIoError> {
        Ok(SilentSession {
            metadata: capture::Metadata {
                interface: self.id.clone(),
                link_type: LinkType::RAW,
                snap_length: 65_535,
                native: capture::RealizedSettings::default(),
            },
            replies: Arc::clone(&self.replies),
        })
    }
}

impl capture::Session for SilentSession {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        if let Some(frame) = self.replies.lock().expect("reply lock").pop_front() {
            return Ok(Some(capture::Captured::new(
                frame,
                Some(std::time::Instant::now()),
            )));
        }
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

pub(crate) fn client_with_reply_script(
    destination: IpAddr,
    reply_sends: &[bool],
) -> (
    Client<impl PacketProviders + TargetProviders + TcpProviders>,
    Arc<AtomicUsize>,
) {
    build_client(destination, reply_sends)
}

pub(crate) fn client(
    destination: IpAddr,
) -> (
    Client<impl PacketProviders + TargetProviders + TcpProviders>,
    Arc<AtomicUsize>,
) {
    build_client(destination, &[])
}

fn build_client(
    destination: IpAddr,
    reply_sends: &[bool],
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
    let replies = Arc::new(Mutex::new(VecDeque::new()));
    let transmit = Transmit {
        sends: Arc::default(),
        replies: Arc::clone(&replies),
        reply_sends: Arc::from(reply_sends),
    };
    let sends = Arc::clone(&transmit.sends);
    let providers = ProviderSet::packet(
        routes,
        Interfaces(id.clone()),
        SilentCapture { id, replies },
        transmit,
    )
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
