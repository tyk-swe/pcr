// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(unreachable_pub)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use packetcraftr::target::{self, Hostname, Resolver};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_netio::Error as LiveIoError;
use packetcraftr_netio::capture::{self, Captured};
use packetcraftr_netio::interface::{self, Id as InterfaceId};
use packetcraftr_netio::link::Capability;
use packetcraftr_netio::route::{self, Decision};
use packetcraftr_netio::tcp;
use packetcraftr_netio::transmit;

pub fn fixture_interface() -> InterfaceId {
    InterfaceId {
        name: "fixture0".to_owned(),
        index: 1,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    Responsive,
    Closed,
    Blocked,
    Silent,
    Malformed,
    Unrelated,
}

impl Condition {
    pub const IDS: &'static [&'static str] = &[
        "responsive",
        "closed",
        "blocked",
        "silent",
        "malformed",
        "unrelated",
    ];

    pub fn parse(token: &str) -> Result<Self, String> {
        match token {
            "responsive" => Ok(Self::Responsive),
            "closed" => Ok(Self::Closed),
            "blocked" => Ok(Self::Blocked),
            "silent" => Ok(Self::Silent),
            "malformed" => Ok(Self::Malformed),
            "unrelated" => Ok(Self::Unrelated),
            other => Err(format!(
                "unknown condition `{other}`; expected one of {}",
                Self::IDS.join(", ")
            )),
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::Responsive => "responsive",
            Self::Closed => "closed",
            Self::Blocked => "blocked",
            Self::Silent => "silent",
            Self::Malformed => "malformed",
            Self::Unrelated => "unrelated",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FamilyAddresses {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub router: IpAddr,
}

impl FamilyAddresses {
    pub const IPV4: Self = Self {
        source: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        destination: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2)),
        router: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 254)),
    };
    pub const IPV6: Self = Self {
        source: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
        destination: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
        router: IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x0db8, 0, 0, 0, 0, 0, 0xffff,
        )),
    };

    pub fn parse(family: &str) -> Result<(&'static str, Self), String> {
        match family {
            "ipv4" => Ok(("ipv4", Self::IPV4)),
            "ipv6" => Ok(("ipv6", Self::IPV6)),
            other => Err(format!("unknown family `{other}`; expected ipv4 or ipv6")),
        }
    }
}

#[derive(Clone, Default)]
pub struct Io {
    state: Arc<Mutex<State>>,
    armed: Arc<AtomicUsize>,
    readied: Arc<AtomicUsize>,
    shutdowns: Arc<AtomicUsize>,
}

#[derive(Default)]
struct State {
    sent: Vec<Vec<u8>>,
    reports: Vec<transmit::Timing>,
    frames: VecDeque<(std::time::Instant, std::time::SystemTime, Vec<u8>)>,
    delivered: Vec<(std::time::SystemTime, Vec<u8>)>,
}

impl Io {
    pub fn sent(&self) -> Vec<Vec<u8>> {
        self.state.lock().expect("fixture io").sent.clone()
    }

    pub fn send_timings(&self) -> Vec<transmit::Timing> {
        self.state.lock().expect("fixture io").reports.clone()
    }

    pub fn pending_frames(&self) -> usize {
        self.state.lock().expect("fixture io").frames.len()
    }

    pub fn delivered(&self) -> Vec<(std::time::SystemTime, Vec<u8>)> {
        self.state.lock().expect("fixture io").delivered.clone()
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.armed.load(Ordering::SeqCst),
            self.readied.load(Ordering::SeqCst),
            self.shutdowns.load(Ordering::SeqCst),
        )
    }

    pub fn deliver_frame(&self, bytes: Vec<u8>) {
        self.push_frame(bytes);
    }

    fn push_frame(&self, bytes: Vec<u8>) {
        self.state.lock().expect("fixture io").frames.push_back((
            std::time::Instant::now(),
            std::time::SystemTime::now(),
            bytes,
        ));
    }
}

fn fixture_decision(interface: InterfaceId, addresses: FamilyAddresses) -> Decision {
    Decision {
        interface,
        source_mac: None,
        selected_source: Some(addresses.source),
        preferred_source: None,
        next_hop: None,
        selection_reason: route::SelectionReason::OnLink,
        destination_scope: route::Scope::Link,
        mtu: 1500,
        capability: Capability::Layer3,
        link_type: LinkType::RAW,
    }
}

pub type Responder = Arc<dyn Fn(&[u8]) -> Vec<Vec<u8>> + Send + Sync>;

#[derive(Clone)]
pub struct Providers {
    io: Io,
    addresses: FamilyAddresses,
    responder: Responder,
}

impl Providers {
    pub fn new(io: Io, addresses: FamilyAddresses, responder: Responder) -> Self {
        Self {
            io,
            addresses,
            responder,
        }
    }
}

impl packetcraftr::CaptureProviders for Providers {
    type Interface = Self;
    type Capture = Self;

    fn interface(&self) -> &Self {
        self
    }

    fn capture(&self) -> &Self {
        self
    }
}

impl packetcraftr::PacketProviders for Providers {
    type Route = Self;
    type Transmit = Self;

    fn route(&self) -> &Self {
        self
    }

    fn transmit(&self) -> &Self {
        self
    }
}

impl packetcraftr::TargetProviders for Providers {
    type Resolver = Self;

    fn resolver(&self) -> &Self {
        self
    }
}

impl packetcraftr::TcpProviders for Providers {
    type Tcp = Self;

    fn tcp(&self) -> &Self {
        self
    }
}

impl interface::Provider for Providers {
    fn interfaces(&self, _deadline: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        Ok(vec![interface::Info {
            id: fixture_interface(),
            description: None,
            mac_address: None,
            addresses: Vec::new(),
            flags: interface::Flags::default(),
            mtu: Some(1500),
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        }])
    }
}

pub struct Session {
    io: Io,
    metadata: capture::Metadata,
    readied: Arc<AtomicUsize>,
    shutdowns: Arc<AtomicUsize>,
    ready: bool,
    stopped: bool,
}

impl capture::Session for Session {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), LiveIoError> {
        if !self.ready {
            self.ready = true;
            self.readied.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<Captured>, LiveIoError> {
        loop {
            let frame = self.io.state.lock().expect("fixture io").frames.pop_front();
            match frame {
                Some((queued_at, timestamp, bytes)) => {
                    self.io
                        .state
                        .lock()
                        .expect("fixture io")
                        .delivered
                        .push((timestamp, bytes.clone()));
                    return Ok(Some(Captured::new(
                        Frame::new(timestamp, LinkType::RAW, Bytes::from(bytes))
                            .expect("fixture frames carry bytes"),
                        queued_at,
                    )));
                }
                None => {
                    deadline.check_cancelled().map_err(LiveIoError::from)?;
                    match deadline.remaining() {
                        Ok(remaining) if !remaining.is_zero() => {
                            std::thread::sleep(remaining.min(Duration::from_millis(1)));
                        }
                        _ => {
                            deadline.check_cancelled().map_err(LiveIoError::from)?;
                            return Ok(None);
                        }
                    }
                }
            }
        }
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        if !self.stopped {
            self.stopped = true;
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
}

impl capture::Provider for Providers {
    type Capture = Session;

    fn arm_capture(
        &self,
        request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Session, LiveIoError> {
        assert_eq!(
            request.interface,
            fixture_interface(),
            "capture must arm on the fixture interface identity"
        );
        self.io.armed.fetch_add(1, Ordering::SeqCst);
        Ok(Session {
            io: self.io.clone(),
            ready: false,
            stopped: false,
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::RAW,
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
            readied: self.io.readied.clone(),
            shutdowns: self.io.shutdowns.clone(),
        })
    }
}

impl route::Provider for Providers {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
        _deadline: &Deadline,
    ) -> Result<Decision, Infallible> {
        assert_eq!(
            destination, self.addresses.destination,
            "the workflow must route toward the corpus destination"
        );
        if let Some(hint) = interface_hint {
            assert_eq!(
                *hint,
                fixture_interface(),
                "a pinned interface hint must be the fixture interface"
            );
        }
        assert!(
            preferred_source.is_none_or(|source| source == self.addresses.source),
            "a preferred source must be the corpus source: {preferred_source:?}"
        );
        Ok(fixture_decision(fixture_interface(), self.addresses))
    }
}

impl transmit::Provider for Providers {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        let armed = self.io.armed.load(Ordering::SeqCst);
        assert!(
            armed > 0 && self.io.readied.load(Ordering::SeqCst) == armed,
            "a send was attempted before the armed capture reported readiness"
        );
        let bytes = frame.bytes().to_vec();
        let report = transmit::Report::committed(bytes.len(), Bytes::from(bytes.clone()));
        let mut state = self.io.state.lock().expect("fixture io");
        state.reports.push(report.timing());
        state.sent.push(bytes.clone());
        drop(state);
        for response in (self.responder)(&bytes) {
            self.io.push_frame(response);
        }
        Ok(report)
    }
}

impl Resolver for Providers {
    fn resolve(&self, _hostname: &Hostname, _limit: usize) -> Result<Vec<IpAddr>, target::Error> {
        Ok(Vec::new())
    }
}

impl tcp::Provider for Providers {
    type Stream = NeverStream;

    fn connect(
        &self,
        _endpoint: SocketAddr,
        _deadline: &Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the packet fixture never performs a TCP connect",
        )
        .into())
    }
}

pub struct NeverStream {
    peer: SocketAddr,
}

impl std::io::Read for NeverStream {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

impl std::io::Write for NeverStream {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

impl tcp::Stream for NeverStream {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer)
    }

    fn set_read_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}
