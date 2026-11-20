// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::capture_file::{Reader, Writer};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::{MacAddress, Packet};
use packetcraftr_core::protocol::{builtin, link::Ethernet, network::Ipv4, transport::Udp};
use packetcraftr_core::{build, codec};
use packetcraftr_netio::{
    Error as LiveIoError, capture, interface,
    link::{Capability, Mode as LinkMode},
    route::{Decision, Provider as RouteProvider},
    transmit::{self, Outbound, Report as IoSendReport},
};

use crate::clock::Clock;
use crate::policy::Policy;
use crate::providers::{CaptureProviders, PacketProviders};
use crate::replay::{Error, Report};
use crate::route::Interface;

use super::super::admission::FrameAdmission;
use super::super::executor::ProviderExecutor;
use super::super::request::{Limits, Options, Parts, Selector, Source, Timing};
use super::run;

#[derive(Clone)]
struct SharedClock(Arc<Mutex<Instant>>);

impl Clock for SharedClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }

    fn wall_now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
    }

    fn sleep(&self, _: Duration, _: &Deadline) -> Result<(), Infallible> {
        Ok(())
    }
}

struct ExpiringSelector {
    now: Arc<Mutex<Instant>>,
    advance: Duration,
}

impl Selector for ExpiringSelector {
    fn select(&mut self, _: u64, _: &Frame) -> Result<bool, Error> {
        *self.now.lock().unwrap() += self.advance;
        Ok(true)
    }

    fn interface(&mut self, _: u64, _: &Frame) -> Result<Interface, Error> {
        unreachable!("the deadline expires before routing")
    }
}

struct Layer2Selector;

impl Selector for Layer2Selector {
    fn select(&mut self, _: u64, _: &Frame) -> Result<bool, Error> {
        Ok(true)
    }

    fn interface(&mut self, _: u64, _: &Frame) -> Result<Interface, Error> {
        Ok(Interface::Name(INTERFACE.to_owned()))
    }
}

#[derive(Default)]
struct Providers {
    interfaces: Vec<interface::Info>,
    sent: Mutex<Vec<Bytes>>,
}

impl interface::Provider for Providers {
    fn interfaces(&self, _: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        Ok(self.interfaces.clone())
    }
}

impl RouteProvider for Providers {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&interface::Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<Decision, Infallible> {
        unreachable!("Layer 2 replay never looks up a route")
    }
}

impl capture::Provider for Providers {
    type Capture = Box<dyn capture::Session>;

    fn arm_capture(
        &self,
        _: &capture::Request,
        _: &Deadline,
    ) -> Result<Self::Capture, LiveIoError> {
        unreachable!("replay reads a capture file, not a live capture")
    }
}

impl transmit::Provider for Providers {
    fn send(&self, frame: Outbound<'_>) -> Result<IoSendReport, LiveIoError> {
        self.sent.lock().unwrap().push(frame.bytes().clone());
        Ok(transmit::Submission::start().complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

impl CaptureProviders for Providers {
    type Interface = Self;
    type Capture = Self;

    fn interface(&self) -> &Self {
        self
    }

    fn capture(&self) -> &Self {
        self
    }
}

impl PacketProviders for Providers {
    type Route = Self;
    type Transmit = Self;

    fn route(&self) -> &Self {
        self
    }

    fn transmit(&self) -> &Self {
        self
    }
}

const INTERFACE: &str = "replay0";
const INTERFACE_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 1]);

fn capture(bytes: impl Into<Bytes>) -> Reader<Cursor<Vec<u8>>> {
    let frame = Frame::new(Some(SystemTime::UNIX_EPOCH), LinkType::ETHERNET, bytes).unwrap();
    let mut writer =
        Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, Default::default()).unwrap();
    writer.write_frame(&frame).unwrap();
    Reader::with_limits(Cursor::new(writer.into_inner()), Default::default()).unwrap()
}

#[test]
fn a_step_that_expires_the_deadline_reports_the_deadline_error() {
    let now = Instant::now();
    let shared = Arc::new(Mutex::new(now));
    let deadline = Deadline::with_time_source(Duration::from_secs(1), {
        let shared = Arc::clone(&shared);
        move || *shared.lock().unwrap()
    });
    let options = Options {
        repeat: 1,
        inter_pass_delay: Duration::ZERO,
        link_mode: LinkMode::Layer2,
        timing: Timing::Immediate,
        max_gap: None,
        limits: Limits::default(),
        allow_permissive_live: false,
    };
    let parts = Parts {
        source: Source::stream(capture(vec![0_u8; 60])),
        selector: ExpiringSelector {
            now: Arc::clone(&shared),
            advance: Duration::from_secs(2),
        },
        options,
    };
    let policy = Policy::default();
    let mut authorizer = FrameAdmission::new(&policy, builtin::registry(), false);
    let providers = Providers::default();
    let mut executor = ProviderExecutor::new(&providers);
    let mut clock = SharedClock(shared);

    let result = run(
        parts,
        &mut authorizer,
        &mut executor,
        &mut clock,
        deadline,
        |_, _| Ok(()),
    );

    assert!(matches!(
        result,
        Err(Error::DurationLimit {
            source_index: 0,
            ..
        })
    ));
}

fn udp_frame_from(source: Ipv4Addr) -> Bytes {
    let mut packet = Packet::default();
    packet.push(Ethernet {
        destination: [2, 0, 0, 0, 0, 9],
        source: INTERFACE_MAC.0,
        ..Default::default()
    });
    packet.push(Ipv4 {
        source,
        destination: Ipv4Addr::new(10, 0, 0, 9),
        ..Default::default()
    });
    packet.push(Udp {
        source_port: 40_000,
        destination_port: 9,
        ..Default::default()
    });
    packet.push(Raw::new(Bytes::from_static(&[0; 18])));
    build::Builder::new(builtin::registry())
        .build(
            packet,
            codec::Addresses::default(),
            build::Options::default(),
        )
        .unwrap()
        .bytes
}

fn replay_layer2_from(source: Ipv4Addr) -> (Result<Report, Error>, Vec<Bytes>) {
    let frame = udp_frame_from(source);
    let parts = Parts {
        source: Source::stream(capture(frame)),
        selector: Layer2Selector,
        options: Options {
            repeat: 1,
            inter_pass_delay: Duration::ZERO,
            link_mode: LinkMode::Layer2,
            timing: Timing::Immediate,
            max_gap: None,
            limits: Limits::default(),
            allow_permissive_live: true,
        },
    };
    let providers = Providers {
        interfaces: vec![interface::Info {
            id: interface::Id {
                name: INTERFACE.to_owned(),
                index: 1,
            },
            description: None,
            mac_address: Some(INTERFACE_MAC),
            addresses: [1, 2]
                .map(|host| interface::Address {
                    address: Ipv4Addr::new(10, 0, 0, host).into(),
                    prefix_length: 24,
                })
                .into(),
            flags: interface::Flags {
                up: true,
                ..Default::default()
            },
            mtu: Some(1500),
            capability: Capability::Layer2,
            link_type: LinkType::ETHERNET,
        }],
        ..Default::default()
    };
    let policy = Policy {
        allow_permissive_packets: true,
        ..Policy::default()
    };
    let mut authorizer = FrameAdmission::new(&policy, builtin::registry(), true);
    let mut executor = ProviderExecutor::new(&providers);
    let mut clock = SharedClock(Arc::new(Mutex::new(Instant::now())));
    let result = run(
        parts,
        &mut authorizer,
        &mut executor,
        &mut clock,
        Deadline::new(Duration::from_secs(5)),
        |_, _| Ok(()),
    );
    drop(executor);
    (result, providers.sent.into_inner().unwrap())
}

#[test]
fn layer2_replay_sends_from_any_owned_interface_address_and_refuses_foreign_sources() {
    let owned = Ipv4Addr::new(10, 0, 0, 2);
    let (result, sent) = replay_layer2_from(owned);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(sent, [udp_frame_from(owned)]);

    let (result, sent) = replay_layer2_from(Ipv4Addr::new(10, 0, 0, 3));
    assert!(
        matches!(
            result,
            Err(Error::Authorization {
                source_index: 0,
                ..
            })
        ),
        "{result:?}"
    );
    assert!(sent.is_empty());
}
