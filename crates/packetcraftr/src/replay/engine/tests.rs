// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::io::Cursor;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::capture_file::{Reader, Writer};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::builtin;
use packetcraftr_netio::{
    Error as LiveIoError, capture, interface,
    link::Mode as LinkMode,
    route::{Decision, Provider as RouteProvider},
    transmit::{self, Outbound, Report as IoSendReport},
};

use crate::clock::Clock;
use crate::policy::Policy;
use crate::providers::{CaptureProviders, PacketProviders};
use crate::replay::Error;
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

struct Providers;

impl interface::Provider for Providers {
    fn interfaces(&self, _: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        unreachable!("the deadline expires before interface resolution")
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
        unreachable!("the deadline expires before route planning")
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
    fn send(&self, _: Outbound<'_>) -> Result<IoSendReport, LiveIoError> {
        unreachable!("the deadline expires before transmission")
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

fn capture() -> Reader<Cursor<Vec<u8>>> {
    let frame = Frame::new(
        Some(SystemTime::UNIX_EPOCH),
        LinkType::ETHERNET,
        vec![0_u8; 60],
    )
    .unwrap();
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
        source: Source::stream(capture()),
        selector: ExpiringSelector {
            now: Arc::clone(&shared),
            advance: Duration::from_secs(2),
        },
        options,
    };
    let policy = Policy::default();
    let mut authorizer = FrameAdmission::new(&policy, builtin::registry(), false);
    let providers = Providers;
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
