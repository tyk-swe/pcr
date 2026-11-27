// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};

use packetcraftr_core::{
    frame::{Frame, LinkType},
    registry::Registry,
};
use packetcraftr_netio::{Error, interface};

use super::*;
use crate::{forwarding, policy::Policy, providers::ProviderSet};

struct Capture {
    metadata: native::Metadata,
    delivered: bool,
}

impl native::Session for Capture {
    fn metadata(&self) -> &native::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _: &Deadline) -> Result<(), Error> {
        Ok(())
    }

    fn next_captured_frame(&mut self, _: &Deadline) -> Result<Option<native::Captured>, Error> {
        assert!(!self.delivered);
        self.delivered = true;
        let frame = Frame::new(None, LinkType::ETHERNET, vec![42]).unwrap();
        Ok(Some(native::Captured::new(frame, None)))
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn stats(&self) -> native::Stats {
        native::Stats {
            received_frames: u64::from(self.delivered),
            received_bytes: u64::from(self.delivered),
            ..Default::default()
        }
    }
}

struct Provider;

impl native::Provider for Provider {
    type Capture = Capture;

    fn arm_capture(&self, request: &native::Request, _: &Deadline) -> Result<Self::Capture, Error> {
        Ok(Capture {
            metadata: native::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::ETHERNET,
                snap_length: request.settings.limits.snap_length,
                native: Default::default(),
            },
            delivered: false,
        })
    }
}

#[derive(Clone)]
struct ClockControl {
    start: Instant,
    expired: Arc<AtomicBool>,
}

impl Clock for ClockControl {
    type Error = Infallible;

    fn now(&self) -> Instant {
        self.start
            + if self.expired.load(Ordering::Relaxed) {
                Duration::from_secs(10)
            } else {
                Duration::ZERO
            }
    }

    fn wall_now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
    }

    fn sleep(&self, _: Duration, _: &Deadline) -> Result<(), Self::Error> {
        panic!("capture should not sleep through its injected clock")
    }
}

#[test]
fn selector_finishing_after_window_cannot_publish_frame() {
    let expired = Arc::new(AtomicBool::new(false));
    let client = Client::new(
        Arc::new(Registry::default()),
        Policy::default(),
        ProviderSet::capture(interface::SystemProvider, Provider),
    )
    .with_clock(ClockControl {
        start: Instant::now(),
        expired: Arc::clone(&expired),
    });
    let window = Duration::from_secs(2);
    let request = Request::new(
        native::GroupRequest::new(
            vec![interface::Id {
                index: 1,
                name: "controlled".into(),
            }],
            native::Limits::default(),
        ),
        window,
    )
    .with_selector(move |_, _| {
        expired.store(true, Ordering::Relaxed);
        Ok(true)
    });
    let mut started = false;
    let report = client
        .capture(
            request,
            forwarding(|event, deadline| {
                match event {
                    Event::Started { .. } => {
                        started = true;
                        assert!(deadline.unwrap().remaining().unwrap() <= window);
                    }
                    Event::Frame { .. } => panic!("expired frame reached the sink"),
                }
                Ok(Control::Continue)
            }),
        )
        .unwrap();
    assert!(started);
    assert_eq!(report.stop, StopReason::Window);
    assert_eq!(report.frames_delivered, 1);
    assert_eq!(report.sources[0].matched_frames, 0);
}
