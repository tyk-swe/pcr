// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::error::Classified;
use packetcraftr_netio::capture::{self, Provider};
use packetcraftr_netio::{Error, interface::Id};

struct WithoutTimestampDiscovery;

impl Provider for WithoutTimestampDiscovery {
    type Capture = capture::SystemSession;

    fn arm_capture(&self, _: &capture::Request, _: &Deadline) -> Result<Self::Capture, Error> {
        unreachable!("timestamp discovery must not arm capture")
    }
}

#[test]
fn capture_interruptions_precede_unsupported_capabilities() {
    let interface = Id {
        name: "fixture0".to_owned(),
        index: 7,
    };
    let request = capture::Request {
        interface: interface.clone(),
        limits: capture::Limits::default(),
        filter: None,
        promiscuous: false,
        native: Default::default(),
    };
    let frozen = Instant::now();
    let cancelled = Cancellation::default();
    cancelled.cancel();
    for (deadline, code) in [
        (
            Deadline::with_time_source(Duration::ZERO, move || frozen),
            "io.deadline_exceeded",
        ),
        (
            Deadline::with_time_source(Duration::ZERO, move || frozen)
                .with_cancellation(Some(cancelled)),
            "io.cancelled",
        ),
    ] {
        assert_eq!(
            WithoutTimestampDiscovery
                .timestamp_types(&interface, &deadline)
                .unwrap_err()
                .classification()
                .code,
            code,
        );
        assert_eq!(
            capture::SystemProvider
                .timestamp_types(&interface, &deadline)
                .unwrap_err()
                .classification()
                .code,
            code,
        );
        let error = match capture::SystemProvider.arm_capture(&request, &deadline) {
            Err(error) => error,
            Ok(_) => panic!("an interrupted caller must not open capture"),
        };
        assert_eq!(error.classification().code, code);
    }
    assert_eq!(
        WithoutTimestampDiscovery
            .timestamp_types(&interface, &Deadline::new(Duration::from_secs(1)))
            .unwrap_err()
            .classification()
            .code,
        "capability.unsupported",
    );
}
