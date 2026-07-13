// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::io::Cursor;
use std::time::{Duration, SystemTime};

use packetcraftr::{
    capture::{Frame, LinkType, Reader, Writer},
    net::{Error as LiveIoError, interface::Id, link::Mode, transmit::Report},
    workflow::{
        clock::Clock as ReplayClock,
        replay::{
            AuthorizationError, Authorizer as ReplayAuthorizer, Limits, Options, Timing,
            Transmission, Transmitter as ReplayTransmitter, run,
        },
    },
};

struct Authorizer;

impl ReplayAuthorizer for Authorizer {
    fn authorize(&mut self, _frame: &Frame, _mode: Mode) -> Result<(), AuthorizationError> {
        Ok(())
    }
}

struct Transmitter;

impl ReplayTransmitter for Transmitter {
    fn validate_interface(
        &mut self,
        interface: &Id,
        _mode: Mode,
        _frame: &Frame,
    ) -> Result<Id, LiveIoError> {
        Ok(interface.clone())
    }

    fn transmit(
        &mut self,
        interface: &Id,
        _mode: Mode,
        frame: &Frame,
    ) -> Result<Transmission, LiveIoError> {
        Ok(Transmission {
            interface: interface.clone(),
            report: Report {
                bytes_sent: frame.bytes.len(),
                wire_bytes: Some(frame.bytes.clone()),
            },
        })
    }
}

#[derive(Default)]
struct Clock(Vec<Duration>);

impl ReplayClock for Clock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.0.push(delay);
        Ok(())
    }
}

#[test]
fn downstream_code_can_inject_replay_policy_timing_and_transmission() {
    let original =
        Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![0, 1, 2, 3]).unwrap();
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    writer.write_frame(&original).unwrap();
    let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
    let options = Options {
        interface: Id {
            name: "injected0".to_owned(),
            index: 1,
        },
        link_mode: Mode::Auto,
        timing: Timing::Immediate,
        limits: Limits::default(),
    };
    let mut authorizer = Authorizer;
    let mut transmitter = Transmitter;
    let mut clock = Clock::default();
    let mut evidence = Vec::new();
    let summary = run(
        &mut reader,
        &options,
        &mut authorizer,
        &mut transmitter,
        &mut clock,
        |frame| {
            evidence.push(frame);
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(summary.frames_completed, 1);
    assert_eq!(summary.bytes_completed, 4);
    assert_eq!(clock.0, [Duration::ZERO]);
    assert_eq!(evidence[0].frame, original);
}
