// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::io::Cursor;
use std::time::{Duration, SystemTime};

use packetcraftr::{
    replay_capture, CaptureReader, CaptureWriter, CapturedFrame, InterfaceId, IoSendReport,
    LinkMode, LinkType, LiveIoError, ReplayAuthorizationError, ReplayAuthorizer, ReplayClock,
    ReplayLimits, ReplayOptions, ReplayTiming, ReplayTransmission, ReplayTransmitter,
};

struct Authorizer;

impl ReplayAuthorizer for Authorizer {
    fn authorize(
        &mut self,
        _frame: &CapturedFrame,
        _mode: LinkMode,
    ) -> Result<(), ReplayAuthorizationError> {
        Ok(())
    }
}

struct Transmitter;

impl ReplayTransmitter for Transmitter {
    fn validate_interface(
        &mut self,
        interface: &InterfaceId,
        _mode: LinkMode,
        _frame: &CapturedFrame,
    ) -> Result<InterfaceId, LiveIoError> {
        Ok(interface.clone())
    }

    fn transmit(
        &mut self,
        interface: &InterfaceId,
        _mode: LinkMode,
        frame: &CapturedFrame,
    ) -> Result<ReplayTransmission, LiveIoError> {
        Ok(ReplayTransmission {
            interface: interface.clone(),
            report: IoSendReport {
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
        CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![0, 1, 2, 3]).unwrap();
    let mut writer = CaptureWriter::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    writer.write_frame(&original).unwrap();
    let mut reader = CaptureReader::new(Cursor::new(writer.into_inner())).unwrap();
    let options = ReplayOptions {
        interface: InterfaceId {
            name: "injected0".to_owned(),
            index: 1,
        },
        link_mode: LinkMode::Auto,
        timing: ReplayTiming::Immediate,
        limits: ReplayLimits::default(),
    };
    let mut authorizer = Authorizer;
    let mut transmitter = Transmitter;
    let mut clock = Clock::default();
    let mut evidence = Vec::new();
    let summary = replay_capture(
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
