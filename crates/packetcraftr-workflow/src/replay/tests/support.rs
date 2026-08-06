// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::io::Cursor;
use std::result::Result;
use std::time::{Duration, UNIX_EPOCH};

use super::super::model::{
    ReplayAuthorizationContext, ReplayAuthorizer, ReplayLimits, ReplayOptions, ReplayTiming,
    ReplayTransmission, ReplayTransmitter,
};
use crate::BoundaryError;
use crate::clock::Clock as WorkflowClock;
use packetcraftr_capture::{Frame, LinkType, Reader, Writer};
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_net::{
    Error as LiveIoError, link::LinkMode, route::InterfaceId, transmit::IoSendReport,
};

#[derive(Default)]
pub(super) struct ConfigurableRecordingAuthorizer {
    pub(super) authorization_calls: usize,
    pub(super) contexts: Vec<ReplayAuthorizationContext>,
    pub(super) deny_authorization: bool,
}

impl ReplayAuthorizer for ConfigurableRecordingAuthorizer {
    fn authorize_operation(
        &mut self,
        context: ReplayAuthorizationContext,
        _frame: &Frame,
        _mode: LinkMode,
    ) -> Result<(), BoundaryError> {
        self.authorization_calls += 1;
        self.contexts.push(context);
        if self.deny_authorization {
            Err(BoundaryError::new(
                "denied by test policy",
                Classification::new("policy.test", Kind::Policy, None),
                Vec::new(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
pub(super) struct ConfigurableRecordingTransmitter {
    pub(super) validation_calls: usize,
    pub(super) transmission_calls: usize,
    pub(super) validation_delay: Duration,
    pub(super) transmission_delay: Duration,
    pub(super) return_partial_send: bool,
    pub(super) report_different_interface: bool,
}

impl ReplayTransmitter for ConfigurableRecordingTransmitter {
    fn validate_interface(
        &mut self,
        interface: &InterfaceId,
        _mode: LinkMode,
        _frame: &Frame,
    ) -> Result<InterfaceId, LiveIoError> {
        self.validation_calls += 1;
        if !self.validation_delay.is_zero() {
            std::thread::sleep(self.validation_delay);
        }
        Ok(interface.clone())
    }

    fn transmit(
        &mut self,
        _interface: &InterfaceId,
        _mode: LinkMode,
        frame: &Frame,
    ) -> Result<ReplayTransmission, LiveIoError> {
        self.transmission_calls += 1;
        if !self.transmission_delay.is_zero() {
            std::thread::sleep(self.transmission_delay);
        }
        Ok(ReplayTransmission {
            interface: if self.report_different_interface {
                InterfaceId {
                    name: "other0".to_owned(),
                    index: _interface.index + 1,
                }
            } else {
                _interface.clone()
            },
            report: IoSendReport {
                bytes_sent: if self.return_partial_send {
                    frame.bytes().len().saturating_sub(1)
                } else {
                    frame.bytes().len()
                },
                wire_bytes: frame.bytes().clone(),
            },
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingClock {
    pub(super) delays: Vec<Duration>,
}

impl WorkflowClock for RecordingClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.delays.push(delay);
        Ok(())
    }
}

pub(super) fn test_interface() -> InterfaceId {
    InterfaceId {
        name: "test0".to_owned(),
        index: 7,
    }
}

pub(super) fn capture_reader(
    link_type: LinkType,
    frames: &[(Duration, &[u8])],
) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), link_type).unwrap();
    for (timestamp, bytes) in frames {
        writer
            .write_frame(&Frame::new(UNIX_EPOCH + *timestamp, link_type, bytes.to_vec()).unwrap())
            .unwrap();
    }
    Reader::new(Cursor::new(writer.into_inner())).unwrap()
}

pub(super) fn replay_options(timing: ReplayTiming) -> ReplayOptions {
    ReplayOptions {
        interface: test_interface(),
        link_mode: LinkMode::Auto,
        timing,
        limits: ReplayLimits::default(),
    }
}
