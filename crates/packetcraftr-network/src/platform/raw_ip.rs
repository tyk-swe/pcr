// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Target-native raw IP transmission after upstream authorization, route, MTU,
//! and capture-readiness checks.

#![cfg_attr(windows, allow(unsafe_code))]
#![cfg_attr(not(windows), forbid(unsafe_code))]

use super::super::{
    Error as LiveIoError,
    transmit::{IoSendReport, Layer3Frame},
};
use std::time::{Instant, SystemTime};

use preparation::prepare;
use submission::{map_raw_error, send, validate_platform_support};

mod preparation;
mod submission;

pub(super) fn send_layer3(frame: Layer3Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    let packet = prepare(frame)?;
    validate_platform_support(&packet)?;
    let started = Instant::now();
    let wall_started = SystemTime::now();
    let actual = send(&packet).map_err(|error| map_raw_error(&packet.interface, error))?;
    let finished = Instant::now();
    let wall_finished = SystemTime::now();
    let expected = packet.submission.len();
    if actual != expected {
        return Err(LiveIoError::PartialSend { expected, actual });
    }
    Ok(IoSendReport::accepted(
        packet.wire_bytes,
        crate::transmit::TimingEvidence::submission_interval(
            started,
            finished,
            Some(wall_started),
            Some(wall_finished),
        ),
    ))
}
