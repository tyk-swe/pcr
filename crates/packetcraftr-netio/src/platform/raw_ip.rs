// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Target-native raw IP transmission after upstream authorization, route, MTU,
//! and capture-readiness checks.

#![cfg_attr(windows, allow(unsafe_code))]
#![cfg_attr(not(windows), forbid(unsafe_code))]

use super::super::{
    Error,
    transmit::{self, Layer3Frame, Submission},
};

use preparation::prepare;
#[cfg(target_os = "macos")]
use submission::validate_platform_support;
use submission::{map_raw_error, send};

mod preparation;
mod submission;

pub(super) fn send_layer3(frame: Layer3Frame<'_>) -> Result<transmit::Report, Error> {
    let packet = prepare(frame)?;
    #[cfg(target_os = "macos")]
    validate_platform_support(&packet)?;
    let submission = Submission::start();
    let actual = send(&packet).map_err(|error| map_raw_error(&packet.interface, error))?;
    let expected = packet.submission.len();
    if actual != expected {
        return Err(Error::PartialSend { expected, actual });
    }
    Ok(submission.complete(packet.wire_bytes.len(), packet.wire_bytes))
}
