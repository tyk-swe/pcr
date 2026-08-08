// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Target-native raw IPv4/IPv6 transmission.
//!
//! This is the platform I/O boundary only: it emits bytes a caller has already
//! built and authorized. Destination authorization, route consistency, MTU,
//! and capture readiness are enforced upstream by the client policy layer, and
//! this module is reached only after those checks pass.

#![cfg_attr(windows, allow(unsafe_code))]
#![cfg_attr(not(windows), forbid(unsafe_code))]

use super::super::{
    Error as LiveIoError,
    transmit::{IoSendReport, Layer3Frame},
};

use preparation::prepare;
use submission::{map_raw_error, send, validate_platform_support};

mod preparation;
mod submission;

pub(super) fn send_layer3(frame: Layer3Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    let packet = prepare(frame)?;
    validate_platform_support(&packet)?;
    let actual = send(&packet).map_err(|error| map_raw_error(&packet.interface, error))?;
    let expected = packet.submission.len();
    if actual != expected {
        return Err(LiveIoError::PartialSend { expected, actual });
    }
    Ok(IoSendReport {
        bytes_sent: packet.wire_bytes.len(),
        wire_bytes: packet.wire_bytes,
    })
}
