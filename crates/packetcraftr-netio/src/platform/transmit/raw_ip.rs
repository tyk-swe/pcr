// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    Error,
    transmit::{self, Layer3Frame},
};

use preparation::prepare;
#[cfg(target_os = "macos")]
use submission::validate_platform_support;
use submission::{map_raw_error, open, send};

mod preparation;
#[cfg(target_os = "linux")]
pub(in crate::platform) mod session;
mod submission;

pub(crate) fn send_layer3(frame: Layer3Frame<'_>) -> Result<transmit::Report, Error> {
    let packet = prepare(frame)?;
    #[cfg(target_os = "macos")]
    validate_platform_support(&packet)?;
    let socket = open(&packet).map_err(|error| map_raw_error(&packet.interface, error))?;
    submit(&socket, packet)
}

fn submit(
    socket: &socket2::Socket,
    packet: preparation::PreparedRawIp,
) -> Result<transmit::Report, Error> {
    let (actual, submission) =
        send(socket, &packet).map_err(|error| map_raw_error(&packet.interface, error))?;
    let expected = packet.submission.len();
    if actual != expected {
        return Err(Error::PartialSend { expected, actual });
    }
    Ok(submission.complete(packet.wire_bytes.len(), packet.wire_bytes))
}
