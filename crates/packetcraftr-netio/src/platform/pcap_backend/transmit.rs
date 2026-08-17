// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! libpcap Layer 2 frame transmission.

#![allow(unsafe_code)]

use pcap::{Capture, Error as PcapError};

use super::capture::map_open_error;
use crate::{
    Error as LiveIoError,
    interface::Id as InterfaceId,
    transmit::{IoSendReport, Layer2Frame, Submission},
};

const READ_TIMEOUT_MILLIS: i32 = 50;

pub(crate) fn send_layer2(frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    let interface = &frame.route().plan.decision.interface;
    i32::try_from(frame.bytes().len()).map_err(|_| LiveIoError::InvalidTransmissionFrame {
        message: format!(
            "Layer 2 frame length {} exceeds the libpcap signed-length limit",
            frame.bytes().len()
        ),
    })?;
    let mut capture = Capture::from_device(interface.name.as_str())
        .map_err(|error| map_open_error(interface, error))?
        .promisc(false)
        .timeout(READ_TIMEOUT_MILLIS)
        .immediate_mode(true)
        .open()
        .map_err(|error| map_open_error(interface, error))?;
    let submission = Submission::start();
    capture
        .sendpacket(frame.bytes().as_ref())
        .map_err(|error| map_send_error(interface, error))?;
    Ok(submission.complete(frame.bytes().len(), frame.bytes().clone()))
}

pub(super) fn map_send_error(interface: &InterfaceId, error: PcapError) -> LiveIoError {
    let message = error.to_string();
    let lower = message.to_ascii_lowercase();
    if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("access is denied")
    {
        return LiveIoError::Privilege {
            message: format!(
                "cannot inject on {} through libpcap: {message}; grant link-layer injection privileges",
                interface.name
            ),
        };
    }
    LiveIoError::Send {
        message: format!("libpcap injection on {} failed: {message}", interface.name),
    }
}
