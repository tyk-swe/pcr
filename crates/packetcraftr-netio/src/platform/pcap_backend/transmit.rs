// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! libpcap Layer 2 frame transmission.

use std::sync::Arc;

use pcap::{Capture, Error as PcapError};

use super::capture::map_open_error;
use crate::{
    Error,
    interface::Id as InterfaceId,
    platform::live_capture::is_permission_denied,
    transmit::{self, Layer2Frame, Submission},
};

const READ_TIMEOUT_MILLIS: i32 = 50;

pub(in crate::platform) fn send_layer2(frame: Layer2Frame<'_>) -> Result<transmit::Report, Error> {
    let interface = &frame.route().plan.decision.interface;
    i32::try_from(frame.bytes().len()).map_err(|_| Error::InvalidTransmissionFrame {
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

fn map_send_error(interface: &InterfaceId, error: PcapError) -> Error {
    let message = error.to_string();
    let source: Option<crate::SystemFault> = Some(Arc::new(error));
    if is_permission_denied(&message) {
        return Error::Privilege {
            message: format!(
                "cannot inject on {} through libpcap; grant link-layer injection privileges",
                interface.name
            ),
            source,
        };
    }
    Error::Send {
        message: format!("libpcap injection on {} failed", interface.name),
        source,
    }
}
