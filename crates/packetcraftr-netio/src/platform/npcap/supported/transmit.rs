// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Npcap Layer-2 transmission.

#![allow(unsafe_code)]

use super::{
    abi::SEND_SNAPSHOT_LENGTH,
    handles::{PromiscuousMode, open_handle},
};
use crate::{
    Error,
    platform::live_capture::is_permission_denied,
    transmit::{self, Layer2Frame, Submission},
};

pub(in crate::platform::npcap) fn send_layer2(
    frame: Layer2Frame<'_>,
) -> Result<transmit::Report, Error> {
    let interface = &frame.route().plan.decision.interface;
    let length = i32::try_from(frame.bytes().len()).map_err(|_| Error::Send {
        message: format!(
            "Layer 2 frame for {} exceeds Npcap's signed 32-bit send length",
            interface.name
        ),
        source: None,
    })?;
    let handle = open_handle(interface, SEND_SNAPSHOT_LENGTH, PromiscuousMode::Disabled)?;
    let submission = Submission::start();
    // SAFETY: the byte slice remains valid for the synchronous call and length
    // is its exact checked c_int representation.
    let result = unsafe {
        (handle.api.pcap_sendpacket)(handle.raw.as_ptr(), frame.bytes().as_ptr(), length)
    };
    if result != 0 {
        let message = handle.error_message();
        if is_permission_denied(&message) {
            return Err(Error::Privilege {
                message: format!(
                    "cannot inject on {} through Npcap: {message}; run with packet capture privileges",
                    interface.name
                ),
                source: None,
            });
        }
        return Err(Error::Send {
            message: format!(
                "Npcap injection on {} failed with status {result}: {message}",
                interface.name
            ),
            source: None,
        });
    }
    Ok(submission.complete(frame.bytes().len(), frame.bytes().clone()))
}
