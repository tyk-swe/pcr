// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Npcap Layer-2 transmission.

#![allow(unsafe_code)]

use super::{
    abi::SEND_SNAPSHOT_LENGTH,
    error::is_permission_message,
    handles::{PromiscuousMode, open_handle},
};
use crate::{
    Error as LiveIoError,
    transmit::{IoSendReport, Layer2Frame, Submission},
};

pub(super) fn send_layer2(frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    let interface = &frame.route().plan.route.interface;
    let length = i32::try_from(frame.bytes().len()).map_err(|_| LiveIoError::Send {
        message: format!(
            "Layer 2 frame for {} exceeds Npcap's signed 32-bit send length",
            interface.name
        ),
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
        let lower = message.to_ascii_lowercase();
        if is_permission_message(&lower) {
            return Err(LiveIoError::Privilege {
                message: format!(
                    "cannot inject on {} through Npcap: {message}; run with packet capture privileges",
                    interface.name
                ),
            });
        }
        return Err(LiveIoError::Send {
            message: format!(
                "Npcap injection on {} failed with status {result}: {message}",
                interface.name
            ),
        });
    }
    Ok(submission.complete(frame.bytes().len(), frame.bytes().clone()))
}
