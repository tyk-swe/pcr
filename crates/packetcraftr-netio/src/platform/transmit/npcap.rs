// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(
    unsafe_code,
    reason = "Npcap frame injection goes through the pcap_sendpacket FFI call"
)]

use crate::platform::common::npcap::{
    abi::SEND_SNAPSHOT_LENGTH,
    handles::{PromiscuousMode, open_handle},
};
use crate::{
    Error,
    capture::NativeSettings,
    platform::common::pcap_api::{Diagnostic, map_send_error},
    transmit::{self, Layer2Frame, Submission},
};

pub(crate) fn send_layer2(frame: Layer2Frame<'_>) -> Result<transmit::Report, Error> {
    let interface = &frame.route().decision.interface;
    let length = i32::try_from(frame.bytes().len()).map_err(|_| Error::Send {
        message: format!(
            "Layer 2 frame for {} exceeds Npcap's signed 32-bit send length",
            interface.name
        ),
        source: None,
    })?;
    let handle = open_handle(
        interface,
        SEND_SNAPSHOT_LENGTH,
        PromiscuousMode::Disabled,
        &NativeSettings::default(),
    )?;
    let submission = Submission::start();
    // SAFETY: the byte slice remains valid for the synchronous call and length is its exact size.
    let result = unsafe {
        (handle.api.pcap_sendpacket)(handle.raw.as_ptr(), frame.bytes().as_ptr(), length)
    };
    if result != 0 {
        let diagnostic = handle.error_message();
        let source = Diagnostic::new(Some(result), diagnostic.clone()).into_source();
        return Err(map_send_error(
            "Npcap",
            "run with packet capture privileges",
            interface,
            &diagnostic,
            source,
        ));
    }
    Ok(submission.complete(frame.bytes().len(), frame.bytes().clone()))
}
