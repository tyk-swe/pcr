// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::platform::common::npcap::{
    abi::SEND_SNAPSHOT_LENGTH,
    handles::{PromiscuousMode, open_handle},
};
use crate::{
    Error,
    capture::NativeSettings,
    platform::common::pcap_api::{Diagnostic, map_send_error, validate_layer2_length},
    transmit::{self, Layer2Frame, Submission},
};

pub(crate) fn send_layer2(frame: Layer2Frame<'_>) -> Result<transmit::Report, Error> {
    let interface = &frame.route().decision.interface;
    let length = validate_layer2_length("Npcap", frame.bytes().len())?;
    let mut handle = open_handle(
        interface,
        SEND_SNAPSHOT_LENGTH,
        PromiscuousMode::Disabled,
        &NativeSettings::default(),
    )?;
    let submission = Submission::start();
    let result = handle.sendpacket(frame.bytes().as_ref(), length);
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
