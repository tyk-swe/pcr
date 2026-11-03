// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use pcap::{Capture, Error as PcapError};

use crate::{
    Error,
    interface::Id as InterfaceId,
    platform::common::READ_TIMEOUT_MILLIS,
    platform::common::libpcap::map_open_error,
    platform::common::pcap_api::is_permission_denied,
    transmit::{self, Layer2Frame, Submission},
};
use packetcraftr_core::error::Source;

pub(crate) fn send_layer2(frame: Layer2Frame<'_>) -> Result<transmit::Report, Error> {
    validate_length(frame)?;
    let mut capture = open(frame)?;
    submit(&mut capture, frame)
}

fn validate_length(frame: Layer2Frame<'_>) -> Result<(), Error> {
    i32::try_from(frame.bytes().len()).map_err(|_| Error::InvalidTransmissionFrame {
        message: format!(
            "Layer 2 frame length {} exceeds the libpcap signed-length limit",
            frame.bytes().len()
        ),
    })?;
    Ok(())
}

fn open(frame: Layer2Frame<'_>) -> Result<Capture<pcap::Active>, Error> {
    let interface = &frame.route().decision.interface;
    Capture::from_device(interface.name.as_str())
        .map_err(|error| map_open_error(interface, error))?
        .promisc(false)
        .timeout(READ_TIMEOUT_MILLIS)
        .immediate_mode(true)
        .open()
        .map_err(|error| map_open_error(interface, error))
}

fn submit(
    capture: &mut Capture<pcap::Active>,
    frame: Layer2Frame<'_>,
) -> Result<transmit::Report, Error> {
    let interface = &frame.route().decision.interface;
    let submission = Submission::start();
    capture
        .sendpacket(frame.bytes().as_ref())
        .map_err(|error| map_send_error(interface, error))?;
    Ok(submission.complete(frame.bytes().len(), frame.bytes().clone()))
}

#[cfg(target_os = "linux")]
mod session;

#[cfg(target_os = "linux")]
pub(crate) fn session_backend() -> session::Backend {
    session::Backend::new()
}

fn map_send_error(interface: &InterfaceId, error: PcapError) -> Error {
    let message = error.to_string();
    let source = Some(Source::new(error));
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
