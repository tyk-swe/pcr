// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use pcap::Error as PcapError;

use crate::{
    Error,
    interface::Id as InterfaceId,
    platform::common::pcap_api::{is_missing_device, is_permission_denied},
};
use packetcraftr_core::error::Source;

enum Failure {
    Privilege,
    MissingDevice,
    Other,
}

fn classify(message: &str) -> Failure {
    if is_permission_denied(message) {
        Failure::Privilege
    } else if is_missing_device(message) {
        Failure::MissingDevice
    } else {
        Failure::Other
    }
}

pub(in crate::platform) fn map_open_error(interface: &InterfaceId, error: PcapError) -> Error {
    let failure = classify(&error.to_string());
    let source = Some(Source::new(error));
    match failure {
        Failure::Privilege => Error::Privilege {
            message: format!(
                "cannot open {} through libpcap; grant capture privileges (for example CAP_NET_RAW on Linux or BPF access on macOS)",
                interface.name
            ),
            source,
        },
        Failure::MissingDevice => Error::Device {
            interface: interface.name.clone(),
            message: "libpcap could not open this interface".to_owned(),
            source,
        },
        Failure::Other => Error::Capture {
            message: format!("could not open {} through libpcap", interface.name),
            source,
        },
    }
}

pub(in crate::platform) fn map_send_error(interface: &InterfaceId, error: PcapError) -> Error {
    let failure = classify(&error.to_string());
    let source = Some(Source::new(error));
    match failure {
        Failure::Privilege => Error::Privilege {
            message: format!(
                "cannot inject on {} through libpcap; grant link-layer injection privileges",
                interface.name
            ),
            source,
        },
        Failure::MissingDevice | Failure::Other => Error::Send {
            message: format!("libpcap injection on {} failed", interface.name),
            source,
        },
    }
}
