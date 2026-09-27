// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Opening a libpcap handle, shared by the libpcap capture and transmit
//! backends.

use pcap::Error as PcapError;

use crate::{
    Error,
    interface::Id as InterfaceId,
    platform::common::pcap_api::{is_missing_device, is_permission_denied},
};
use packetcraftr_core::error::Source;

/// How long one blocking libpcap read waits before the handle checks for
/// interruption.
pub(in crate::platform) const READ_TIMEOUT_MILLIS: i32 = 50;

pub(in crate::platform) fn map_open_error(interface: &InterfaceId, error: PcapError) -> Error {
    let message = error.to_string();
    let source = Some(Source::new(error));
    if is_permission_denied(&message) {
        return Error::Privilege {
            message: format!(
                "cannot open {} through libpcap; grant capture privileges (for example CAP_NET_RAW on Linux or BPF access on macOS)",
                interface.name
            ),
            source,
        };
    }
    if is_missing_device(&message) {
        return Error::Device {
            interface: interface.name.clone(),
            message: "libpcap could not open this interface".to_owned(),
            source,
        };
    }
    Error::Capture {
        message: format!("could not open {} through libpcap", interface.name),
        source,
    }
}
