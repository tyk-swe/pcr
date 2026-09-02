// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable Npcap error classification and diagnostics.

use std::ffi::{c_char, c_int};
use std::sync::Arc;

use super::abi::{
    PCAP_ERROR_BUFFER_SIZE, PCAP_ERROR_CAPTURE_NOTSUP, PCAP_ERROR_IFACE_NOT_UP,
    PCAP_ERROR_NO_SUCH_DEVICE, PCAP_ERROR_PERM_DENIED, PCAP_ERROR_PROMISC_PERM_DENIED,
    PCAP_ERROR_RFMON_NOTSUP, PCAP_WARNING_PROMISC_NOTSUP,
};
use crate::{
    Error,
    interface::Id as InterfaceId,
    platform::pcap_common::{is_missing_device, is_permission_denied},
};

pub(super) fn map_activation_error(
    interface: &InterfaceId,
    status: c_int,
    message: String,
) -> Error {
    match status {
        PCAP_WARNING_PROMISC_NOTSUP => Error::Unsupported {
            message: format!(
                "Npcap does not support requested promiscuous capture on {}: {message}",
                interface.name
            ),
            source: None,
        },
        PCAP_ERROR_PERM_DENIED | PCAP_ERROR_PROMISC_PERM_DENIED => Error::Privilege {
            message: format!(
                "cannot open {} through Npcap: {message}; grant capture privileges or run elevated",
                interface.name
            ),
            source: None,
        },
        PCAP_ERROR_NO_SUCH_DEVICE | PCAP_ERROR_IFACE_NOT_UP => Error::Device {
            interface: interface.name.clone(),
            message: format!("Npcap activation failed with status {status}: {message}"),
            source: None,
        },
        PCAP_ERROR_RFMON_NOTSUP | PCAP_ERROR_CAPTURE_NOTSUP => Error::Unsupported {
            message: format!(
                "Npcap does not support capture on {} (status {status}): {message}",
                interface.name
            ),
            source: None,
        },
        _ => Error::Capture {
            message: format!(
                "Npcap activation failed for {} with status {status}: {message}",
                interface.name
            ),
            source: None,
        },
    }
}

pub(super) fn map_open_message(interface: &InterfaceId, message: String) -> Error {
    if is_permission_denied(&message) {
        return Error::Privilege {
            message: format!(
                "cannot open {} through Npcap: {message}; grant capture privileges or run elevated",
                interface.name
            ),
            source: None,
        };
    }
    if is_missing_device(&message) {
        return Error::Device {
            interface: interface.name.clone(),
            message: format!("Npcap could not open this interface: {message}"),
            source: None,
        };
    }
    Error::Capture {
        message: format!("could not open {} through Npcap: {message}", interface.name),
        source: None,
    }
}

pub(super) fn interface_conversion_error(
    interface: &InterfaceId,
    operation: &'static str,
    code: u32,
) -> Error {
    Error::Device {
        interface: interface.name.clone(),
        message: format!(
            "{operation} rejected interface index {} (Win32 error {code})",
            interface.index
        ),
        source: Some(Arc::new(std::io::Error::from_raw_os_error(
            code.cast_signed(),
        ))),
    }
}

pub(super) fn error_buffer_message(buffer: &[c_char; PCAP_ERROR_BUFFER_SIZE]) -> String {
    // Bound decoding to `PCAP_ERRBUF_SIZE` if the runtime omits NUL termination.
    let bytes: Vec<u8> = buffer
        .iter()
        .copied()
        .take_while(|character| *character != 0)
        .map(i8::cast_unsigned)
        .collect();
    let message = String::from_utf8_lossy(&bytes).into_owned();
    if message.is_empty() {
        "Npcap returned no diagnostic".to_owned()
    } else {
        message
    }
}
