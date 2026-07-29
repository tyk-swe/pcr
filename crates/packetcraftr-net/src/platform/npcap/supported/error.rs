// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable Npcap error classification and diagnostics.

#![forbid(unsafe_code)]

use std::ffi::{c_char, c_int};

use super::abi::{
    PCAP_ERROR_BUFFER_SIZE, PCAP_ERROR_CAPTURE_NOTSUP, PCAP_ERROR_IFACE_NOT_UP,
    PCAP_ERROR_NO_SUCH_DEVICE, PCAP_ERROR_PERM_DENIED, PCAP_ERROR_PROMISC_PERM_DENIED,
    PCAP_ERROR_RFMON_NOTSUP,
};
use crate::{Error as LiveIoError, route::InterfaceId};

pub(super) fn map_activation_error(
    interface: &InterfaceId,
    status: c_int,
    message: String,
) -> LiveIoError {
    match status {
        PCAP_ERROR_PERM_DENIED | PCAP_ERROR_PROMISC_PERM_DENIED => LiveIoError::Privilege {
            message: format!(
                "cannot open {} through Npcap: {message}; grant capture privileges or run elevated",
                interface.name
            ),
        },
        PCAP_ERROR_NO_SUCH_DEVICE | PCAP_ERROR_IFACE_NOT_UP => LiveIoError::Device {
            interface: interface.name.clone(),
            message: format!("Npcap activation failed with status {status}: {message}"),
        },
        PCAP_ERROR_RFMON_NOTSUP | PCAP_ERROR_CAPTURE_NOTSUP => LiveIoError::Unsupported {
            message: format!(
                "Npcap does not support capture on {} (status {status}): {message}",
                interface.name
            ),
        },
        _ => LiveIoError::Capture {
            message: format!(
                "Npcap activation failed for {} with status {status}: {message}",
                interface.name
            ),
        },
    }
}

pub(super) fn map_open_message(interface: &InterfaceId, message: String) -> LiveIoError {
    let lower = message.to_ascii_lowercase();
    if is_permission_message(&lower) {
        return LiveIoError::Privilege {
            message: format!(
                "cannot open {} through Npcap: {message}; grant capture privileges or run elevated",
                interface.name
            ),
        };
    }
    if lower.contains("no such device")
        || lower.contains("not found")
        || lower.contains("does not exist")
    {
        return LiveIoError::Device {
            interface: interface.name.clone(),
            message: format!("Npcap could not open this interface: {message}"),
        };
    }
    LiveIoError::Capture {
        message: format!("could not open {} through Npcap: {message}", interface.name),
    }
}

pub(super) fn is_permission_message(message: &str) -> bool {
    message.contains("permission denied")
        || message.contains("access is denied")
        || message.contains("not permitted")
        || message.contains("administrator")
}

pub(super) fn interface_conversion_error(
    interface: &InterfaceId,
    operation: &'static str,
    code: u32,
) -> LiveIoError {
    LiveIoError::Device {
        interface: interface.name.clone(),
        message: format!(
            "{operation} rejected interface index {}: {} (Win32 error {code})",
            interface.index,
            std::io::Error::from_raw_os_error(code.cast_signed())
        ),
    }
}

pub(super) fn error_buffer_message(buffer: &[c_char; PCAP_ERROR_BUFFER_SIZE]) -> String {
    // Decode only within PCAP_ERRBUF_SIZE even if an incompatible runtime
    // fails to terminate its diagnostic.
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

#[cfg(test)]
mod tests {
    use super::map_activation_error;
    use crate::{Error as LiveIoError, route::InterfaceId};

    use super::super::abi::{
        PCAP_ERROR_CAPTURE_NOTSUP, PCAP_ERROR_NO_SUCH_DEVICE, PCAP_ERROR_PERM_DENIED,
    };

    #[test]
    fn activation_errors_preserve_actionable_categories() {
        let interface = InterfaceId {
            name: "Ethernet".to_owned(),
            index: 7,
        };
        assert!(matches!(
            map_activation_error(&interface, PCAP_ERROR_PERM_DENIED, "denied".to_owned()),
            LiveIoError::Privilege { .. }
        ));
        assert!(matches!(
            map_activation_error(&interface, PCAP_ERROR_NO_SUCH_DEVICE, "missing".to_owned()),
            LiveIoError::Device { .. }
        ));
        assert!(matches!(
            map_activation_error(
                &interface,
                PCAP_ERROR_CAPTURE_NOTSUP,
                "unsupported".to_owned()
            ),
            LiveIoError::Unsupported { .. }
        ));
    }
}
