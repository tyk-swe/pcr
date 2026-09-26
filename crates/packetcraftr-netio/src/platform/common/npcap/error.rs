// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::{c_char, c_int};

use super::abi::{
    PCAP_ERROR_BUFFER_SIZE, PCAP_ERROR_CAPTURE_NOTSUP, PCAP_ERROR_IFACE_NOT_UP,
    PCAP_ERROR_NO_SUCH_DEVICE, PCAP_ERROR_PERM_DENIED, PCAP_ERROR_PROMISC_PERM_DENIED,
    PCAP_ERROR_RFMON_NOTSUP, PCAP_WARNING_PROMISC_NOTSUP,
};
use crate::{
    Error, NativeCapability, Unsupported,
    interface::Id as InterfaceId,
    platform::common::pcap_api::{Diagnostic, is_missing_device, is_permission_denied},
};
use packetcraftr_core::error::Source;

/// Classifies a rejected activation by its status; the status and Npcap's
/// diagnostic stay the failure's source.
pub(in crate::platform) fn map_activation_error(
    interface: &InterfaceId,
    status: c_int,
    diagnostic: String,
) -> Error {
    let source = Diagnostic::new(Some(status), diagnostic).into_source();
    match status {
        PCAP_WARNING_PROMISC_NOTSUP => Unsupported {
            capability: NativeCapability::Capture,
            message: format!(
                "Npcap does not support requested promiscuous capture on {}",
                interface.name
            ),
            source,
        }
        .into(),
        PCAP_ERROR_PERM_DENIED | PCAP_ERROR_PROMISC_PERM_DENIED => Error::Privilege {
            message: format!(
                "cannot open {} through Npcap; grant capture privileges or run elevated",
                interface.name
            ),
            source,
        },
        PCAP_ERROR_NO_SUCH_DEVICE | PCAP_ERROR_IFACE_NOT_UP => Error::Device {
            interface: interface.name.clone(),
            message: "Npcap activation failed".to_owned(),
            source,
        },
        PCAP_ERROR_RFMON_NOTSUP | PCAP_ERROR_CAPTURE_NOTSUP => Unsupported {
            capability: NativeCapability::Capture,
            message: format!("Npcap does not support capture on {}", interface.name),
            source,
        }
        .into(),
        _ => Error::Capture {
            message: format!("Npcap activation failed for {}", interface.name),
            source,
        },
    }
}

/// Classifies a failed `pcap_create` by its diagnostic, the only thing it
/// reports; the diagnostic stays the failure's source.
pub(in crate::platform) fn map_open_message(interface: &InterfaceId, diagnostic: String) -> Error {
    let privilege = is_permission_denied(&diagnostic);
    let missing = is_missing_device(&diagnostic);
    let source = Diagnostic::new(None, diagnostic).into_source();
    if privilege {
        return Error::Privilege {
            message: format!(
                "cannot open {} through Npcap; grant capture privileges or run elevated",
                interface.name
            ),
            source,
        };
    }
    if missing {
        return Error::Device {
            interface: interface.name.clone(),
            message: "Npcap could not open this interface".to_owned(),
            source,
        };
    }
    Error::Capture {
        message: format!("could not open {} through Npcap", interface.name),
        source,
    }
}

pub(in crate::platform) fn interface_conversion_error(
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
        source: Some(Source::new(std::io::Error::from_raw_os_error(
            code.cast_signed(),
        ))),
    }
}

pub(in crate::platform) fn error_buffer_message(
    buffer: &[c_char; PCAP_ERROR_BUFFER_SIZE],
) -> String {
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
