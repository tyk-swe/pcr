// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Activated Npcap handle ownership and configuration.

#![allow(unsafe_code)]

use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    ptr::NonNull,
    sync::Arc,
};

use super::{
    abi::{
        PCAP_ERROR_BUFFER_SIZE, PCAP_WARNING_PROMISC_NOTSUP, PcapSetInteger, READ_TIMEOUT_MILLIS,
    },
    error::{error_buffer_message, map_activation_error, map_open_message},
    loader::{NpcapApi, npcap_api, npcap_device_name},
};
use crate::{
    Error,
    capture::NativeSettings,
    interface::Id as InterfaceId,
    platform::layer2::pcap_common::{
        check_setting_status, timestamp_precision_value, timestamp_source_value,
    },
};

#[derive(Clone, Copy)]
pub(super) enum PromiscuousMode {
    Disabled,
    Enabled,
}

impl PromiscuousMode {
    const fn pcap_value(self) -> c_int {
        match self {
            Self::Disabled => 0,
            Self::Enabled => 1,
        }
    }
}

pub(super) struct NpcapHandle {
    pub(super) api: Arc<NpcapApi>,
    pub(super) raw: NonNull<c_void>,
}

// SAFETY: a handle is read only by its owning capture worker. The only
// concurrent operation is pcap_breakloop, which libpcap explicitly allows
// from another thread. Session shutdown joins the worker before the final Arc
// is dropped, so pcap_close never races an active handle operation.
unsafe impl Send for NpcapHandle {}
// SAFETY: see the Send invariant above; shared access is limited to the
// documented pcap_breakloop interrupt path.
unsafe impl Sync for NpcapHandle {}

impl NpcapHandle {
    pub(super) fn error_message(&self) -> String {
        // SAFETY: the handle remains live through self's Arc owner and the
        // function pointer belongs to the equally live API module.
        let message = unsafe { (self.api.pcap_geterr)(self.raw.as_ptr()) };
        if message.is_null() {
            return "Npcap returned no diagnostic".to_owned();
        }
        // SAFETY: pcap_geterr returns a NUL-terminated string owned by the live
        // handle; it is copied before any subsequent handle call.
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for NpcapHandle {
    fn drop(&mut self) {
        // SAFETY: this is the last Arc owner, capture work has already joined,
        // and pcap_close consumes exactly this live handle once.
        unsafe { (self.api.pcap_close)(self.raw.as_ptr()) };
    }
}

/// Creates an unactivated handle for interface metadata queries; the `Drop`
/// impl releases it through `pcap_close` like an activated one.
pub(super) fn create_handle(interface: &InterfaceId) -> Result<Arc<NpcapHandle>, Error> {
    let api = npcap_api()?;
    let device_name = npcap_device_name(interface)?;
    let device_name = CString::new(device_name).map_err(|_| Error::Device {
        interface: interface.name.clone(),
        message: "Npcap device name contains an embedded NUL byte".to_owned(),
        source: None,
    })?;
    let mut error_buffer = [0 as c_char; PCAP_ERROR_BUFFER_SIZE];
    // SAFETY: both C strings are valid for this synchronous call and the
    // returned pointer is checked before ownership begins.
    let raw = unsafe { (api.pcap_create)(device_name.as_ptr(), error_buffer.as_mut_ptr()) };
    let raw = NonNull::new(raw)
        .ok_or_else(|| map_open_message(interface, error_buffer_message(&error_buffer)))?;
    Ok(Arc::new(NpcapHandle { api, raw }))
}

pub(super) fn open_handle(
    interface: &InterfaceId,
    snap_length: c_int,
    promiscuous_mode: PromiscuousMode,
    native: &NativeSettings,
) -> Result<Arc<NpcapHandle>, Error> {
    let handle = create_handle(interface)?;

    set_integer_option(
        &handle,
        interface,
        "pcap_set_snaplen",
        handle.api.pcap_set_snaplen,
        snap_length,
    )?;
    set_integer_option(
        &handle,
        interface,
        "pcap_set_promisc",
        handle.api.pcap_set_promisc,
        promiscuous_mode.pcap_value(),
    )?;
    set_integer_option(
        &handle,
        interface,
        "pcap_set_timeout",
        handle.api.pcap_set_timeout,
        READ_TIMEOUT_MILLIS,
    )?;
    set_integer_option(
        &handle,
        interface,
        "pcap_set_immediate_mode",
        handle.api.pcap_set_immediate_mode,
        1,
    )?;
    if let Some(buffer_size) = native.buffer_size {
        let size = c_int::try_from(buffer_size).map_err(|_| Error::InvalidCaptureSetting {
            field: "buffer_size",
            message: format!(
                "exceeds the native maximum of {} bytes",
                crate::capture::MAX_NATIVE_BUFFER_SIZE
            ),
        })?;
        set_native_option(
            &handle,
            interface,
            "pcap_set_buffer_size",
            "buffer_size",
            &buffer_size.to_string(),
            handle.api.pcap_set_buffer_size,
            size,
        )?;
    }
    if let Some(source) = native.timestamp_source {
        set_native_option(
            &handle,
            interface,
            "pcap_set_tstamp_type",
            "timestamp_source",
            source.as_str(),
            handle.api.pcap_set_tstamp_type,
            timestamp_source_value(source),
        )?;
    }
    if let Some(precision) = native.timestamp_precision {
        set_native_option(
            &handle,
            interface,
            "pcap_set_tstamp_precision",
            "timestamp_precision",
            precision.as_str(),
            handle.api.pcap_set_tstamp_precision,
            timestamp_precision_value(precision),
        )?;
    }
    // SAFETY: all pre-activation options are complete and this handle has not
    // previously been activated.
    let activation = unsafe { (handle.api.pcap_activate)(handle.raw.as_ptr()) };
    if activation_rejected(activation, promiscuous_mode) {
        return Err(map_activation_error(
            interface,
            activation,
            handle.error_message(),
        ));
    }
    Ok(handle)
}

fn activation_rejected(status: c_int, promiscuous_mode: PromiscuousMode) -> bool {
    status < 0
        || status == PCAP_WARNING_PROMISC_NOTSUP
            && matches!(promiscuous_mode, PromiscuousMode::Enabled)
}

fn set_integer_option(
    handle: &NpcapHandle,
    interface: &InterfaceId,
    operation: &'static str,
    function: PcapSetInteger,
    value: c_int,
) -> Result<(), Error> {
    // SAFETY: every supplied function is a pcap_set_* operation with this exact
    // ABI and the handle has not yet been activated.
    let result = unsafe { function(handle.raw.as_ptr(), value) };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::Capture {
            message: format!(
                "{operation} failed for {} with status {result}: {}",
                interface.name,
                handle.error_message()
            ),
            source: None,
        })
    }
}

/// An optional configuration export: a runtime without the symbol rejects the
/// explicit request typed, and a loaded symbol's status is classified the same
/// way the libpcap backend classifies it.
fn set_native_option(
    handle: &NpcapHandle,
    interface: &InterfaceId,
    operation: &'static str,
    setting: &'static str,
    requested: &str,
    function: Option<PcapSetInteger>,
    value: c_int,
) -> Result<(), Error> {
    let Some(function) = function else {
        return Err(Error::UnsupportedCaptureSetting {
            setting,
            interface: interface.name.clone(),
            message: format!("the loaded Npcap runtime does not export {operation}").into(),
        });
    };
    // SAFETY: function is a pcap_set_* operation with this exact ABI and the
    // handle has not yet been activated.
    let status = unsafe { function(handle.raw.as_ptr(), value) };
    check_setting_status(
        "Npcap",
        interface,
        operation,
        setting,
        requested,
        status,
        &handle.error_message(),
    )
}

/// The timestamp precision an activated handle delivers, when the runtime can
/// report one.
pub(super) fn reported_precision(handle: &NpcapHandle) -> Option<c_int> {
    // SAFETY: handle is activated and live; pcap_get_tstamp_precision only
    // reads the negotiated precision.
    handle
        .api
        .pcap_get_tstamp_precision
        .map(|function| unsafe { function(handle.raw.as_ptr()) })
        .filter(|value| *value >= 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promiscuous_warning_is_rejected_only_when_requested() {
        assert!(activation_rejected(-1, PromiscuousMode::Disabled));
        assert!(!activation_rejected(0, PromiscuousMode::Enabled));
        assert!(!activation_rejected(
            PCAP_WARNING_PROMISC_NOTSUP,
            PromiscuousMode::Disabled
        ));
        assert!(activation_rejected(
            PCAP_WARNING_PROMISC_NOTSUP,
            PromiscuousMode::Enabled
        ));
    }
}
