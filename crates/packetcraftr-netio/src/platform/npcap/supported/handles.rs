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
    abi::{PCAP_ERROR_BUFFER_SIZE, PcapSetInteger, READ_TIMEOUT_MILLIS},
    error::{error_buffer_message, map_activation_error, map_open_message},
    loader::{NpcapApi, npcap_api, npcap_device_name},
};
use crate::{Error as LiveIoError, route::InterfaceId};

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

pub(super) fn open_handle(
    interface: &InterfaceId,
    snap_length: c_int,
    promiscuous_mode: PromiscuousMode,
) -> Result<Arc<NpcapHandle>, LiveIoError> {
    let api = npcap_api()?;
    let device_name = npcap_device_name(interface)?;
    let device_name = CString::new(device_name).map_err(|_| LiveIoError::Device {
        interface: interface.name.clone(),
        message: "Npcap device name contains an embedded NUL byte".to_owned(),
    })?;
    let mut error_buffer = [0 as c_char; PCAP_ERROR_BUFFER_SIZE];
    // SAFETY: both C strings are valid for this synchronous call and the
    // returned pointer is checked before ownership begins.
    let raw = unsafe { (api.pcap_create)(device_name.as_ptr(), error_buffer.as_mut_ptr()) };
    let raw = NonNull::new(raw)
        .ok_or_else(|| map_open_message(interface, error_buffer_message(&error_buffer)))?;
    let handle = Arc::new(NpcapHandle { api, raw });

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
    // SAFETY: all pre-activation options are complete and this handle has not
    // previously been activated.
    let activation = unsafe { (handle.api.pcap_activate)(handle.raw.as_ptr()) };
    if activation < 0 {
        return Err(map_activation_error(
            interface,
            activation,
            handle.error_message(),
        ));
    }
    Ok(handle)
}

fn set_integer_option(
    handle: &NpcapHandle,
    interface: &InterfaceId,
    operation: &'static str,
    function: PcapSetInteger,
    value: c_int,
) -> Result<(), LiveIoError> {
    // SAFETY: every supplied function is a pcap_set_* operation with this exact
    // ABI and the handle has not yet been activated.
    let result = unsafe { function(handle.raw.as_ptr(), value) };
    if result == 0 {
        Ok(())
    } else {
        Err(LiveIoError::Capture {
            message: format!(
                "{operation} failed for {} with status {result}: {}",
                interface.name,
                handle.error_message()
            ),
        })
    }
}
