// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::{CStr, c_char, c_int, c_void};

use pcap::Error as PcapError;

use crate::{
    Error,
    interface::Id as InterfaceId,
    platform::common::pcap_api::{self, BpfProgram},
};
use packetcraftr_core::error::Source;

// The pcap crate omits BPF/option status codes and timestamp queries, so these bind libpcap directly.
#[link(name = "pcap")]
#[expect(unsafe_code, reason = "declares libpcap C FFI symbols")]
unsafe extern "C" {
    pub(in crate::platform) fn pcap_snapshot(handle: *mut c_void) -> c_int;
    pub(in crate::platform) fn pcap_set_buffer_size(handle: *mut c_void, size: c_int) -> c_int;
    pub(in crate::platform) fn pcap_set_tstamp_type(handle: *mut c_void, ttype: c_int) -> c_int;
    pub(in crate::platform) fn pcap_set_tstamp_precision(
        handle: *mut c_void,
        precision: c_int,
    ) -> c_int;
    pub(in crate::platform) fn pcap_get_tstamp_precision(handle: *mut c_void) -> c_int;
    pub(in crate::platform) fn pcap_list_tstamp_types(
        handle: *mut c_void,
        types: *mut *mut c_int,
    ) -> c_int;
    pub(in crate::platform) fn pcap_free_tstamp_types(types: *mut c_int);
    pub(in crate::platform) fn pcap_tstamp_type_val_to_name(ttype: c_int) -> *const c_char;
    pub(in crate::platform) fn pcap_tstamp_type_val_to_description(ttype: c_int) -> *const c_char;
    pub(in crate::platform) fn pcap_compile(
        handle: *mut c_void,
        program: *mut BpfProgram,
        source: *const c_char,
        optimize: c_int,
        netmask: u32,
    ) -> c_int;
    pub(in crate::platform) fn pcap_setfilter(
        handle: *mut c_void,
        program: *mut BpfProgram,
    ) -> c_int;
    pub(in crate::platform) fn pcap_freecode(program: *mut BpfProgram);
    fn pcap_geterr(handle: *mut c_void) -> *mut c_char;
}

/// # Safety
///
/// `handle` must be null or point to a live `pcap_t` owned exclusively by the caller.
#[expect(
    unsafe_code,
    reason = "reads the error buffer of a live libpcap handle"
)]
pub(in crate::platform) unsafe fn pcap_error_message(handle: *mut c_void) -> String {
    if handle.is_null() {
        return "libpcap returned no diagnostic".to_owned();
    }
    // SAFETY: caller guarantees `handle` is a live pcap handle with exclusive access.
    let message = unsafe { pcap_geterr(handle) };
    if message.is_null() {
        return "libpcap returned no diagnostic".to_owned();
    }
    // SAFETY: `message` is non-null and points to a valid NUL-terminated C string.
    unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned()
}

pub(in crate::platform) fn map_open_error(interface: &InterfaceId, error: PcapError) -> Error {
    let diagnostic = error.to_string();
    pcap_api::map_open_error(
        "libpcap",
        "grant capture privileges (for example CAP_NET_RAW on Linux or BPF access on macOS)",
        interface,
        &diagnostic,
        Some(Source::new(error)),
    )
}

pub(in crate::platform) fn map_send_error(interface: &InterfaceId, error: PcapError) -> Error {
    let diagnostic = error.to_string();
    pcap_api::map_send_error(
        "libpcap",
        "grant link-layer injection privileges",
        interface,
        &diagnostic,
        Some(Source::new(error)),
    )
}
