// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! libpcap BPF filter compilation and kernel installation.

#![allow(unsafe_code)]

use std::{
    ffi::{CStr, CString, c_char, c_int, c_uint, c_void},
    mem::MaybeUninit,
};

use pcap::{Active, Capture};

use crate::{Error, interface::Id as InterfaceId};

#[link(name = "pcap")]
unsafe extern "C" {
    fn pcap_compile(
        handle: *mut c_void,
        program: *mut c_void,
        source: *const c_char,
        optimize: c_int,
        netmask: u32,
    ) -> c_int;
    fn pcap_setfilter(handle: *mut c_void, program: *mut c_void) -> c_int;
    fn pcap_freecode(program: *mut c_void);
    fn pcap_geterr(handle: *mut c_void) -> *mut c_char;
}

/// Owns the kernel-format program `pcap_compile` allocates.
///
/// A value of this type only ever exists after a successful `pcap_compile`,
/// and `Drop` is its single release, so no exit path can leak the allocation.
#[repr(C)]
struct PcapBpfProgram {
    instruction_count: c_uint,
    instructions: *mut c_void,
}

impl Drop for PcapBpfProgram {
    fn drop(&mut self) {
        // SAFETY: this value is only ever produced by a successful
        // `pcap_compile`, whose allocation this owns; `Drop` runs once, and
        // `pcap_setfilter` has finished with the program by then because it
        // borrows the value for strictly less than this scope.
        unsafe { pcap_freecode((&raw mut *self).cast()) };
    }
}

pub(super) fn install_capture_filter(
    capture: &mut Capture<Active>,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<(), Error> {
    let mut program = compile_capture_filter(capture, interface, filter, netmask)?;
    let handle = capture.as_ptr().cast::<c_void>();
    // SAFETY: program was initialized by pcap_compile for this live handle,
    // which remains exclusively borrowed until installation returns.
    let install_status = unsafe { pcap_setfilter(handle, (&raw mut program).cast::<c_void>()) };
    if install_status != 0 {
        return Err(map_filter_install_error(interface, read_pcap_error(handle)));
    }
    Ok(())
}

fn compile_capture_filter(
    capture: &Capture<Active>,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<PcapBpfProgram, Error> {
    let handle = capture.as_ptr().cast::<c_void>();
    let c_filter = CString::new(filter).map_err(|_| Error::InvalidCaptureFilter {
        interface: interface.name.clone(),
        message: "filter string contains interior null byte".to_owned(),
    })?;
    let mut program = MaybeUninit::<PcapBpfProgram>::zeroed();
    // SAFETY: `capture.as_ptr()` yields a valid `pcap_t*`, `c_filter` is a
    // null-terminated C string, and `program.as_mut_ptr()` points to uninitialized
    // memory of the exact layout of libpcap's `struct bpf_program`.
    let compile_status = unsafe {
        pcap_compile(
            handle,
            program.as_mut_ptr().cast(),
            c_filter.as_ptr(),
            1,
            netmask,
        )
    };
    if compile_status != 0 {
        return Err(map_filter_compile_error(interface, read_pcap_error(handle)));
    }
    // SAFETY: `pcap_compile` returned 0, guaranteeing the `struct bpf_program`
    // fields were fully initialized.
    Ok(unsafe { program.assume_init() })
}

fn read_pcap_error(handle: *mut c_void) -> String {
    if handle.is_null() {
        return "unknown libpcap error".to_owned();
    }
    // SAFETY: `pcap_geterr` returns a pointer to a null-terminated string
    // owned by the pcap handle.
    let error_ptr = unsafe { pcap_geterr(handle) };
    if error_ptr.is_null() {
        return "unknown libpcap error".to_owned();
    }
    // SAFETY: `error_ptr` is non-null and points to a valid C string.
    unsafe { CStr::from_ptr(error_ptr) }
        .to_string_lossy()
        .into_owned()
}

fn map_filter_compile_error(interface: &InterfaceId, error: impl std::fmt::Display) -> Error {
    Error::InvalidCaptureFilter {
        interface: interface.name.clone(),
        message: format!("libpcap compilation failed: {error}"),
    }
}

fn map_filter_install_error(interface: &InterfaceId, error: impl std::fmt::Display) -> Error {
    Error::CaptureFilterInstallation {
        interface: interface.name.clone(),
        message: format!("libpcap installation failed: {error}"),
    }
}
