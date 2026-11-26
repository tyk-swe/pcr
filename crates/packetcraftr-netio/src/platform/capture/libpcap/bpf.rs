// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::{CString, c_void};

use pcap::{Active, Capture};

use crate::{
    Error,
    interface::Id as InterfaceId,
    platform::common::{
        libpcap::{pcap_compile, pcap_error_message, pcap_freecode, pcap_setfilter},
        pcap_api::BpfProgram,
    },
};

struct CompiledFilter(BpfProgram);

impl Drop for CompiledFilter {
    #[expect(
        unsafe_code,
        reason = "releases compiled BPF program via pcap_freecode"
    )]
    fn drop(&mut self) {
        // SAFETY: only a successful `pcap_compile` produces this value and `Drop` runs once,
        // after `pcap_setfilter` has finished borrowing the program.
        unsafe { pcap_freecode(&raw mut self.0) };
    }
}

#[expect(
    unsafe_code,
    reason = "installs compiled BPF program via pcap_setfilter"
)]
pub(in crate::platform) fn install_capture_filter(
    capture: &mut Capture<Active>,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<(), Error> {
    let mut program = compile_capture_filter(capture, interface, filter, netmask)?;
    let handle = capture.as_ptr().cast::<c_void>();
    // SAFETY: program was initialized by pcap_compile for this live handle,
    // which remains exclusively borrowed until installation returns.
    let install_status = unsafe { pcap_setfilter(handle, &raw mut program.0) };
    if install_status != 0 {
        // SAFETY: handle is exclusively borrowed by this thread.
        return Err(map_filter_install_error(interface, unsafe {
            pcap_error_message(handle)
        }));
    }
    Ok(())
}

#[expect(unsafe_code, reason = "compiles BPF filter via pcap_compile")]
fn compile_capture_filter(
    capture: &Capture<Active>,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<CompiledFilter, Error> {
    let handle = capture.as_ptr().cast::<c_void>();
    let c_filter = CString::new(filter).map_err(|_| Error::InvalidCaptureFilter {
        interface: interface.name.clone(),
        message: "filter string contains interior null byte".to_owned(),
    })?;
    let mut program = BpfProgram::empty();
    // SAFETY: `capture.as_ptr()` is a valid `pcap_t*`, `c_filter` is null-terminated, and
    // `program` points to a writable `struct bpf_program`.
    let compile_status =
        unsafe { pcap_compile(handle, &raw mut program, c_filter.as_ptr(), 1, netmask) };
    if compile_status != 0 {
        // SAFETY: handle is live and owned by this thread.
        return Err(map_filter_compile_error(interface, unsafe {
            pcap_error_message(handle)
        }));
    }
    Ok(CompiledFilter(program))
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
