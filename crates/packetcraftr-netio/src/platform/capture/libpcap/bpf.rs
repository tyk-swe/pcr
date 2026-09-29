// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(unsafe_code)]

use std::{
    ffi::{CStr, CString, c_char, c_int, c_uint, c_void},
    mem::MaybeUninit,
};

use pcap::{Activated, Active, Capture};

use crate::{Error, interface::Id as InterfaceId};

#[link(name = "pcap")]
unsafe extern "C" {
    fn pcap_open_dead(link_type: c_int, snap_length: c_int) -> *mut c_void;
    fn pcap_close(handle: *mut c_void);
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

#[repr(C)]
struct PcapBpfProgram {
    instruction_count: c_uint,
    instructions: *mut c_void,
}

impl Drop for PcapBpfProgram {
    fn drop(&mut self) {
        // SAFETY: only a successful `pcap_compile` produces this value and `Drop` runs once,
        // after `pcap_setfilter` has finished borrowing the program.
        unsafe { pcap_freecode((&raw mut *self).cast()) };
    }
}

struct DeadHandle(*mut c_void);
impl Drop for DeadHandle {
    fn drop(&mut self) {
        // SAFETY: this owns the non-null dead handle from pcap_open_dead and closes it once.
        unsafe { pcap_close(self.0) };
    }
}
pub(in crate::platform) fn validate_capture_filter(
    interface: &crate::interface::Info,
    snap_length: usize,
    filter: &str,
    netmask: u32,
) -> Result<(), Error> {
    let datalink = crate::platform::common::pcap_api::filter_datalink(interface)?;
    let snap_length = c_int::try_from(snap_length).map_err(|_| Error::InvalidCaptureFilter {
        interface: interface.id.name.clone(),
        message: "capture snapshot exceeds native BPF range".to_owned(),
    })?;
    // SAFETY: datalink and snapshot are validated native integers; this creates no live capture.
    let handle = unsafe { pcap_open_dead(datalink, snap_length) };
    if handle.is_null() {
        return Err(Error::Capture {
            message: "libpcap could not allocate a dead filter-compilation handle".to_owned(),
            source: None,
        });
    }
    let handle = DeadHandle(handle);
    let program = compile_filter_handle(handle.0, &interface.id, filter, netmask)?;
    drop(program);
    Ok(())
}

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
    let install_status = unsafe { pcap_setfilter(handle, (&raw mut program).cast::<c_void>()) };
    if install_status != 0 {
        return Err(map_filter_install_error(interface, read_pcap_error(handle)));
    }
    Ok(())
}

fn compile_capture_filter<T: Activated>(
    capture: &Capture<T>,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<PcapBpfProgram, Error> {
    compile_filter_handle(capture.as_ptr().cast(), interface, filter, netmask)
}

fn compile_filter_handle(
    handle: *mut c_void,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<PcapBpfProgram, Error> {
    let c_filter = CString::new(filter).map_err(|_| Error::InvalidCaptureFilter {
        interface: interface.name.clone(),
        message: "filter string contains interior null byte".to_owned(),
    })?;
    let mut program = MaybeUninit::<PcapBpfProgram>::zeroed();
    // SAFETY: the caller owns a live or dead `pcap_t*`, `c_filter` is null-terminated, and
    // `program` points to uninitialized memory laid out as libpcap's `struct bpf_program`.
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
    // SAFETY: `pcap_compile` returned 0, so the `struct bpf_program` is fully initialized.
    Ok(unsafe { program.assume_init() })
}

fn read_pcap_error(handle: *mut c_void) -> String {
    if handle.is_null() {
        return "unknown libpcap error".to_owned();
    }
    // SAFETY: `pcap_geterr` returns a null-terminated string owned by the pcap handle.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{self, Provider};
    use packetcraftr_core::budget::Deadline;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    #[test]
    fn later_numeric_bpf_syntax_error_prevents_every_source_activation() {
        struct Compiler {
            activations: AtomicUsize,
        }
        impl Provider for Compiler {
            type Capture = capture::SystemSession;
            fn validate_capture(
                &self,
                request: &capture::Request,
                _: &Deadline,
            ) -> Result<(), Error> {
                let interface = crate::interface::Info {
                    id: request.interface.clone(),
                    link_type: packetcraftr_core::frame::LinkType::ETHERNET,
                    ..crate::test_support::interface_info("fixture", request.interface.index)
                };
                validate_capture_filter(
                    &interface,
                    request.limits.snap_length,
                    request.filter.as_deref().unwrap(),
                    u32::MAX,
                )
            }
            fn arm_capture(
                &self,
                _: &capture::Request,
                _: &Deadline,
            ) -> Result<Self::Capture, Error> {
                self.activations.fetch_add(1, Ordering::SeqCst);
                panic!("native syntax errors must precede activation")
            }
        }
        let first = InterfaceId {
            name: "first0".to_owned(),
            index: 7,
        };
        let last = InterfaceId {
            name: "later0".to_owned(),
            index: 8,
        };
        let request = capture::GroupRequest {
            interfaces: vec![first, last.clone()],
            limits: capture::Limits::default(),
            filter: Some("udp port 53".to_owned()),
            filters: vec![(last.clone(), "udp and".to_owned())],
            promiscuous: false,
            native: Default::default(),
        };
        let compiler = Compiler {
            activations: AtomicUsize::new(0),
        };
        let mut group = capture::Group::new(&request).unwrap();
        let error = group
            .arm(&compiler, &Deadline::new(Duration::from_secs(1)))
            .unwrap_err();
        assert!(
            matches!(error, Error::InvalidCaptureFilter {interface,..} if interface == last.name)
        );
        assert_eq!(compiler.activations.load(Ordering::SeqCst), 0);
        assert_eq!(group.sources().count(), 0);
    }
}
