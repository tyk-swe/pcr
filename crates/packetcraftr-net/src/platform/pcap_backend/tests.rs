// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(test)]

use pcap::{Capture, Error as PcapError};

use super::bpf::{
    PcapBpfProgram, compile_capture_filter, map_filter_compile_error, map_filter_install_error,
};
use super::capture::{PCAP_NETMASK_UNKNOWN, map_open_error};
use super::transmit::map_send_error;
use crate::{Error as LiveIoError, route::InterfaceId};

fn interface() -> InterfaceId {
    InterfaceId {
        name: "test0".to_owned(),
        index: 7,
    }
}

#[test]
fn open_error_maps_all_permission_spellings_to_privilege() {
    for message in [
        "Permission denied",
        "Operation not permitted",
        "Access is denied",
    ] {
        let error = map_open_error(&interface(), PcapError::PcapError(message.to_owned()));
        assert!(matches!(error, LiveIoError::Privilege { .. }));
        assert!(error.to_string().contains("test0"));
    }
}

#[test]
fn open_error_maps_missing_device_spellings_to_device() {
    for message in [
        "No such device",
        "device not found",
        "interface does not exist",
    ] {
        let error = map_open_error(&interface(), PcapError::PcapError(message.to_owned()));
        assert!(matches!(
            error,
            LiveIoError::Device { interface, .. } if interface == "test0"
        ));
    }
}

#[test]
fn other_open_errors_remain_capture_errors() {
    let error = map_open_error(
        &interface(),
        PcapError::PcapError("backend failure".to_owned()),
    );
    assert!(matches!(error, LiveIoError::Capture { .. }));
    assert!(error.to_string().contains("backend failure"));
}

#[test]
fn send_error_maps_all_permission_spellings_to_privilege() {
    for message in [
        "Permission denied",
        "Operation not permitted",
        "Access is denied",
    ] {
        let error = map_send_error(&interface(), PcapError::PcapError(message.to_owned()));
        assert!(matches!(error, LiveIoError::Privilege { .. }));
        assert!(error.to_string().contains("test0"));
    }
}

#[test]
fn other_send_errors_remain_send_errors() {
    let error = map_send_error(
        &interface(),
        PcapError::PcapError("backend failure".to_owned()),
    );
    assert!(matches!(error, LiveIoError::Send { .. }));
    assert!(error.to_string().contains("backend failure"));
}

#[test]
fn capture_filter_errors_preserve_compile_and_install_stages() {
    let compile = map_filter_compile_error(
        &interface(),
        PcapError::PcapError("syntax error".to_owned()),
    );
    assert!(matches!(compile, LiveIoError::InvalidCaptureFilter { .. }));
    assert!(compile.to_string().contains("test0"));
    assert!(compile.to_string().contains("syntax error"));

    let install = map_filter_install_error(
        &interface(),
        PcapError::PcapError("backend failure".to_owned()),
    );
    assert!(matches!(
        install,
        LiveIoError::CaptureFilterInstallation { .. }
    ));
    assert!(install.to_string().contains("test0"));
    assert!(install.to_string().contains("backend failure"));
}

#[test]
fn broadcast_filter_compiles_with_the_interface_netmask() {
    let capture = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let mut program = compile_capture_filter(
        &capture,
        &interface(),
        "ip broadcast",
        u32::from_ne_bytes([255, 255, 255, 0]),
    )
    .unwrap();
    assert!(program.instruction_count > 0);
    // SAFETY: the program was initialized by pcap_compile and is being
    // released exactly once after the assertion.
    unsafe { pcap_freecode((&mut program as *mut PcapBpfProgram).cast()) };

    let unknown =
        compile_capture_filter(&capture, &interface(), "ip broadcast", PCAP_NETMASK_UNKNOWN);
    assert!(matches!(
        unknown,
        Err(LiveIoError::InvalidCaptureFilter { .. })
    ));
}

#[link(name = "pcap")]
unsafe extern "C" {
    fn pcap_freecode(program: *mut std::ffi::c_void);
}
