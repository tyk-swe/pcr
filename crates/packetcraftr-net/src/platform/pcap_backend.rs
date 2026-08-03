// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! libpcap-backed Layer 2 capture and injection for Linux and macOS.

#![allow(unsafe_code)]

use std::{
    ffi::{CStr, CString, c_char, c_int, c_uint, c_void},
    mem::MaybeUninit,
    sync::Arc,
    time::{Instant, SystemTime},
};

use bytes::Bytes;
use pcap::{Activated, Active, Capture, Error as PcapError};

use super::live_capture::{
    CaptureInterrupt, NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource,
    NativeCaptureStatistics, NativeCapturedPacket, monotonic_packet_time, system_time,
};
use crate::{
    Error as LiveIoError,
    capture::CaptureQueueLimits,
    route::InterfaceId,
    transmit::{IoSendReport, Layer2Frame},
};
use packetcraftr_core::frame::LinkType;

const READ_TIMEOUT_MILLIS: i32 = 50;
const PCAP_NETMASK_UNKNOWN: u32 = u32::MAX;

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

#[repr(C)]
struct PcapBpfProgram {
    instruction_count: c_uint,
    instructions: *mut c_void,
}

pub(super) fn open_capture(
    interface: &InterfaceId,
    limits: CaptureQueueLimits,
    capture_filter: Option<&str>,
    netmask: Option<u32>,
) -> Result<NativeCaptureParts, LiveIoError> {
    let snap_length =
        i32::try_from(limits.snap_length).map_err(|_| LiveIoError::InvalidCaptureQueueLimit {
            field: "snap_length",
            value: limits.snap_length,
            reason: "libpcap snap length exceeds i32",
        })?;
    let mut capture = Capture::from_device(interface.name.as_str())
        .map_err(|error| map_open_error(interface, error))?
        .snaplen(snap_length)
        .promisc(true)
        .timeout(READ_TIMEOUT_MILLIS)
        .immediate_mode(true)
        .open()
        .map_err(|error| map_open_error(interface, error))?;
    if let Some(filter) = capture_filter {
        install_capture_filter(
            &mut capture,
            interface,
            filter,
            netmask.unwrap_or(PCAP_NETMASK_UNKNOWN),
        )?;
    }
    let datalink = capture.get_datalink().0;
    let link_type =
        u32::try_from(datalink)
            .map(LinkType)
            .map_err(|_| LiveIoError::Unsupported {
                message: format!(
                    "libpcap returned negative data-link type {datalink} for {}",
                    interface.name
                ),
            })?;
    let interrupt = Arc::new(PcapInterrupt(capture.breakloop_handle()));
    Ok(NativeCaptureParts {
        source: Box::new(PcapCaptureSource {
            capture,
            snap_length: limits.snap_length,
        }),
        interrupt,
        interface: interface.clone(),
        link_type,
    })
}

fn install_capture_filter(
    capture: &mut Capture<Active>,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<(), LiveIoError> {
    let mut program = compile_capture_filter(capture, interface, filter, netmask)?;
    let handle = capture.as_ptr().cast::<c_void>();
    // SAFETY: program was initialized by pcap_compile for this live handle,
    // which remains exclusively borrowed until installation returns.
    let install_status =
        unsafe { pcap_setfilter(handle, (&mut program as *mut PcapBpfProgram).cast()) };
    let diagnostic = (install_status != 0).then(|| capture_error_message(handle));
    // SAFETY: pcap_compile initialized this ABI-compatible local structure,
    // pcap_setfilter has finished using it, and this is its single cleanup.
    unsafe { pcap_freecode((&mut program as *mut PcapBpfProgram).cast()) };

    if let Some(diagnostic) = diagnostic {
        return Err(map_filter_install_error(interface, diagnostic));
    }
    Ok(())
}

fn compile_capture_filter<T: Activated>(
    capture: &Capture<T>,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<PcapBpfProgram, LiveIoError> {
    let filter = CString::new(filter).map_err(|_| {
        map_filter_compile_error(
            interface,
            "BPF expressions cannot contain an interior NUL byte",
        )
    })?;
    let mut program = MaybeUninit::<PcapBpfProgram>::zeroed();
    let handle = capture.as_ptr().cast::<c_void>();
    // SAFETY: the pcap crate owns a live activated handle; program is the
    // writable repr(C) layout of libpcap's bpf_program, filter is NUL-
    // terminated, and no worker or other caller can access the handle.
    let compile_status = unsafe {
        pcap_compile(
            handle,
            program.as_mut_ptr().cast(),
            filter.as_ptr(),
            1,
            netmask,
        )
    };
    if compile_status != 0 {
        return Err(map_filter_compile_error(
            interface,
            capture_error_message(handle),
        ));
    }

    // SAFETY: successful pcap_compile initialized the local ABI structure.
    Ok(unsafe { program.assume_init() })
}

fn capture_error_message(handle: *mut c_void) -> String {
    // SAFETY: handle is a live pcap handle and pcap_geterr returns either null
    // or a NUL-terminated diagnostic owned by that handle. Copy it before any
    // later handle call can replace the backend buffer.
    let diagnostic = unsafe { pcap_geterr(handle) };
    if diagnostic.is_null() {
        "unknown libpcap error".to_owned()
    } else {
        // SAFETY: the non-null pointer is the NUL-terminated pcap_geterr
        // diagnostic promised above and is read only for this immediate copy.
        unsafe { CStr::from_ptr(diagnostic) }
            .to_string_lossy()
            .into_owned()
    }
}

pub(super) fn send_layer2(frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    let interface = &frame.route().plan.route.interface;
    i32::try_from(frame.bytes().len()).map_err(|_| LiveIoError::InvalidTransmissionFrame {
        message: format!(
            "Layer 2 frame length {} exceeds the libpcap signed-length limit",
            frame.bytes().len()
        ),
    })?;
    let mut capture = Capture::from_device(interface.name.as_str())
        .map_err(|error| map_open_error(interface, error))?
        .promisc(false)
        .timeout(READ_TIMEOUT_MILLIS)
        .immediate_mode(true)
        .open()
        .map_err(|error| map_open_error(interface, error))?;
    capture
        .sendpacket(frame.bytes().as_ref())
        .map_err(|error| map_send_error(interface, error))?;
    Ok(IoSendReport {
        bytes_sent: frame.bytes().len(),
        wire_bytes: frame.bytes().clone(),
    })
}

struct PcapCaptureSource {
    capture: Capture<Active>,
    snap_length: usize,
}

impl NativeCaptureSource for PcapCaptureSource {
    fn next_event(&mut self) -> Result<NativeCaptureEvent, LiveIoError> {
        match self.capture.next_packet() {
            Ok(packet) => {
                // Monotonic first makes the paired-clock sampling skew conservative.
                let observed_at = Instant::now();
                let observed_wall = SystemTime::now();
                #[cfg(target_os = "linux")]
                let timestamp = system_time(packet.header.ts.tv_sec, packet.header.ts.tv_usec)?;
                #[cfg(target_os = "macos")]
                let timestamp =
                    system_time(packet.header.ts.tv_sec, i64::from(packet.header.ts.tv_usec))?;
                let received_at = monotonic_packet_time(timestamp, observed_wall, observed_at);
                if packet.data.len() > self.snap_length {
                    return Err(LiveIoError::Capture {
                        message: format!(
                            "libpcap returned {} bytes beyond configured snap length {}",
                            packet.data.len(),
                            self.snap_length
                        ),
                    });
                }
                if packet.data.len() != packet.header.caplen as usize {
                    return Err(LiveIoError::Capture {
                        message: format!(
                            "libpcap packet data contains {} bytes but declares captured length {}",
                            packet.data.len(),
                            packet.header.caplen
                        ),
                    });
                }
                Ok(NativeCaptureEvent::Packet(NativeCapturedPacket {
                    timestamp,
                    received_at,
                    captured_length: packet.header.caplen,
                    original_length: packet.header.len,
                    bytes: Bytes::copy_from_slice(packet.data),
                }))
            }
            Err(PcapError::TimeoutExpired) => Ok(NativeCaptureEvent::Timeout),
            Err(PcapError::NoMorePackets) => Ok(NativeCaptureEvent::Closed),
            Err(error) => Err(LiveIoError::Capture {
                message: format!("libpcap receive failed: {error}"),
            }),
        }
    }

    fn statistics(&mut self) -> Result<NativeCaptureStatistics, LiveIoError> {
        self.capture
            .stats()
            .map(|statistics| NativeCaptureStatistics {
                capture_dropped_frames: statistics.dropped,
                network_dropped_frames: 0,
                interface_dropped_frames: statistics.if_dropped,
            })
            .map_err(|error| LiveIoError::Capture {
                message: format!("libpcap statistics failed: {error}"),
            })
    }
}

struct PcapInterrupt(pcap::BreakLoop);

impl CaptureInterrupt for PcapInterrupt {
    fn interrupt(&self) {
        self.0.breakloop();
    }
}

fn map_open_error(interface: &InterfaceId, error: PcapError) -> LiveIoError {
    let message = error.to_string();
    let lower = message.to_ascii_lowercase();
    if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("access is denied")
    {
        return LiveIoError::Privilege {
            message: format!(
                "cannot open {} through libpcap: {message}; grant capture privileges (for example CAP_NET_RAW on Linux or BPF access on macOS)",
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
            message: format!("libpcap could not open this interface: {message}"),
        };
    }
    LiveIoError::Capture {
        message: format!(
            "could not open {} through libpcap: {message}",
            interface.name
        ),
    }
}

fn map_send_error(interface: &InterfaceId, error: PcapError) -> LiveIoError {
    let message = error.to_string();
    let lower = message.to_ascii_lowercase();
    if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("access is denied")
    {
        return LiveIoError::Privilege {
            message: format!(
                "cannot inject on {} through libpcap: {message}; grant link-layer injection privileges",
                interface.name
            ),
        };
    }
    LiveIoError::Send {
        message: format!("libpcap injection on {} failed: {message}", interface.name),
    }
}

fn map_filter_compile_error(interface: &InterfaceId, error: impl std::fmt::Display) -> LiveIoError {
    LiveIoError::InvalidCaptureFilter {
        interface: interface.name.clone(),
        message: format!("libpcap compilation failed: {error}"),
    }
}

fn map_filter_install_error(interface: &InterfaceId, error: impl std::fmt::Display) -> LiveIoError {
    LiveIoError::CaptureFilterInstallation {
        interface: interface.name.clone(),
        message: format!("libpcap installation failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
