// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Npcap capture source and interrupt lifecycle.

#![allow(unsafe_code)]

use std::{
    ffi::CString,
    ptr::{NonNull, null_mut},
    sync::Arc,
    time::{Instant, SystemTime},
};

use bytes::Bytes;
use packetcraftr_core::frame::LinkType;

use super::{
    abi::{BpfProgram, PCAP_ERROR, PCAP_ERROR_BREAK, PCAP_NETMASK_UNKNOWN, PcapStatistics},
    handles::{NpcapHandle, PromiscuousMode, open_handle},
};
use crate::{
    Error as LiveIoError,
    capture::CaptureQueueLimits,
    platform::live_capture::{
        CaptureInterrupt, NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource,
        NativeCaptureStatistics, NativeCapturedPacket, monotonic_packet_time, system_time,
    },
    route::InterfaceId,
};

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
            reason: "Npcap snap length exceeds i32",
        })?;
    let handle = open_handle(interface, snap_length, PromiscuousMode::Enabled)?;
    if let Some(filter) = capture_filter {
        install_capture_filter(
            &handle,
            interface,
            filter,
            netmask.unwrap_or(PCAP_NETMASK_UNKNOWN),
        )?;
    }
    // SAFETY: handle is activated and live; pcap_datalink only reads its
    // negotiated link-layer type.
    let datalink = unsafe { (handle.api.pcap_datalink)(handle.raw.as_ptr()) };
    let datalink = u32::try_from(datalink).map_err(|_| LiveIoError::Capture {
        message: format!(
            "Npcap could not report the data-link type for {}: {}",
            interface.name,
            handle.error_message()
        ),
    })?;
    let link_type = LinkType(datalink);
    let interrupt = Arc::new(NpcapInterrupt(Arc::clone(&handle)));
    Ok(NativeCaptureParts {
        source: Box::new(NpcapCaptureSource {
            handle,
            snap_length: limits.snap_length,
        }),
        interrupt,
        interface: interface.clone(),
        link_type,
    })
}

fn install_capture_filter(
    handle: &NpcapHandle,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<(), LiveIoError> {
    let filter = CString::new(filter).map_err(|_| LiveIoError::InvalidCaptureFilter {
        interface: interface.name.clone(),
        message: "Npcap BPF expressions cannot contain an interior NUL byte".to_owned(),
    })?;
    let mut program = BpfProgram {
        instruction_count: 0,
        instructions: null_mut(),
    };
    // SAFETY: handle is activated and live, program is a writable SDK-layout
    // output structure, filter is NUL-terminated, and the API owner keeps the
    // function pointer loaded for this call.
    let compile_status = unsafe {
        (handle.api.pcap_compile)(
            handle.raw.as_ptr(),
            &mut program,
            filter.as_ptr(),
            1,
            netmask,
        )
    };
    if compile_status != 0 {
        let diagnostic = handle.error_message();
        return Err(LiveIoError::InvalidCaptureFilter {
            interface: interface.name.clone(),
            message: format!("Npcap compilation failed: {diagnostic}"),
        });
    }

    // SAFETY: successful pcap_compile initialized program for this live
    // handle; the worker has not started, so this is the only handle call.
    let install_status = unsafe { (handle.api.pcap_setfilter)(handle.raw.as_ptr(), &mut program) };
    let diagnostic = (install_status != 0).then(|| handle.error_message());
    // SAFETY: pcap_compile succeeded and this is the single matching
    // pcap_freecode call, after pcap_setfilter has finished using the program.
    unsafe { (handle.api.pcap_freecode)(&mut program) };

    if let Some(diagnostic) = diagnostic {
        return Err(LiveIoError::CaptureFilterInstallation {
            interface: interface.name.clone(),
            message: format!("Npcap installation failed: {diagnostic}"),
        });
    }
    Ok(())
}

struct NpcapCaptureSource {
    handle: Arc<NpcapHandle>,
    snap_length: usize,
}

impl NativeCaptureSource for NpcapCaptureSource {
    fn next_event(&mut self) -> Result<NativeCaptureEvent, LiveIoError> {
        let mut header = std::ptr::null_mut();
        let mut data = std::ptr::null();
        // SAFETY: header/data are writable out-pointers and the worker is the
        // sole reader of this live handle.
        let result = unsafe {
            (self.handle.api.pcap_next_ex)(self.handle.raw.as_ptr(), &mut header, &mut data)
        };
        // Monotonic first makes the paired-clock sampling skew conservative.
        let observed_at = Instant::now();
        let observed_wall = SystemTime::now();
        match result {
            1 => {
                let header = NonNull::new(header).ok_or_else(|| LiveIoError::Capture {
                    message: "Npcap returned a packet without a header".to_owned(),
                })?;
                // SAFETY: a successful pcap_next_ex result guarantees the
                // header remains valid until the next handle operation; we copy
                // the fixed-size value immediately.
                let header = unsafe { *header.as_ptr() };
                let timestamp = system_time(
                    header.timestamp.tv_sec as i64,
                    header.timestamp.tv_usec as i64,
                )?;
                let received_at = monotonic_packet_time(timestamp, observed_wall, observed_at);
                let captured_length = header.captured_length as usize;
                if captured_length > self.snap_length {
                    return Err(LiveIoError::Capture {
                        message: format!(
                            "Npcap returned {captured_length} bytes beyond configured snap length {}",
                            self.snap_length
                        ),
                    });
                }
                if header.original_length < header.captured_length {
                    return Err(LiveIoError::Capture {
                        message: format!(
                            "Npcap returned captured length {} above original length {}",
                            header.captured_length, header.original_length
                        ),
                    });
                }
                let bytes = if captured_length == 0 {
                    Bytes::new()
                } else {
                    if data.is_null() {
                        return Err(LiveIoError::Capture {
                            message: "Npcap returned packet bytes through a null pointer"
                                .to_owned(),
                        });
                    }
                    // SAFETY: pcap_next_ex guarantees caplen readable bytes
                    // until the next handle call; Bytes copies them now.
                    Bytes::copy_from_slice(unsafe {
                        std::slice::from_raw_parts(data, captured_length)
                    })
                };
                Ok(NativeCaptureEvent::Packet(NativeCapturedPacket {
                    timestamp,
                    received_at,
                    captured_length: header.captured_length,
                    original_length: header.original_length,
                    bytes,
                }))
            }
            0 => Ok(NativeCaptureEvent::Timeout),
            PCAP_ERROR_BREAK => Ok(NativeCaptureEvent::Closed),
            PCAP_ERROR => Err(LiveIoError::Capture {
                message: format!("Npcap receive failed: {}", self.handle.error_message()),
            }),
            status => Err(LiveIoError::Capture {
                message: format!(
                    "Npcap receive returned unexpected status {status}: {}",
                    self.handle.error_message()
                ),
            }),
        }
    }

    fn statistics(&mut self) -> Result<NativeCaptureStatistics, LiveIoError> {
        let mut statistics = PcapStatistics::default();
        // SAFETY: the SDK-sized output structure is writable and the worker
        // exclusively operates this live capture handle.
        let result =
            unsafe { (self.handle.api.pcap_stats)(self.handle.raw.as_ptr(), &mut statistics) };
        if result != 0 {
            return Err(LiveIoError::Capture {
                message: format!(
                    "Npcap statistics failed with status {result}: {}",
                    self.handle.error_message()
                ),
            });
        }
        Ok(NativeCaptureStatistics {
            capture_dropped_frames: statistics.dropped,
            network_dropped_frames: statistics.network_dropped,
            interface_dropped_frames: statistics.interface_dropped,
        })
    }
}

struct NpcapInterrupt(Arc<NpcapHandle>);

impl CaptureInterrupt for NpcapInterrupt {
    fn interrupt(&self) {
        // SAFETY: libpcap documents pcap_breakloop as callable from a different
        // thread; the Arc keeps the handle live for this call.
        unsafe { (self.0.api.pcap_breakloop)(self.0.raw.as_ptr()) };
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::{c_char, c_int, c_uchar, c_uint, c_void},
        ptr::{NonNull, null_mut},
        sync::{
            Arc,
            atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering},
        },
    };

    use libloading::os::windows::Library;

    use super::super::{
        abi::{BpfProgram, PcapPacketHeader, PcapStatistics},
        handles::NpcapHandle,
        loader::NpcapApi,
    };
    use super::*;
    use crate::Error as LiveIoError;

    static COMPILE_STATUS: AtomicI32 = AtomicI32::new(0);
    static SETFILTER_STATUS: AtomicI32 = AtomicI32::new(0);
    static FREECODE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static LAST_NETMASK: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn noop_create(_: *const c_char, _: *mut c_char) -> *mut c_void {
        null_mut()
    }

    unsafe extern "C" fn noop_set_integer(_: *mut c_void, _: c_int) -> c_int {
        0
    }

    unsafe extern "C" fn noop_activate(_: *mut c_void) -> c_int {
        0
    }

    unsafe extern "C" fn noop_datalink(_: *mut c_void) -> c_int {
        1
    }

    unsafe extern "C" fn test_compile(
        _: *mut c_void,
        program: *mut BpfProgram,
        _: *const c_char,
        _: c_int,
        netmask: c_uint,
    ) -> c_int {
        LAST_NETMASK.store(netmask, Ordering::SeqCst);
        let status = COMPILE_STATUS.load(Ordering::SeqCst);
        if status == 0 {
            // SAFETY: install_capture_filter supplies a valid writable program
            // pointer for every successful controlled compile.
            unsafe {
                (*program).instruction_count = 1;
                (*program).instructions = null_mut();
            }
        }
        status
    }

    unsafe extern "C" fn test_setfilter(_: *mut c_void, _: *mut BpfProgram) -> c_int {
        SETFILTER_STATUS.load(Ordering::SeqCst)
    }

    unsafe extern "C" fn test_freecode(_: *mut BpfProgram) {
        FREECODE_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn noop_next_ex(
        _: *mut c_void,
        _: *mut *mut PcapPacketHeader,
        _: *mut *const c_uchar,
    ) -> c_int {
        PCAP_ERROR_BREAK
    }

    unsafe extern "C" fn noop_send_packet(_: *mut c_void, _: *const c_uchar, _: c_int) -> c_int {
        0
    }

    unsafe extern "C" fn noop_stats(_: *mut c_void, _: *mut PcapStatistics) -> c_int {
        0
    }

    unsafe extern "C" fn noop_breakloop(_: *mut c_void) {}

    unsafe extern "C" fn test_geterr(_: *mut c_void) -> *mut c_char {
        c"controlled error".as_ptr().cast_mut()
    }

    unsafe extern "C" fn noop_close(_: *mut c_void) {}

    fn api() -> Arc<NpcapApi> {
        Arc::new(NpcapApi {
            _library: Library::this().expect("the test executable is a Windows module"),
            pcap_create: noop_create,
            pcap_set_snaplen: noop_set_integer,
            pcap_set_promisc: noop_set_integer,
            pcap_set_timeout: noop_set_integer,
            pcap_set_immediate_mode: noop_set_integer,
            pcap_activate: noop_activate,
            pcap_datalink: noop_datalink,
            pcap_compile: test_compile,
            pcap_setfilter: test_setfilter,
            pcap_freecode: test_freecode,
            pcap_next_ex: noop_next_ex,
            pcap_sendpacket: noop_send_packet,
            pcap_stats: noop_stats,
            pcap_breakloop: noop_breakloop,
            pcap_geterr: test_geterr,
            pcap_close: noop_close,
        })
    }

    fn test_handle() -> NpcapHandle {
        NpcapHandle {
            api: api(),
            raw: NonNull::dangling(),
        }
    }

    fn interface() -> InterfaceId {
        InterfaceId {
            name: "test0".to_owned(),
            index: 7,
        }
    }

    fn configure(compile_status: c_int, setfilter_status: c_int) {
        COMPILE_STATUS.store(compile_status, Ordering::SeqCst);
        SETFILTER_STATUS.store(setfilter_status, Ordering::SeqCst);
        FREECODE_CALLS.store(0, Ordering::SeqCst);
        LAST_NETMASK.store(0, Ordering::SeqCst);
    }

    #[test]
    fn install_capture_filter_classifies_failures_cleans_code_and_forwards_netmask() {
        let interface = interface();
        let netmask = 0xffff_ff00;

        configure(PCAP_ERROR, 0);
        let handle = test_handle();
        let error = install_capture_filter(&handle, &interface, "ip", netmask).unwrap_err();
        assert!(matches!(error, LiveIoError::InvalidCaptureFilter { .. }));
        assert_eq!(FREECODE_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(LAST_NETMASK.load(Ordering::SeqCst), netmask);

        configure(0, PCAP_ERROR);
        let handle = test_handle();
        let error = install_capture_filter(&handle, &interface, "ip", netmask).unwrap_err();
        assert!(matches!(
            error,
            LiveIoError::CaptureFilterInstallation { .. }
        ));
        assert_eq!(FREECODE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_NETMASK.load(Ordering::SeqCst), netmask);

        configure(0, 0);
        let handle = test_handle();
        install_capture_filter(&handle, &interface, "ip", netmask).unwrap();
        assert_eq!(FREECODE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_NETMASK.load(Ordering::SeqCst), netmask);
    }
}
