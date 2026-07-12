// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-loaded Npcap adapter for Windows.

use super::live_capture::NativeCaptureParts;
use crate::net::{CaptureQueueLimits, InterfaceId, IoSendReport, Layer2Frame, LiveIoError};

#[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
mod supported {
    use std::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void, CStr, CString, OsString};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::ptr::NonNull;
    use std::sync::{Arc, OnceLock};

    use bytes::Bytes;
    use libloading::os::windows::{
        Library, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    use windows::core::GUID;
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToGuid,
    };
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

    use super::super::live_capture::{
        system_time, CaptureInterrupt, NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource,
        NativeCaptureStatistics, NativeCapturedPacket,
    };
    use crate::capture::LinkType;
    use crate::net::{CaptureQueueLimits, InterfaceId, IoSendReport, Layer2Frame, LiveIoError};

    const NPCAP_DEPENDENCY: &str = "Npcap 1.88 runtime";
    const PCAP_ERROR_BUFFER_SIZE: usize = 256;
    const PCAP_CHAR_ENC_UTF_8: c_uint = 1;
    const READ_TIMEOUT_MILLIS: c_int = 50;
    const SEND_SNAPSHOT_LENGTH: c_int = 65_535;

    const PCAP_ERROR: c_int = -1;
    const PCAP_ERROR_BREAK: c_int = -2;
    const PCAP_ERROR_NO_SUCH_DEVICE: c_int = -5;
    const PCAP_ERROR_RFMON_NOTSUP: c_int = -6;
    const PCAP_ERROR_PERM_DENIED: c_int = -8;
    const PCAP_ERROR_IFACE_NOT_UP: c_int = -9;
    const PCAP_ERROR_PROMISC_PERM_DENIED: c_int = -11;
    const PCAP_ERROR_CAPTURE_NOTSUP: c_int = -13;

    type PcapInit = unsafe extern "C" fn(c_uint, *mut c_char) -> c_int;
    type PcapCreate = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_void;
    type PcapSetInteger = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
    type PcapActivate = unsafe extern "C" fn(*mut c_void) -> c_int;
    type PcapDatalink = unsafe extern "C" fn(*mut c_void) -> c_int;
    type PcapNextEx =
        unsafe extern "C" fn(*mut c_void, *mut *mut PcapPacketHeader, *mut *const c_uchar) -> c_int;
    type PcapSendPacket = unsafe extern "C" fn(*mut c_void, *const c_uchar, c_int) -> c_int;
    type PcapStats = unsafe extern "C" fn(*mut c_void, *mut PcapStatistics) -> c_int;
    type PcapBreakLoop = unsafe extern "C" fn(*mut c_void);
    type PcapGetError = unsafe extern "C" fn(*mut c_void) -> *mut c_char;
    type PcapClose = unsafe extern "C" fn(*mut c_void);

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PcapTimeval {
        tv_sec: c_long,
        tv_usec: c_long,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PcapPacketHeader {
        timestamp: PcapTimeval,
        captured_length: c_uint,
        original_length: c_uint,
    }

    // Npcap's Windows ABI extends the portable three-counter pcap_stat with
    // ps_capt, ps_sent, and ps_netdrop. The complete SDK 1.16 layout is
    // required here so pcap_stats cannot write beyond the Rust allocation.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct PcapStatistics {
        received: c_uint,
        dropped: c_uint,
        interface_dropped: c_uint,
        captured: c_uint,
        sent: c_uint,
        network_dropped: c_uint,
    }

    struct NpcapApi {
        // Function pointers remain valid only while their defining module is
        // loaded. This owner keeps it live for every use of the inert pointers.
        _library: Library,
        pcap_create: PcapCreate,
        pcap_set_snaplen: PcapSetInteger,
        pcap_set_promisc: PcapSetInteger,
        pcap_set_timeout: PcapSetInteger,
        pcap_set_immediate_mode: PcapSetInteger,
        pcap_activate: PcapActivate,
        pcap_datalink: PcapDatalink,
        pcap_next_ex: PcapNextEx,
        pcap_sendpacket: PcapSendPacket,
        pcap_stats: PcapStats,
        pcap_breakloop: PcapBreakLoop,
        pcap_geterr: PcapGetError,
        pcap_close: PcapClose,
    }

    impl NpcapApi {
        fn load() -> Result<Self, LiveIoError> {
            let path = npcap_library_path()?;
            // SAFETY: the path is obtained from the operating system rather
            // than process environment, and the flags restrict dependent DLL
            // lookup to Npcap's directory plus System32.
            let library = unsafe {
                Library::load_with_flags(
                    &path,
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            }
            .map_err(|error| LiveIoError::MissingDependency {
                dependency: NPCAP_DEPENDENCY,
                message: format!(
                    "could not load {}: {error}; install Npcap 1.88 for all users and restart PacketcraftR",
                    path.display()
                ),
            })?;

            // SAFETY: every requested symbol and function signature is copied
            // directly from the pinned Npcap SDK 1.16 pcap.h ABI.
            let pcap_init = unsafe { load_symbol::<PcapInit>(&library, b"pcap_init\0")? };
            // SAFETY: see the ABI note above.
            let pcap_create = unsafe { load_symbol::<PcapCreate>(&library, b"pcap_create\0")? };
            // SAFETY: see the ABI note above.
            let pcap_set_snaplen =
                unsafe { load_symbol::<PcapSetInteger>(&library, b"pcap_set_snaplen\0")? };
            // SAFETY: see the ABI note above.
            let pcap_set_promisc =
                unsafe { load_symbol::<PcapSetInteger>(&library, b"pcap_set_promisc\0")? };
            // SAFETY: see the ABI note above.
            let pcap_set_timeout =
                unsafe { load_symbol::<PcapSetInteger>(&library, b"pcap_set_timeout\0")? };
            // SAFETY: see the ABI note above.
            let pcap_set_immediate_mode =
                unsafe { load_symbol::<PcapSetInteger>(&library, b"pcap_set_immediate_mode\0")? };
            // SAFETY: see the ABI note above.
            let pcap_activate =
                unsafe { load_symbol::<PcapActivate>(&library, b"pcap_activate\0")? };
            // SAFETY: see the ABI note above.
            let pcap_datalink =
                unsafe { load_symbol::<PcapDatalink>(&library, b"pcap_datalink\0")? };
            // SAFETY: see the ABI note above.
            let pcap_next_ex = unsafe { load_symbol::<PcapNextEx>(&library, b"pcap_next_ex\0")? };
            // SAFETY: see the ABI note above.
            let pcap_sendpacket =
                unsafe { load_symbol::<PcapSendPacket>(&library, b"pcap_sendpacket\0")? };
            // SAFETY: see the ABI note above.
            let pcap_stats = unsafe { load_symbol::<PcapStats>(&library, b"pcap_stats\0")? };
            // SAFETY: see the ABI note above.
            let pcap_breakloop =
                unsafe { load_symbol::<PcapBreakLoop>(&library, b"pcap_breakloop\0")? };
            // SAFETY: see the ABI note above.
            let pcap_geterr = unsafe { load_symbol::<PcapGetError>(&library, b"pcap_geterr\0")? };
            // SAFETY: see the ABI note above.
            let pcap_close = unsafe { load_symbol::<PcapClose>(&library, b"pcap_close\0")? };

            let mut error_buffer = [0 as c_char; PCAP_ERROR_BUFFER_SIZE];
            // SAFETY: the function pointer came from the pinned DLL and the
            // writable error buffer has PCAP_ERRBUF_SIZE bytes.
            let initialization =
                unsafe { pcap_init(PCAP_CHAR_ENC_UTF_8, error_buffer.as_mut_ptr()) };
            if initialization != 0 {
                return Err(LiveIoError::MissingDependency {
                    dependency: NPCAP_DEPENDENCY,
                    message: format!(
                        "pcap_init rejected UTF-8 mode: {}",
                        error_buffer_message(&error_buffer)
                    ),
                });
            }

            Ok(Self {
                _library: library,
                pcap_create,
                pcap_set_snaplen,
                pcap_set_promisc,
                pcap_set_timeout,
                pcap_set_immediate_mode,
                pcap_activate,
                pcap_datalink,
                pcap_next_ex,
                pcap_sendpacket,
                pcap_stats,
                pcap_breakloop,
                pcap_geterr,
                pcap_close,
            })
        }
    }

    struct NpcapHandle {
        api: Arc<NpcapApi>,
        raw: NonNull<c_void>,
    }

    // SAFETY: a handle is read only by its owning capture worker. The only
    // concurrent operation is pcap_breakloop, which libpcap explicitly allows
    // from another thread. Session shutdown joins the worker before the final
    // Arc is dropped, so pcap_close never races an active handle operation.
    unsafe impl Send for NpcapHandle {}
    // SAFETY: see the Send invariant above; shared access is limited to the
    // documented pcap_breakloop interrupt path.
    unsafe impl Sync for NpcapHandle {}

    impl NpcapHandle {
        fn error_message(&self) -> String {
            // SAFETY: the handle remains live through self's Arc owner and the
            // function pointer belongs to the equally live API module.
            let message = unsafe { (self.api.pcap_geterr)(self.raw.as_ptr()) };
            if message.is_null() {
                return "Npcap returned no diagnostic".to_owned();
            }
            // SAFETY: pcap_geterr returns a NUL-terminated string owned by the
            // live handle; it is copied before any subsequent handle call.
            unsafe { CStr::from_ptr(message) }
                .to_string_lossy()
                .into_owned()
        }
    }

    impl Drop for NpcapHandle {
        fn drop(&mut self) {
            // SAFETY: this is the last Arc owner, capture work has already
            // joined, and pcap_close consumes exactly this live handle once.
            unsafe { (self.api.pcap_close)(self.raw.as_ptr()) };
        }
    }

    pub(super) fn open_capture(
        interface: &InterfaceId,
        limits: CaptureQueueLimits,
    ) -> Result<NativeCaptureParts, LiveIoError> {
        let snap_length = c_int::try_from(limits.snap_length).map_err(|_| {
            LiveIoError::InvalidCaptureQueueLimit {
                field: "snap_length",
                value: limits.snap_length,
                reason: "Npcap snap length exceeds i32",
            }
        })?;
        let handle = open_handle(interface, snap_length, true)?;
        // SAFETY: handle is activated and live; pcap_datalink only reads its
        // negotiated link-layer type.
        let datalink = unsafe { (handle.api.pcap_datalink)(handle.raw.as_ptr()) };
        if datalink < 0 {
            return Err(LiveIoError::Capture {
                message: format!(
                    "Npcap could not report the data-link type for {}: {}",
                    interface.name,
                    handle.error_message()
                ),
            });
        }
        let link_type = LinkType(datalink as u32);
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

    pub(super) fn send_layer2(frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
        let interface = &frame.route().plan.route.interface;
        let length = c_int::try_from(frame.bytes().len()).map_err(|_| LiveIoError::Send {
            message: format!(
                "Layer 2 frame for {} exceeds Npcap's signed 32-bit send length",
                interface.name
            ),
        })?;
        let handle = open_handle(interface, SEND_SNAPSHOT_LENGTH, false)?;
        // SAFETY: the byte slice remains valid for the synchronous call and
        // length is its exact checked c_int representation.
        let result = unsafe {
            (handle.api.pcap_sendpacket)(handle.raw.as_ptr(), frame.bytes().as_ptr(), length)
        };
        if result != 0 {
            let message = handle.error_message();
            let lower = message.to_ascii_lowercase();
            if is_permission_message(&lower) {
                return Err(LiveIoError::Privilege {
                    message: format!(
                        "cannot inject on {} through Npcap: {message}; run with packet capture privileges",
                        interface.name
                    ),
                });
            }
            return Err(LiveIoError::Send {
                message: format!(
                    "Npcap injection on {} failed with status {result}: {message}",
                    interface.name
                ),
            });
        }
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }

    struct NpcapCaptureSource {
        handle: Arc<NpcapHandle>,
        snap_length: usize,
    }

    impl NativeCaptureSource for NpcapCaptureSource {
        fn next_event(&mut self) -> Result<NativeCaptureEvent, LiveIoError> {
            let mut header = std::ptr::null_mut();
            let mut data = std::ptr::null();
            // SAFETY: header/data are writable out-pointers and the worker is
            // the sole reader of this live handle.
            let result = unsafe {
                (self.handle.api.pcap_next_ex)(self.handle.raw.as_ptr(), &mut header, &mut data)
            };
            match result {
                1 => {
                    let header = NonNull::new(header).ok_or_else(|| LiveIoError::Capture {
                        message: "Npcap returned a packet without a header".to_owned(),
                    })?;
                    // SAFETY: a successful pcap_next_ex result guarantees the
                    // header remains valid until the next handle operation; we
                    // copy the fixed-size value immediately.
                    let header = unsafe { *header.as_ptr() };
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
                        timestamp: system_time(
                            header.timestamp.tv_sec as i64,
                            header.timestamp.tv_usec as i64,
                        )?,
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
            // SAFETY: the SDK-sized output structure is writable and the
            // worker exclusively operates this live capture handle.
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
                dropped: statistics.dropped,
                network_dropped: statistics.network_dropped,
                interface_dropped: statistics.interface_dropped,
            })
        }
    }

    struct NpcapInterrupt(Arc<NpcapHandle>);

    impl CaptureInterrupt for NpcapInterrupt {
        fn interrupt(&self) {
            // SAFETY: libpcap documents pcap_breakloop as callable from a
            // different thread; the Arc keeps the handle live for this call.
            unsafe { (self.0.api.pcap_breakloop)(self.0.raw.as_ptr()) };
        }
    }

    fn open_handle(
        interface: &InterfaceId,
        snap_length: c_int,
        promiscuous: bool,
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
            c_int::from(promiscuous),
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
        // SAFETY: all pre-activation options are complete and this handle has
        // not previously been activated.
        let activation = unsafe { (handle.api.pcap_activate)(handle.raw.as_ptr()) };
        if activation != 0 {
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
        // SAFETY: every supplied function is a pcap_set_* operation with this
        // exact ABI and the handle has not yet been activated.
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

    fn map_activation_error(
        interface: &InterfaceId,
        status: c_int,
        message: String,
    ) -> LiveIoError {
        match status {
            PCAP_ERROR_PERM_DENIED | PCAP_ERROR_PROMISC_PERM_DENIED => LiveIoError::Privilege {
                message: format!(
                    "cannot open {} through Npcap: {message}; grant capture privileges or run elevated",
                    interface.name
                ),
            },
            PCAP_ERROR_NO_SUCH_DEVICE | PCAP_ERROR_IFACE_NOT_UP => LiveIoError::Device {
                interface: interface.name.clone(),
                message: format!("Npcap activation failed with status {status}: {message}"),
            },
            PCAP_ERROR_RFMON_NOTSUP | PCAP_ERROR_CAPTURE_NOTSUP => LiveIoError::Unsupported {
                message: format!(
                    "Npcap does not support capture on {} (status {status}): {message}",
                    interface.name
                ),
            },
            _ => LiveIoError::Capture {
                message: format!(
                    "Npcap activation failed for {} with status {status}: {message}",
                    interface.name
                ),
            },
        }
    }

    fn map_open_message(interface: &InterfaceId, message: String) -> LiveIoError {
        let lower = message.to_ascii_lowercase();
        if is_permission_message(&lower) {
            return LiveIoError::Privilege {
                message: format!(
                    "cannot open {} through Npcap: {message}; grant capture privileges or run elevated",
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
                message: format!("Npcap could not open this interface: {message}"),
            };
        }
        LiveIoError::Capture {
            message: format!("could not open {} through Npcap: {message}", interface.name),
        }
    }

    fn is_permission_message(message: &str) -> bool {
        message.contains("permission denied")
            || message.contains("access is denied")
            || message.contains("not permitted")
            || message.contains("administrator")
    }

    fn npcap_api() -> Result<Arc<NpcapApi>, LiveIoError> {
        static API: OnceLock<Result<Arc<NpcapApi>, LiveIoError>> = OnceLock::new();
        API.get_or_init(|| NpcapApi::load().map(Arc::new)).clone()
    }

    fn npcap_device_name(interface: &InterfaceId) -> Result<String, LiveIoError> {
        let mut luid = NET_LUID_LH::default();
        // SAFETY: luid is writable and the interface index is a plain value.
        let index_result = unsafe { ConvertInterfaceIndexToLuid(interface.index, &mut luid) };
        if index_result != NO_ERROR {
            return Err(interface_conversion_error(
                interface,
                "ConvertInterfaceIndexToLuid",
                index_result.0,
            ));
        }
        let mut guid = GUID::zeroed();
        // SAFETY: luid was initialized by IP Helper and guid is writable.
        let guid_result = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
        if guid_result != NO_ERROR {
            return Err(interface_conversion_error(
                interface,
                "ConvertInterfaceLuidToGuid",
                guid_result.0,
            ));
        }
        Ok(format_npcap_device(guid))
    }

    fn format_npcap_device(guid: GUID) -> String {
        format!(r"\Device\NPF_{{{guid:?}}}")
    }

    fn interface_conversion_error(
        interface: &InterfaceId,
        operation: &'static str,
        code: u32,
    ) -> LiveIoError {
        LiveIoError::Device {
            interface: interface.name.clone(),
            message: format!(
                "{operation} rejected interface index {}: {} (Win32 error {code})",
                interface.index,
                std::io::Error::from_raw_os_error(code as i32)
            ),
        }
    }

    fn npcap_library_path() -> Result<PathBuf, LiveIoError> {
        // Windows paths can be up to 32,767 UTF-16 code units. A fixed maximum
        // buffer avoids trusting mutable environment variables for DLL lookup.
        let mut windows_directory = vec![0_u16; 32_768];
        // SAFETY: the entire mutable UTF-16 buffer is provided to the system
        // API, which returns the number of initialized code units.
        let length = unsafe { GetSystemWindowsDirectoryW(Some(&mut windows_directory)) } as usize;
        if length == 0 || length >= windows_directory.len() {
            return Err(LiveIoError::MissingDependency {
                dependency: NPCAP_DEPENDENCY,
                message: "Windows did not return a valid system directory for secure DLL lookup"
                    .to_owned(),
            });
        }
        windows_directory.truncate(length);
        let mut path = PathBuf::from(OsString::from_wide(&windows_directory));
        path.push("System32");
        path.push("Npcap");
        path.push("wpcap.dll");
        Ok(path)
    }

    fn error_buffer_message(buffer: &[c_char; PCAP_ERROR_BUFFER_SIZE]) -> String {
        // Decode only within PCAP_ERRBUF_SIZE even if an incompatible runtime
        // fails to terminate its diagnostic.
        let bytes: Vec<u8> = buffer
            .iter()
            .copied()
            .take_while(|character| *character != 0)
            .map(|character| character as u8)
            .collect();
        let message = String::from_utf8_lossy(&bytes).into_owned();
        if message.is_empty() {
            "Npcap returned no diagnostic".to_owned()
        } else {
            message
        }
    }

    unsafe fn load_symbol<T: Copy>(
        library: &Library,
        name: &'static [u8],
    ) -> Result<T, LiveIoError> {
        // SAFETY: the caller supplies the exact SDK signature associated with
        // this NUL-terminated export name; the Library owner outlives T.
        unsafe { library.get::<T>(name) }
            .map(|symbol| *symbol)
            .map_err(|error| LiveIoError::MissingDependency {
                dependency: NPCAP_DEPENDENCY,
                message: format!(
                    "required SDK 1.16 symbol {} is unavailable: {error}",
                    String::from_utf8_lossy(&name[..name.len().saturating_sub(1)])
                ),
            })
    }

    #[cfg(test)]
    mod tests {
        use std::mem::size_of;

        use super::*;

        #[test]
        fn pinned_sdk_layouts_match_windows_x64_abi() {
            assert_eq!(size_of::<PcapTimeval>(), 8);
            assert_eq!(size_of::<PcapPacketHeader>(), 16);
            assert_eq!(size_of::<PcapStatistics>(), 24);
        }

        #[test]
        fn npcap_device_uses_ip_helper_guid_syntax() {
            let guid = GUID::from_values(
                0x1234_5678,
                0x9abc,
                0xdef0,
                [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
            );
            assert_eq!(
                format_npcap_device(guid),
                r"\Device\NPF_{12345678-9ABC-DEF0-1234-56789ABCDEF0}"
            );
        }

        #[test]
        fn activation_errors_preserve_actionable_categories() {
            let interface = InterfaceId {
                name: "Ethernet".to_owned(),
                index: 7,
            };
            assert!(matches!(
                map_activation_error(&interface, PCAP_ERROR_PERM_DENIED, "denied".to_owned()),
                LiveIoError::Privilege { .. }
            ));
            assert!(matches!(
                map_activation_error(&interface, PCAP_ERROR_NO_SUCH_DEVICE, "missing".to_owned()),
                LiveIoError::Device { .. }
            ));
            assert!(matches!(
                map_activation_error(
                    &interface,
                    PCAP_ERROR_CAPTURE_NOTSUP,
                    "unsupported".to_owned()
                ),
                LiveIoError::Unsupported { .. }
            ));
        }
    }
}

pub(super) fn open_capture(
    interface: &InterfaceId,
    limits: CaptureQueueLimits,
) -> Result<NativeCaptureParts, LiveIoError> {
    #[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
    {
        supported::open_capture(interface, limits)
    }
    #[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
    {
        let _ = (interface, limits);
        Err(LiveIoError::Unsupported {
            message: "native Windows Layer 2 I/O supports only x86_64-pc-windows-msvc".to_owned(),
        })
    }
}

pub(super) fn send_layer2(frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    #[cfg(all(target_arch = "x86_64", target_env = "msvc"))]
    {
        supported::send_layer2(frame)
    }
    #[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
    {
        let _ = frame;
        Err(LiveIoError::Unsupported {
            message: "native Windows Layer 2 I/O supports only x86_64-pc-windows-msvc".to_owned(),
        })
    }
}
