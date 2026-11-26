// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    ptr::{NonNull, null_mut},
    sync::Arc,
};

use packetcraftr_core::clock::{Clock, SystemClock};

use super::super::READ_TIMEOUT_MILLIS;
use super::{
    abi::{
        PCAP_ERROR, PCAP_ERROR_BREAK, PCAP_ERROR_BUFFER_SIZE, PCAP_WARNING_PROMISC_NOTSUP,
        PcapSetInteger, PcapStatistics,
    },
    error::{error_buffer_message, map_activation_error, map_open_message},
    loader::{NpcapApi, npcap_api, npcap_device_name},
};
use crate::{
    Error,
    capture::{
        NativeSettings, TimestampPrecision, TimestampType,
        live::{NativeCaptureEvent, NativeCaptureStats},
    },
    interface::Id as InterfaceId,
    platform::common::pcap_api::{
        BpfProgram, Diagnostic, NativeSetting, RawPacketHeader, apply_native_settings,
        map_timestamp_types, timestamp_type_list, tstamp_type_string, validate_captured_packet,
    },
};

#[derive(Clone, Copy)]
pub(in crate::platform) enum PromiscuousMode {
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

struct RawNpcapHandle {
    api: Arc<NpcapApi>,
    raw: NonNull<c_void>,
}

impl Drop for RawNpcapHandle {
    #[expect(unsafe_code, reason = "closes the owned pcap_t handle via pcap_close")]
    fn drop(&mut self) {
        // SAFETY: this is the last Arc owner and pcap_close consumes exactly this live handle once.
        unsafe { (self.api.pcap_close)(self.raw.as_ptr()) };
    }
}

/// Exclusive owner of all non-breakloop operations on an Npcap `pcap_t*`.
///
/// `!Sync` and non-`Clone` so `pcap_next_ex`, `pcap_stats`, `pcap_sendpacket`,
/// and `pcap_geterr` can never race across threads.
pub(in crate::platform) struct NpcapHandle {
    inner: Arc<RawNpcapHandle>,
}

#[expect(
    unsafe_code,
    reason = "NpcapHandle transfers exclusive non-breakloop ownership across threads"
)]
// SAFETY: a single NpcapHandle owns all non-breakloop handle operations;
// only NpcapBreakLoop shares the underlying Arc to call thread-safe pcap_breakloop.
unsafe impl Send for NpcapHandle {}

/// Thread-safe handle restricted strictly to `pcap_breakloop`.
pub(in crate::platform) struct NpcapBreakLoop {
    inner: Arc<RawNpcapHandle>,
}

#[expect(
    unsafe_code,
    reason = "NpcapBreakLoop only invokes thread-safe pcap_breakloop"
)]
// SAFETY: NpcapBreakLoop exposes only pcap_breakloop, which libpcap documents
// as callable concurrently from another thread; the Arc keeps the handle alive.
unsafe impl Send for NpcapBreakLoop {}

#[expect(
    unsafe_code,
    reason = "NpcapBreakLoop only invokes thread-safe pcap_breakloop"
)]
// SAFETY: see Send invariant above; shared access is limited exclusively to pcap_breakloop.
unsafe impl Sync for NpcapBreakLoop {}

impl NpcapBreakLoop {
    #[expect(
        unsafe_code,
        reason = "interrupts a blocked capture via pcap_breakloop"
    )]
    pub(in crate::platform) fn breakloop(&self) {
        // SAFETY: libpcap documents pcap_breakloop as callable from a different
        // thread; the Arc keeps the handle live for this call.
        unsafe { (self.inner.api.pcap_breakloop)(self.inner.raw.as_ptr()) };
    }
}

impl NpcapHandle {
    pub(in crate::platform) fn breakloop_handle(&self) -> NpcapBreakLoop {
        NpcapBreakLoop {
            inner: Arc::clone(&self.inner),
        }
    }

    #[expect(unsafe_code, reason = "reads the handle-owned pcap_geterr C string")]
    pub(in crate::platform) fn error_message(&mut self) -> String {
        // SAFETY: `&mut self` grants exclusive access to non-breakloop handle state.
        let message = unsafe { (self.inner.api.pcap_geterr)(self.inner.raw.as_ptr()) };
        if message.is_null() {
            return "Npcap returned no diagnostic".to_owned();
        }
        // SAFETY: pcap_geterr returns a NUL-terminated string owned by the live handle.
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    }

    #[expect(unsafe_code, reason = "reads the activated handle link-layer type")]
    pub(in crate::platform) fn datalink(&mut self) -> c_int {
        // SAFETY: handle is activated and exclusively borrowed by `&mut self`.
        unsafe { (self.inner.api.pcap_datalink)(self.inner.raw.as_ptr()) }
    }

    #[expect(unsafe_code, reason = "reads the activated handle snapshot length")]
    pub(in crate::platform) fn snapshot(&mut self) -> c_int {
        // SAFETY: handle is activated and exclusively borrowed by `&mut self`.
        unsafe { (self.inner.api.pcap_snapshot)(self.inner.raw.as_ptr()) }
    }

    #[expect(unsafe_code, reason = "reads the activated handle timestamp precision")]
    pub(in crate::platform) fn reported_precision(&mut self) -> Option<c_int> {
        // SAFETY: handle is activated and exclusively borrowed by `&mut self`.
        self.inner
            .api
            .pcap_get_tstamp_precision
            .map(|function| unsafe { function(self.inner.raw.as_ptr()) })
            .filter(|value| *value >= 0)
    }

    #[expect(unsafe_code, reason = "enumerates Npcap timestamp types via FFI")]
    pub(in crate::platform) fn list_timestamp_types(
        &mut self,
        interface: &InterfaceId,
    ) -> Result<Vec<TimestampType>, Error> {
        let Some(list_types) = self.inner.api.pcap_list_tstamp_types else {
            return Err(Error::UnsupportedCaptureSetting {
                setting: "timestamp_source",
                interface: interface.name.clone(),
                message: "the loaded Npcap runtime does not export pcap_list_tstamp_types".into(),
            });
        };
        // Only pcap_free_tstamp_types releases the list, so a runtime without it would leak.
        let Some(free) = self.inner.api.pcap_free_tstamp_types else {
            return Err(Error::UnsupportedCaptureSetting {
                setting: "timestamp_source",
                interface: interface.name.clone(),
                message: "the loaded Npcap runtime does not export pcap_free_tstamp_types".into(),
            });
        };
        let mut list: *mut c_int = null_mut();
        // SAFETY: handle is a live unactivated capture owned exclusively by `&mut self`.
        let count = unsafe { list_types(self.inner.raw.as_ptr(), &mut list) };
        let values = timestamp_type_list(
            "Npcap",
            interface,
            count,
            || self.error_message(),
            // SAFETY: list is the unchanged Npcap allocation, released exactly once.
            || unsafe { free(list) },
            // SAFETY: list points to `count` consecutive c_int values Npcap owns.
            |count| unsafe { std::slice::from_raw_parts(list, count) }.to_vec(),
        )?;
        let api = Arc::clone(&self.inner.api);
        Ok(map_timestamp_types(
            values,
            |value| {
                api.pcap_tstamp_type_val_to_name.and_then(|name| {
                    // SAFETY: `name` returns a static NUL-terminated string or NULL, copied at once.
                    unsafe { tstamp_type_string(name(value)) }
                })
            },
            |value| {
                api.pcap_tstamp_type_val_to_description
                    .and_then(|describe| {
                        // SAFETY: same contract as the name lookup.
                        unsafe { tstamp_type_string(describe(value)) }
                    })
            },
        ))
    }

    #[expect(
        unsafe_code,
        reason = "compiles and installs an Npcap BPF filter via FFI"
    )]
    pub(in crate::platform) fn install_capture_filter(
        &mut self,
        interface: &InterfaceId,
        filter: &str,
        netmask: u32,
    ) -> Result<(), Error> {
        let filter = CString::new(filter).map_err(|_| Error::InvalidCaptureFilter {
            interface: interface.name.clone(),
            message: "Npcap BPF expressions cannot contain an interior NUL byte".to_owned(),
        })?;
        let mut program = BpfProgram::empty();
        // SAFETY: handle is activated and exclusively borrowed, program is a writable
        // SDK-layout output, and filter is NUL-terminated.
        let compile_status = unsafe {
            (self.inner.api.pcap_compile)(
                self.inner.raw.as_ptr(),
                &mut program,
                filter.as_ptr(),
                1,
                netmask,
            )
        };
        if compile_status != 0 {
            let diagnostic = self.error_message();
            return Err(Error::InvalidCaptureFilter {
                interface: interface.name.clone(),
                message: format!("Npcap compilation failed: {diagnostic}"),
            });
        }

        // SAFETY: successful pcap_compile initialized program for this live handle.
        let install_status =
            unsafe { (self.inner.api.pcap_setfilter)(self.inner.raw.as_ptr(), &mut program) };
        let diagnostic = (install_status != 0).then(|| self.error_message());
        // SAFETY: pcap_compile succeeded and this is the single matching pcap_freecode call.
        unsafe { (self.inner.api.pcap_freecode)(&mut program) };

        if let Some(diagnostic) = diagnostic {
            return Err(Error::CaptureFilterInstallation {
                interface: interface.name.clone(),
                message: format!("Npcap installation failed: {diagnostic}"),
            });
        }
        Ok(())
    }

    #[expect(unsafe_code, reason = "reads the next packet via pcap_next_ex FFI")]
    pub(in crate::platform) fn next_packet(
        &mut self,
        snap_length: usize,
        timestamp_precision: TimestampPrecision,
    ) -> Result<NativeCaptureEvent, Error> {
        let mut header = null_mut();
        let mut data = std::ptr::null();
        // SAFETY: header/data are writable out-pointers and `&mut self` grants exclusive access.
        let result = unsafe {
            (self.inner.api.pcap_next_ex)(self.inner.raw.as_ptr(), &mut header, &mut data)
        };
        // Monotonic first makes the paired-clock sampling skew conservative.
        let observed_at = SystemClock.now();
        let observed_wall = SystemClock.wall_now();
        match result {
            1 => {
                let header = NonNull::new(header).ok_or_else(|| Error::Capture {
                    message: "Npcap returned a packet without a header".to_owned(),
                    source: None,
                })?;
                // SAFETY: after a successful pcap_next_ex the header stays valid until the next
                // handle operation; the fixed-size value is copied immediately.
                let header = unsafe { *header.as_ptr() };
                let captured_length = header.captured_length as usize;
                if captured_length > snap_length {
                    return Err(Error::Capture {
                        message: format!(
                            "Npcap returned {captured_length} bytes beyond configured snap length {snap_length}"
                        ),
                        source: None,
                    });
                }
                if header.original_length < header.captured_length {
                    return Err(Error::Capture {
                        message: format!(
                            "Npcap returned captured length {} above original length {}",
                            header.captured_length, header.original_length
                        ),
                        source: None,
                    });
                }
                let slice = if captured_length == 0 {
                    &[]
                } else {
                    if data.is_null() {
                        return Err(Error::Capture {
                            message: "Npcap returned packet bytes through a null pointer"
                                .to_owned(),
                            source: None,
                        });
                    }
                    // SAFETY: pcap_next_ex guarantees caplen readable bytes until the next handle call.
                    unsafe { std::slice::from_raw_parts(data, captured_length) }
                };
                let packet = validate_captured_packet(
                    "Npcap",
                    snap_length,
                    timestamp_precision,
                    RawPacketHeader {
                        tv_sec: header.timestamp.tv_sec as i64,
                        tv_usec: header.timestamp.tv_usec as i64,
                        observed_at,
                        observed_wall,
                        captured_length: header.captured_length,
                        original_length: header.original_length,
                    },
                    slice,
                )?;
                Ok(NativeCaptureEvent::Packet(packet))
            }
            0 => Ok(NativeCaptureEvent::Timeout),
            PCAP_ERROR_BREAK => Ok(NativeCaptureEvent::Closed),
            PCAP_ERROR => Err(Error::Capture {
                message: "Npcap receive failed".to_owned(),
                source: Diagnostic::new(Some(PCAP_ERROR), self.error_message()).into_source(),
            }),
            status => Err(Error::Capture {
                message: "Npcap receive returned an unexpected status".to_owned(),
                source: Diagnostic::new(Some(status), self.error_message()).into_source(),
            }),
        }
    }

    #[expect(
        unsafe_code,
        reason = "queries capture drop statistics via pcap_stats FFI"
    )]
    pub(in crate::platform) fn stats(&mut self) -> Result<NativeCaptureStats, Error> {
        let mut statistics = PcapStatistics::default();
        // SAFETY: the SDK-sized output structure is writable and `&mut self` grants exclusive access.
        let result =
            unsafe { (self.inner.api.pcap_stats)(self.inner.raw.as_ptr(), &mut statistics) };
        if result != 0 {
            return Err(Error::Capture {
                message: "Npcap statistics failed".to_owned(),
                source: Diagnostic::new(Some(result), self.error_message()).into_source(),
            });
        }
        Ok(NativeCaptureStats {
            capture_dropped_frames: statistics.dropped,
            network_dropped_frames: statistics.network_dropped,
            interface_dropped_frames: statistics.interface_dropped,
        })
    }

    #[expect(
        unsafe_code,
        reason = "injects a Layer 2 frame via pcap_sendpacket FFI"
    )]
    pub(in crate::platform) fn sendpacket(&mut self, bytes: &[u8], length: c_int) -> c_int {
        debug_assert_eq!(usize::try_from(length), Ok(bytes.len()));
        // SAFETY: the byte slice remains valid for the synchronous call and length is its exact size.
        unsafe { (self.inner.api.pcap_sendpacket)(self.inner.raw.as_ptr(), bytes.as_ptr(), length) }
    }

    #[expect(
        unsafe_code,
        reason = "sets an integer pre-activation option via pcap_set_* FFI"
    )]
    fn set_option(&mut self, function: PcapSetInteger, value: c_int) -> c_int {
        // SAFETY: function is a pcap_set_* operation with this ABI and the handle is not yet activated.
        unsafe { function(self.inner.raw.as_ptr(), value) }
    }

    #[expect(
        unsafe_code,
        reason = "activates an unactivated handle via pcap_activate FFI"
    )]
    fn activate(&mut self) -> c_int {
        // SAFETY: pre-activation options are complete and this handle was never activated.
        unsafe { (self.inner.api.pcap_activate)(self.inner.raw.as_ptr()) }
    }
}

#[expect(unsafe_code, reason = "creates an Npcap handle via pcap_create FFI")]
#[expect(
    clippy::arc_with_non_send_sync,
    reason = "the Arc only shares lifetime, while NpcapHandle and NpcapBreakLoop carry the scoped Send/Sync impls"
)]
pub(in crate::platform) fn create_handle(interface: &InterfaceId) -> Result<NpcapHandle, Error> {
    let api = npcap_api()?;
    let device_name = npcap_device_name(interface)?;
    let device_name = CString::new(device_name).map_err(|_| Error::Device {
        interface: interface.name.clone(),
        message: "Npcap device name contains an embedded NUL byte".to_owned(),
        source: None,
    })?;
    let mut error_buffer = [0 as c_char; PCAP_ERROR_BUFFER_SIZE];
    // SAFETY: both C strings are valid for this synchronous call.
    let raw = unsafe { (api.pcap_create)(device_name.as_ptr(), error_buffer.as_mut_ptr()) };
    let raw = NonNull::new(raw)
        .ok_or_else(|| map_open_message(interface, error_buffer_message(&error_buffer)))?;
    Ok(NpcapHandle {
        inner: Arc::new(RawNpcapHandle { api, raw }),
    })
}

pub(in crate::platform) fn open_handle(
    interface: &InterfaceId,
    snap_length: c_int,
    promiscuous_mode: PromiscuousMode,
    native: &NativeSettings,
) -> Result<NpcapHandle, Error> {
    let mut handle = create_handle(interface)?;
    let api = Arc::clone(&handle.inner.api);

    set_integer_option(
        &mut handle,
        interface,
        "pcap_set_snaplen",
        api.pcap_set_snaplen,
        snap_length,
    )?;
    set_integer_option(
        &mut handle,
        interface,
        "pcap_set_promisc",
        api.pcap_set_promisc,
        promiscuous_mode.pcap_value(),
    )?;
    set_integer_option(
        &mut handle,
        interface,
        "pcap_set_timeout",
        api.pcap_set_timeout,
        READ_TIMEOUT_MILLIS,
    )?;
    set_integer_option(
        &mut handle,
        interface,
        "pcap_set_immediate_mode",
        api.pcap_set_immediate_mode,
        1,
    )?;
    apply_native_settings("Npcap", interface, native, |setting, value| {
        let function = match setting {
            NativeSetting::BufferSize => api.pcap_set_buffer_size,
            NativeSetting::TimestampSource => api.pcap_set_tstamp_type,
            NativeSetting::TimestampPrecision => api.pcap_set_tstamp_precision,
        };
        let Some(function) = function else {
            return Err(Error::UnsupportedCaptureSetting {
                setting: setting.field(),
                interface: interface.name.clone(),
                message: format!(
                    "the loaded Npcap runtime does not export {}",
                    setting.operation()
                )
                .into(),
            });
        };
        let status = handle.set_option(function, value);
        if status == 0 {
            Ok(Ok(()))
        } else {
            Ok(Err((status, handle.error_message())))
        }
    })?;
    let activation = handle.activate();
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
    handle: &mut NpcapHandle,
    interface: &InterfaceId,
    operation: &'static str,
    function: PcapSetInteger,
    value: c_int,
) -> Result<(), Error> {
    let result = handle.set_option(function, value);
    if result == 0 {
        Ok(())
    } else {
        Err(Error::Capture {
            message: format!("{operation} failed for {}", interface.name),
            source: Diagnostic::new(Some(result), handle.error_message()).into_source(),
        })
    }
}
