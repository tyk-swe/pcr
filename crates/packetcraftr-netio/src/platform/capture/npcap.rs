// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Npcap capture source and interrupt lifecycle.

#![allow(unsafe_code)]

use std::{
    ffi::{CStr, CString, c_int},
    ptr::{NonNull, null_mut},
    sync::Arc,
    time::{Instant, SystemTime},
};

use super::{
    abi::{BpfProgram, PCAP_ERROR, PCAP_ERROR_BREAK, PCAP_NETMASK_UNKNOWN, PcapStatistics},
    handles::{NpcapHandle, PromiscuousMode, create_handle, open_handle, reported_precision},
};
use crate::{
    Error,
    capture::live::{
        CaptureInterrupt, NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource,
        NativeCaptureStats, NativeCapturedPacket, monotonic_packet_time, system_time,
    },
    capture::{
        Limits, MAX_TIMESTAMP_TYPES, Metadata, NativeSettings, TimestampPrecision, TimestampType,
    },
    interface::Id as InterfaceId,
    platform::layer2::pcap_common::{
        Diagnostic, canonical_link_type, realize_settings, timestamp_source_of_value,
        validate_effective_snapshot_length,
    },
};
use bytes::Bytes;

pub(in crate::platform) fn open_capture(
    interface: &InterfaceId,
    limits: Limits,
    capture_filter: Option<&str>,
    netmask: Option<u32>,
    promiscuous: bool,
    native: &NativeSettings,
) -> Result<NativeCaptureParts, Error> {
    let snap_length =
        i32::try_from(limits.snap_length).map_err(|_| Error::InvalidCaptureQueueLimit {
            field: "snap_length",
            value: limits.snap_length,
            reason: "Npcap snap length exceeds i32",
        })?;
    let promiscuous_mode = if promiscuous {
        PromiscuousMode::Enabled
    } else {
        PromiscuousMode::Disabled
    };
    let handle = open_handle(interface, snap_length, promiscuous_mode, native)?;
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
    let link_type = u32::try_from(datalink)
        .map(canonical_link_type)
        .map_err(|_| Error::Capture {
            message: format!(
                "Npcap could not report the data-link type for {}",
                interface.name
            ),
            source: Diagnostic::new(Some(datalink), handle.error_message()).into_source(),
        })?;
    // SAFETY: handle is activated and live; pcap_snapshot only reads its
    // effective snapshot length.
    let reported_snap_length = unsafe { (handle.api.pcap_snapshot)(handle.raw.as_ptr()) };
    let snap_length = validate_effective_snapshot_length(
        "Npcap",
        interface,
        limits.snap_length,
        reported_snap_length,
    )?;
    let (native, timestamp_precision) =
        realize_settings("Npcap", interface, native, reported_precision(&handle))?;
    let interrupt = Arc::new(NpcapInterrupt(Arc::clone(&handle)));
    Ok(NativeCaptureParts {
        source: Box::new(NpcapCaptureSource {
            handle,
            snap_length,
            timestamp_precision,
        }),
        interrupt,
        metadata: Metadata {
            interface: interface.clone(),
            link_type,
            snap_length,
            native,
        },
    })
}

/// The timestamp types the loaded Npcap runtime advertises for this
/// interface, read from a created-but-not-activated handle.
pub(in crate::platform) fn timestamp_types(
    interface: &InterfaceId,
) -> Result<Vec<TimestampType>, Error> {
    let handle = create_handle(interface)?;
    let Some(list_types) = handle.api.pcap_list_tstamp_types else {
        return Err(Error::UnsupportedCaptureSetting {
            setting: "timestamp_source",
            interface: interface.name.clone(),
            message: "the loaded Npcap runtime does not export pcap_list_tstamp_types".into(),
        });
    };
    // The list is an allocation only pcap_free_tstamp_types releases, so a
    // runtime without it cannot list types without leaking.
    let Some(free) = handle.api.pcap_free_tstamp_types else {
        return Err(Error::UnsupportedCaptureSetting {
            setting: "timestamp_source",
            interface: interface.name.clone(),
            message: "the loaded Npcap runtime does not export pcap_free_tstamp_types".into(),
        });
    };
    let mut list: *mut c_int = null_mut();
    // SAFETY: handle is a live unactivated capture; Npcap fills the writable
    // out-pointer with an allocation pcap_free_tstamp_types owns.
    let count = unsafe { list_types(handle.raw.as_ptr(), &mut list) };
    if count < 0 {
        return Err(Error::Capture {
            message: format!(
                "Npcap could not enumerate timestamp types for {}",
                interface.name
            ),
            source: Diagnostic::new(Some(count), handle.error_message()).into_source(),
        });
    }
    // A zero count means only the default timestamp type is supported;
    // Npcap returns no allocation, so the null list must not become a slice.
    if count == 0 {
        return Ok(Vec::new());
    }
    let count = usize::try_from(count).unwrap_or(0);
    if count > MAX_TIMESTAMP_TYPES {
        // SAFETY: list is a live Npcap allocation released exactly once.
        unsafe { free(list) };
        return Err(Error::Capture {
            message: format!(
                "Npcap reported {count} timestamp types for {}, above the {MAX_TIMESTAMP_TYPES} bound",
                interface.name
            ),
            source: None,
        });
    }
    // SAFETY: list points to `count` consecutive c_int values Npcap owns;
    // they are copied out before the single pcap_free_tstamp_types call.
    let values = unsafe { std::slice::from_raw_parts(list, count) }.to_vec();
    // SAFETY: list is the unchanged Npcap allocation from above.
    unsafe { free(list) };
    Ok(values
        .into_iter()
        .map(|value| {
            let name = handle.api.pcap_tstamp_type_val_to_name.and_then(|name| {
                // SAFETY: the function returns a static NUL-terminated string
                // or NULL; any text is copied inside this call.
                unsafe { tstamp_type_string(name(value)) }
            });
            let description = handle
                .api
                .pcap_tstamp_type_val_to_description
                .and_then(|describe| {
                    // SAFETY: same contract as the name lookup.
                    unsafe { tstamp_type_string(describe(value)) }
                });
            TimestampType {
                value,
                name,
                description,
                source: timestamp_source_of_value(value),
            }
        })
        .collect())
}

/// Copies a static Npcap string, returning `None` for a NULL or empty one.
unsafe fn tstamp_type_string(raw: *const std::ffi::c_char) -> Option<String> {
    if raw.is_null() {
        return None;
    }
    // SAFETY: `raw` is NULL-checked above and points to a NUL-terminated
    // string Npcap owns statically; the copy happens inside this call.
    let value = unsafe { CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    (!value.is_empty()).then_some(value)
}

fn install_capture_filter(
    handle: &NpcapHandle,
    interface: &InterfaceId,
    filter: &str,
    netmask: u32,
) -> Result<(), Error> {
    let filter = CString::new(filter).map_err(|_| Error::InvalidCaptureFilter {
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
        return Err(Error::InvalidCaptureFilter {
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
        return Err(Error::CaptureFilterInstallation {
            interface: interface.name.clone(),
            message: format!("Npcap installation failed: {diagnostic}"),
        });
    }
    Ok(())
}

struct NpcapCaptureSource {
    handle: Arc<NpcapHandle>,
    snap_length: usize,
    /// The fraction unit the backend delivers in `timestamp.tv_usec`; never
    /// assumed.
    timestamp_precision: TimestampPrecision,
}

impl NativeCaptureSource for NpcapCaptureSource {
    fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
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
                let header = NonNull::new(header).ok_or_else(|| Error::Capture {
                    message: "Npcap returned a packet without a header".to_owned(),
                    source: None,
                })?;
                // SAFETY: a successful pcap_next_ex result guarantees the
                // header remains valid until the next handle operation; we copy
                // the fixed-size value immediately.
                let header = unsafe { *header.as_ptr() };
                let timestamp = system_time(
                    header.timestamp.tv_sec as i64,
                    header.timestamp.tv_usec as i64,
                    self.timestamp_precision,
                )?;
                let received_at = monotonic_packet_time(timestamp, observed_wall, observed_at);
                let captured_length = header.captured_length as usize;
                if captured_length > self.snap_length {
                    return Err(Error::Capture {
                        message: format!(
                            "Npcap returned {captured_length} bytes beyond configured snap length {}",
                            self.snap_length
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
                let bytes = if captured_length == 0 {
                    Bytes::new()
                } else {
                    if data.is_null() {
                        return Err(Error::Capture {
                            message: "Npcap returned packet bytes through a null pointer"
                                .to_owned(),
                            source: None,
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
            PCAP_ERROR => Err(Error::Capture {
                message: "Npcap receive failed".to_owned(),
                source: Diagnostic::new(Some(PCAP_ERROR), self.handle.error_message())
                    .into_source(),
            }),
            status => Err(Error::Capture {
                message: "Npcap receive returned an unexpected status".to_owned(),
                source: Diagnostic::new(Some(status), self.handle.error_message()).into_source(),
            }),
        }
    }

    fn stats(&mut self) -> Result<NativeCaptureStats, Error> {
        let mut statistics = PcapStatistics::default();
        // SAFETY: the SDK-sized output structure is writable and the worker
        // exclusively operates this live capture handle.
        let result =
            unsafe { (self.handle.api.pcap_stats)(self.handle.raw.as_ptr(), &mut statistics) };
        if result != 0 {
            return Err(Error::Capture {
                message: "Npcap statistics failed".to_owned(),
                source: Diagnostic::new(Some(result), self.handle.error_message()).into_source(),
            });
        }
        Ok(NativeCaptureStats {
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
