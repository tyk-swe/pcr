// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! libpcap-backed capture session creation and frame stream.

#![allow(unsafe_code)]

use std::{
    ffi::{CStr, c_char, c_int, c_void},
    ptr::null_mut,
    sync::Arc,
    time::{Instant, SystemTime},
};

use bytes::Bytes;
use pcap::{Active, Capture, Error as PcapError};

use super::bpf::install_capture_filter;
use crate::{
    Error,
    capture::live::{
        CaptureInterrupt, NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource,
        NativeCaptureStatistics, NativeCapturedPacket, monotonic_packet_time, system_time,
    },
    capture::{
        Limits, MAX_TIMESTAMP_TYPES, Metadata, NativeSettings, TimestampPrecision, TimestampType,
    },
    interface::Id as InterfaceId,
    platform::layer2::pcap_common::{
        canonical_link_type, check_setting_status, is_missing_device, is_permission_denied,
        realize_settings, timestamp_precision_value, timestamp_source_of_value,
        timestamp_source_value, validate_effective_snapshot_length,
    },
};
pub(super) const READ_TIMEOUT_MILLIS: i32 = 50;
const PCAP_NETMASK_UNKNOWN: u32 = u32::MAX;

// The locked pcap crate calls pcap_set_* through private raw bindings that
// discard the status code, so the settings this file must accept or reject
// are invoked on the real libpcap symbols directly.
#[link(name = "pcap")]
unsafe extern "C" {
    fn pcap_snapshot(handle: *mut c_void) -> c_int;
    fn pcap_set_buffer_size(handle: *mut c_void, size: c_int) -> c_int;
    fn pcap_set_tstamp_type(handle: *mut c_void, ttype: c_int) -> c_int;
    fn pcap_set_tstamp_precision(handle: *mut c_void, precision: c_int) -> c_int;
    fn pcap_get_tstamp_precision(handle: *mut c_void) -> c_int;
    fn pcap_list_tstamp_types(handle: *mut c_void, types: *mut *mut c_int) -> c_int;
    fn pcap_free_tstamp_types(types: *mut c_int);
    fn pcap_tstamp_type_val_to_name(ttype: c_int) -> *const c_char;
    fn pcap_tstamp_type_val_to_description(ttype: c_int) -> *const c_char;
    fn pcap_geterr(handle: *mut c_void) -> *mut c_char;
}

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
            reason: "libpcap snap length exceeds i32",
        })?;
    let inactive = Capture::from_device(interface.name.as_str())
        .map_err(|error| map_open_error(interface, error))?
        .snaplen(snap_length)
        .promisc(promiscuous)
        .timeout(READ_TIMEOUT_MILLIS)
        .immediate_mode(true);
    apply_native_settings(interface, inactive.as_ptr().cast(), native)?;
    let mut capture = inactive
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
    let link_type = u32::try_from(datalink)
        .map(canonical_link_type)
        .map_err(|_| Error::Unsupported {
            message: format!(
                "libpcap returned negative data-link type {datalink} for {}",
                interface.name
            ),
            source: None,
        })?;
    // SAFETY: capture is activated and remains live and immutably borrowed for
    // this query; pcap_snapshot only reads its configured snapshot length.
    let reported_snap_length = unsafe { pcap_snapshot(capture.as_ptr().cast()) };
    let snap_length = validate_effective_snapshot_length(
        "libpcap",
        interface,
        limits.snap_length,
        reported_snap_length,
    )?;
    // SAFETY: capture is activated and remains live for this query;
    // pcap_get_tstamp_precision only reads the negotiated precision.
    let reported_precision = unsafe { pcap_get_tstamp_precision(capture.as_ptr().cast()) };
    let (native, timestamp_precision) = realize_settings(
        "libpcap",
        interface,
        native,
        (reported_precision >= 0).then_some(reported_precision),
    )?;
    let interrupt = Arc::new(PcapInterrupt(capture.breakloop_handle()));
    Ok(NativeCaptureParts {
        source: Box::new(PcapCaptureSource {
            capture,
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

/// Applies every requested setting on the inactive handle. Any rejection is
/// returned before activation, so no applied setting is ever silently absent
/// from the session.
fn apply_native_settings(
    interface: &InterfaceId,
    handle: *mut c_void,
    settings: &NativeSettings,
) -> Result<(), Error> {
    if let Some(buffer_size) = settings.buffer_size {
        let size = c_int::try_from(buffer_size).map_err(|_| Error::InvalidCaptureSetting {
            field: "buffer_size",
            message: format!(
                "exceeds the native maximum of {} bytes",
                crate::capture::MAX_NATIVE_BUFFER_SIZE
            ),
        })?;
        // SAFETY: handle is a live inactive capture configured by this thread.
        let status = unsafe { pcap_set_buffer_size(handle, size) };
        check_setting_status(
            "libpcap",
            interface,
            "pcap_set_buffer_size",
            "buffer_size",
            &buffer_size.to_string(),
            status,
            &inactive_error_message(handle),
        )?;
    }
    if let Some(source) = settings.timestamp_source {
        let value = timestamp_source_value(source);
        // SAFETY: handle is a live inactive capture configured by this thread.
        let status = unsafe { pcap_set_tstamp_type(handle, value) };
        check_setting_status(
            "libpcap",
            interface,
            "pcap_set_tstamp_type",
            "timestamp_source",
            source.as_str(),
            status,
            &inactive_error_message(handle),
        )?;
    }
    if let Some(precision) = settings.timestamp_precision {
        let value = timestamp_precision_value(precision);
        // SAFETY: handle is a live inactive capture configured by this thread.
        let status = unsafe { pcap_set_tstamp_precision(handle, value) };
        check_setting_status(
            "libpcap",
            interface,
            "pcap_set_tstamp_precision",
            "timestamp_precision",
            precision.as_str(),
            status,
            &inactive_error_message(handle),
        )?;
    }
    Ok(())
}

/// The timestamp types libpcap advertises for this interface, read from a
/// created-but-not-activated handle; no worker or activated device is left
/// behind on failure.
pub(in crate::platform) fn timestamp_types(
    interface: &InterfaceId,
) -> Result<Vec<TimestampType>, Error> {
    let capture = Capture::from_device(interface.name.as_str())
        .map_err(|error| map_open_error(interface, error))?;
    let handle = capture.as_ptr().cast::<c_void>();
    let mut list: *mut c_int = null_mut();
    // SAFETY: handle is a live inactive capture; libpcap fills the writable
    // out-pointer with an allocation pcap_free_tstamp_types owns.
    let count = unsafe { pcap_list_tstamp_types(handle, &mut list) };
    if count < 0 {
        return Err(Error::Capture {
            message: format!(
                "libpcap could not enumerate timestamp types for {}: {}",
                interface.name,
                inactive_error_message(handle)
            ),
            source: None,
        });
    }
    // A zero count means only the default timestamp type is supported;
    // libpcap returns no allocation, so the null list must not become a slice.
    if count == 0 {
        return Ok(Vec::new());
    }
    let count = usize::try_from(count).unwrap_or(0);
    if count > MAX_TIMESTAMP_TYPES {
        // SAFETY: list is a live libpcap allocation released exactly once.
        unsafe { pcap_free_tstamp_types(list) };
        return Err(Error::Capture {
            message: format!(
                "libpcap reported {count} timestamp types for {}, above the {MAX_TIMESTAMP_TYPES} bound",
                interface.name
            ),
            source: None,
        });
    }
    // SAFETY: list points to `count` consecutive c_int values libpcap owns;
    // they are copied out before the single pcap_free_tstamp_types call.
    let values = unsafe { std::slice::from_raw_parts(list, count) }.to_vec();
    // SAFETY: list is the unchanged libpcap allocation from above.
    unsafe { pcap_free_tstamp_types(list) };
    Ok(values
        .into_iter()
        .map(|value| {
            // SAFETY: both functions return a static NUL-terminated string or
            // NULL; any text is copied before the next call.
            let name = unsafe { tstamp_type_string(pcap_tstamp_type_val_to_name(value)) };
            // SAFETY: same contract as the name lookup.
            let description =
                unsafe { tstamp_type_string(pcap_tstamp_type_val_to_description(value)) };
            TimestampType {
                value,
                name,
                description,
                source: timestamp_source_of_value(value),
            }
        })
        .collect())
}

/// Copies a static libpcap string, returning `None` for a NULL or empty one.
unsafe fn tstamp_type_string(raw: *const c_char) -> Option<String> {
    if raw.is_null() {
        return None;
    }
    // SAFETY: `raw` is NULL-checked above and points to a NUL-terminated
    // string libpcap owns statically; the copy happens inside this call.
    let value = unsafe { CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    (!value.is_empty()).then_some(value)
}

fn inactive_error_message(handle: *mut c_void) -> String {
    // SAFETY: handle is a live inactive capture whose error buffer is a
    // NUL-terminated string copied out before returning.
    let message = unsafe { pcap_geterr(handle) };
    if message.is_null() {
        return "libpcap returned no diagnostic".to_owned();
    }
    // SAFETY: see the call above.
    unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned()
}

struct PcapCaptureSource {
    capture: Capture<Active>,
    snap_length: usize,
    /// The fraction unit the backend delivers in `ts.tv_usec`; never assumed.
    timestamp_precision: TimestampPrecision,
}

impl NativeCaptureSource for PcapCaptureSource {
    fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
        match self.capture.next_packet() {
            Ok(packet) => {
                // Monotonic first makes the paired-clock sampling skew conservative.
                let observed_at = Instant::now();
                let observed_wall = SystemTime::now();
                #[cfg(target_os = "linux")]
                let timestamp = system_time(
                    packet.header.ts.tv_sec,
                    packet.header.ts.tv_usec,
                    self.timestamp_precision,
                )?;
                #[cfg(target_os = "macos")]
                let timestamp = system_time(
                    packet.header.ts.tv_sec,
                    i64::from(packet.header.ts.tv_usec),
                    self.timestamp_precision,
                )?;
                let received_at = monotonic_packet_time(timestamp, observed_wall, observed_at);
                if packet.data.len() > self.snap_length {
                    return Err(Error::Capture {
                        message: format!(
                            "libpcap returned {} bytes beyond configured snap length {}",
                            packet.data.len(),
                            self.snap_length
                        ),
                        source: None,
                    });
                }
                if packet.data.len() != packet.header.caplen as usize {
                    return Err(Error::Capture {
                        message: format!(
                            "libpcap packet data contains {} bytes but declares captured length {}",
                            packet.data.len(),
                            packet.header.caplen
                        ),
                        source: None,
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
            Err(error) => Err(Error::Capture {
                message: "libpcap receive failed".to_owned(),
                source: Some(Arc::new(error)),
            }),
        }
    }

    fn statistics(&mut self) -> Result<NativeCaptureStatistics, Error> {
        self.capture
            .stats()
            .map(|statistics| NativeCaptureStatistics {
                capture_dropped_frames: statistics.dropped,
                network_dropped_frames: 0,
                interface_dropped_frames: statistics.if_dropped,
            })
            .map_err(|error| Error::Capture {
                message: "libpcap statistics failed".to_owned(),
                source: Some(Arc::new(error)),
            })
    }
}

struct PcapInterrupt(pcap::BreakLoop);

impl CaptureInterrupt for PcapInterrupt {
    fn interrupt(&self) {
        self.0.breakloop();
    }
}

pub(super) fn map_open_error(interface: &InterfaceId, error: PcapError) -> Error {
    let message = error.to_string();
    let source: Option<crate::SystemFault> = Some(Arc::new(error));
    if is_permission_denied(&message) {
        return Error::Privilege {
            message: format!(
                "cannot open {} through libpcap; grant capture privileges (for example CAP_NET_RAW on Linux or BPF access on macOS)",
                interface.name
            ),
            source,
        };
    }
    if is_missing_device(&message) {
        return Error::Device {
            interface: interface.name.clone(),
            message: "libpcap could not open this interface".to_owned(),
            source,
        };
    }
    Error::Capture {
        message: format!("could not open {} through libpcap", interface.name),
        source,
    }
}
