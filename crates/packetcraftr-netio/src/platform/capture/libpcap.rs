// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(unsafe_code)]

mod bpf;

use packetcraftr_core::clock::{Clock, SystemClock};
use std::{
    ffi::{CStr, c_char, c_int, c_void},
    ptr::null_mut,
    sync::Arc,
};

use bytes::Bytes;
use pcap::{Active, Capture, Error as PcapError};

use self::bpf::install_capture_filter;
use crate::{
    Error, NativeCapability, Unsupported,
    capture::live::{
        CaptureInterrupt, NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource,
        NativeCaptureStats, NativeCapturedPacket, monotonic_packet_time, system_time,
    },
    capture::{Limits, Metadata, NativeSettings, TimestampPrecision, TimestampType},
    interface::Id as InterfaceId,
    platform::common::READ_TIMEOUT_MILLIS,
    platform::common::libpcap::map_open_error,
    platform::common::pcap_api::{
        canonical_link_type, check_setting_status, realize_settings, timestamp_precision_value,
        timestamp_source_of_value, timestamp_source_value, timestamp_type_list, tstamp_type_string,
        validate_effective_snapshot_length,
    },
};
use packetcraftr_core::error::Source;
const PCAP_NETMASK_UNKNOWN: u32 = u32::MAX;

// The pcap crate's pcap_set_* bindings discard the status, so these call libpcap directly.
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

pub(crate) fn open_capture(
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
        .map_err(|_| {
            Unsupported::new(
                NativeCapability::Capture,
                format!(
                    "libpcap returned negative data-link type {datalink} for {}",
                    interface.name
                ),
            )
        })?;
    // SAFETY: capture is activated and borrowed; pcap_snapshot only reads its snapshot length.
    let reported_snap_length = unsafe { pcap_snapshot(capture.as_ptr().cast()) };
    let snap_length = validate_effective_snapshot_length(
        "libpcap",
        interface,
        limits.snap_length,
        reported_snap_length,
    )?;
    // SAFETY: capture is activated and live; pcap_get_tstamp_precision only reads the precision.
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

pub(crate) fn timestamp_types(interface: &InterfaceId) -> Result<Vec<TimestampType>, Error> {
    let capture = Capture::from_device(interface.name.as_str())
        .map_err(|error| map_open_error(interface, error))?;
    let handle = capture.as_ptr().cast::<c_void>();
    let mut list: *mut c_int = null_mut();
    // SAFETY: handle is a live inactive capture; libpcap fills the writable
    // out-pointer with an allocation pcap_free_tstamp_types owns.
    let count = unsafe { pcap_list_tstamp_types(handle, &mut list) };
    let values = timestamp_type_list(
        "libpcap",
        interface,
        count,
        || inactive_error_message(handle),
        // SAFETY: list is the unchanged libpcap allocation, released exactly once.
        || unsafe { pcap_free_tstamp_types(list) },
        // SAFETY: list points to `count` consecutive c_int values libpcap owns.
        |count| unsafe { std::slice::from_raw_parts(list, count) }.to_vec(),
    )?;
    Ok(values
        .into_iter()
        .map(|value| {
            // SAFETY: both functions return a static NUL-terminated string or NULL, copied at once.
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
    timestamp_precision: TimestampPrecision,
}

impl NativeCaptureSource for PcapCaptureSource {
    fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
        match self.capture.next_packet() {
            Ok(packet) => {
                // Monotonic first makes the paired-clock sampling skew conservative.
                let observed_at = SystemClock.now();
                let observed_wall = SystemClock.wall_now();
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
                source: Some(Source::new(error)),
            }),
        }
    }

    fn stats(&mut self) -> Result<NativeCaptureStats, Error> {
        self.capture
            .stats()
            .map(|statistics| NativeCaptureStats {
                capture_dropped_frames: statistics.dropped,
                network_dropped_frames: 0,
                interface_dropped_frames: statistics.if_dropped,
            })
            .map_err(|error| Error::Capture {
                message: "libpcap statistics failed".to_owned(),
                source: Some(Source::new(error)),
            })
    }
}

struct PcapInterrupt(pcap::BreakLoop);

impl CaptureInterrupt for PcapInterrupt {
    fn interrupt(&self) {
        self.0.breakloop();
    }
}
