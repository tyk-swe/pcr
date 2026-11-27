// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod bpf;
#[cfg(any(test, target_os = "macos"))]
mod idle;

use packetcraftr_core::clock::{Clock, SystemClock};
use std::{
    ffi::{c_int, c_void},
    ptr::null_mut,
    sync::Arc,
};

use pcap::{Active, Capture, Error as PcapError};

use self::bpf::install_capture_filter;
use crate::{
    Error, NativeCapability, Unsupported,
    capture::live::{
        NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource, NativeCaptureStats,
    },
    capture::{Limits, Metadata, NativeSettings, TimestampPrecision, TimestampType},
    interface::Id as InterfaceId,
    platform::common::READ_TIMEOUT_MILLIS,
    platform::common::libpcap::{
        map_open_error, pcap_error_message, pcap_free_tstamp_types, pcap_get_tstamp_precision,
        pcap_list_tstamp_types, pcap_set_buffer_size, pcap_set_tstamp_precision,
        pcap_set_tstamp_type, pcap_snapshot, pcap_tstamp_type_val_to_description,
        pcap_tstamp_type_val_to_name,
    },
    platform::common::pcap_api::{
        NativeSetting, PCAP_NETMASK_UNKNOWN, RawPacketHeader, apply_native_settings,
        canonical_link_type, map_timestamp_types, realize_settings, timestamp_type_list,
        tstamp_type_string, validate_captured_packet, validate_effective_snapshot_length,
    },
};
use packetcraftr_core::error::Source;

#[expect(
    unsafe_code,
    reason = "capture settings the pcap crate omits require direct libpcap FFI calls"
)]
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
    let handle = inactive.as_ptr().cast();
    apply_native_settings("libpcap", interface, native, |setting, value| {
        // SAFETY: handle is a live inactive capture configured exclusively by this thread.
        let status = unsafe {
            match setting {
                NativeSetting::BufferSize => pcap_set_buffer_size(handle, value),
                NativeSetting::TimestampSource => pcap_set_tstamp_type(handle, value),
                NativeSetting::TimestampPrecision => pcap_set_tstamp_precision(handle, value),
            }
        };
        if status == 0 {
            Ok(Ok(()))
        } else {
            // SAFETY: handle is exclusively owned by this thread.
            Ok(Err((status, unsafe { pcap_error_message(handle) })))
        }
    })?;
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
    #[cfg(target_os = "macos")]
    let (capture, idle, interrupt) = {
        let capture = capture
            .setnonblock()
            .map_err(|error| map_open_error(interface, error))?;
        // SAFETY: capture is active and owns the returned descriptor until dropped.
        let descriptor = unsafe {
            crate::platform::common::libpcap::pcap_get_selectable_fd(capture.as_ptr().cast())
        };
        let (idle, interrupt) = idle::Wake::pair(descriptor).map_err(|error| Error::Capture {
            message: "could not open a libpcap shutdown wake channel".to_owned(),
            source: Some(Source::new(error)),
        })?;
        (capture, idle, Arc::new(interrupt))
    };
    #[cfg(not(target_os = "macos"))]
    let interrupt = Arc::new(PcapInterrupt(capture.breakloop_handle()));
    Ok(NativeCaptureParts {
        source: Box::new(PcapCaptureSource {
            capture,
            snap_length,
            timestamp_precision,
            #[cfg(target_os = "macos")]
            idle,
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

#[expect(
    unsafe_code,
    reason = "timestamp type discovery calls libpcap FFI functions directly"
)]
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
        // SAFETY: handle is live and exclusively owned by this thread.
        || unsafe { pcap_error_message(handle) },
        // SAFETY: list is the unchanged libpcap allocation, released exactly once.
        || unsafe { pcap_free_tstamp_types(list) },
        // SAFETY: list points to `count` consecutive c_int values libpcap owns.
        |count| unsafe { std::slice::from_raw_parts(list, count) }.to_vec(),
    )?;
    Ok(map_timestamp_types(
        values,
        // SAFETY: returns a static NUL-terminated string or NULL, copied at once.
        |value| unsafe { tstamp_type_string(pcap_tstamp_type_val_to_name(value)) },
        // SAFETY: same contract as the name lookup.
        |value| unsafe { tstamp_type_string(pcap_tstamp_type_val_to_description(value)) },
    ))
}

struct PcapCaptureSource {
    capture: Capture<Active>,
    snap_length: usize,
    timestamp_precision: TimestampPrecision,
    #[cfg(target_os = "macos")]
    idle: idle::Wake,
}

impl NativeCaptureSource for PcapCaptureSource {
    fn initial_drop_baseline(&self, first: NativeCaptureStats) -> NativeCaptureStats {
        NativeCaptureStats {
            capture_dropped_frames: 0,
            ..first
        }
    }

    fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
        match self.capture.next_packet() {
            Ok(packet) => {
                // Monotonic first makes the paired-clock sampling skew conservative.
                let observed_at = SystemClock.now();
                let observed_wall = SystemClock.wall_now();
                #[cfg(target_os = "linux")]
                let tv_usec = packet.header.ts.tv_usec;
                #[cfg(target_os = "macos")]
                let tv_usec = i64::from(packet.header.ts.tv_usec);
                let packet = validate_captured_packet(
                    "libpcap",
                    self.snap_length,
                    self.timestamp_precision,
                    RawPacketHeader {
                        tv_sec: packet.header.ts.tv_sec,
                        tv_usec,
                        observed_at,
                        observed_wall,
                        captured_length: packet.header.caplen,
                        original_length: packet.header.len,
                    },
                    packet.data,
                )?;
                Ok(NativeCaptureEvent::Packet(packet))
            }
            Err(PcapError::TimeoutExpired) => {
                #[cfg(target_os = "macos")]
                if self.idle.wait().map_err(|error| Error::Capture {
                    message: "could not wait for libpcap capture".to_owned(),
                    source: Some(Source::new(error)),
                })? {
                    return Ok(NativeCaptureEvent::Closed);
                }
                Ok(NativeCaptureEvent::Timeout)
            }
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

#[cfg(not(target_os = "macos"))]
struct PcapInterrupt(pcap::BreakLoop);

#[cfg(not(target_os = "macos"))]
impl crate::capture::live::CaptureInterrupt for PcapInterrupt {
    fn interrupt(&self) {
        self.0.breakloop();
    }
}
