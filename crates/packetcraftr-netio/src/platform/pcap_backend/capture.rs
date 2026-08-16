// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! libpcap-backed capture session creation and frame stream.

#![allow(unsafe_code)]

use std::{
    sync::Arc,
    time::{Instant, SystemTime},
};

use bytes::Bytes;
use pcap::{Active, Capture, Error as PcapError};

use super::bpf::install_capture_filter;
use crate::{
    Error as LiveIoError,
    capture::CaptureQueueLimits,
    interface::Id as InterfaceId,
    platform::live_capture::{
        CaptureInterrupt, NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource,
        NativeCaptureStatistics, NativeCapturedPacket, monotonic_packet_time, system_time,
    },
};
use packetcraftr_core::frame::LinkType;

const READ_TIMEOUT_MILLIS: i32 = 50;
pub(super) const PCAP_NETMASK_UNKNOWN: u32 = u32::MAX;

pub(crate) fn open_capture(
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

pub(super) fn map_open_error(interface: &InterfaceId, error: PcapError) -> LiveIoError {
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
