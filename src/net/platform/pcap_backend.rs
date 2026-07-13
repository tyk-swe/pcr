// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! libpcap-backed Layer 2 capture and injection for Linux and macOS.

use std::sync::Arc;

use bytes::Bytes;
use pcap::{Active, Capture, Error as PcapError};

use super::live_capture::{
    system_time, CaptureInterrupt, NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource,
    NativeCaptureStatistics, NativeCapturedPacket,
};
use crate::capture::LinkType;
use crate::net::{CaptureQueueLimits, InterfaceId, IoSendReport, Layer2Frame, LiveIoError};

const READ_TIMEOUT_MILLIS: i32 = 50;

pub(super) fn open_capture(
    interface: &InterfaceId,
    limits: CaptureQueueLimits,
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

pub(super) fn send_layer2(frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
    let interface = &frame.route().plan.route.interface;
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
        wire_bytes: Some(frame.bytes().clone()),
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
                #[cfg(target_os = "linux")]
                let timestamp = system_time(packet.header.ts.tv_sec, packet.header.ts.tv_usec)?;
                #[cfg(target_os = "macos")]
                let timestamp =
                    system_time(packet.header.ts.tv_sec, i64::from(packet.header.ts.tv_usec))?;
                Ok(NativeCaptureEvent::Packet(NativeCapturedPacket {
                    timestamp,
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
