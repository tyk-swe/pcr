// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use std::time::{Duration, Instant};

use log::info;
use log::{error, warn};
use pcap::{Active, Capture, Device, Linktype, Packet as PcapPacket, PacketHeader, Savefile};
use pnet::datalink::{self, Channel, Config as DatalinkConfig};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::config::ListenerRuntimeConfig;
use super::error::{ListenerError, PcapListenerError};
use super::ListenerStartupSignal;
use crate::util::telemetry;

pub(crate) type ListenerResult<T> = std::result::Result<T, ListenerError>;

const CHANNEL_TIMEOUT: Duration = Duration::from_millis(500);
const CAPTURE_BUFFER_SIZE: usize = 65_535;
const DROP_WARNING_INTERVAL: usize = 1_000;

pub(crate) fn spawn_capture_thread(
    runtime: ListenerRuntimeConfig,
    interface: datalink::NetworkInterface,
    packet_tx: mpsc::Sender<Vec<u8>>,
    running: Arc<AtomicBool>,
    startup: Option<ListenerStartupSignal>,
) -> Option<JoinHandle<ListenerResult<()>>> {
    let recovery_running = running;
    Some(tokio::spawn(async move {
        let capture_running = Arc::clone(&recovery_running);
        let result = tokio::task::spawn_blocking(move || {
            let mut startup = startup;
            if runtime.filter.is_some() {
                let result = capture_loop_with_pcap(
                    runtime,
                    interface,
                    packet_tx,
                    Arc::clone(&capture_running),
                    &mut startup,
                );
                return notify_startup_failure_on_error(&mut startup, result);
            }

            let result = capture_loop(runtime, interface, packet_tx, capture_running, &mut startup);
            notify_startup_failure_on_error(&mut startup, result)
        })
        .await;

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => {
                recovery_running.store(false, Ordering::SeqCst);
                Err(err)
            }
            Err(err) => {
                recovery_running.store(false, Ordering::SeqCst);
                if err.is_panic() {
                    error!("capture loop panicked: {err}");
                } else {
                    error!("capture loop aborted unexpectedly: {err}");
                }
                Err(PcapListenerError::CaptureWorkerAborted { source: err }.into())
            }
        }
    }))
}

fn notify_startup_ready(startup: &mut Option<ListenerStartupSignal>) {
    if let Some(startup) = startup.take() {
        let _ = startup.send(Ok(()));
    }
}

fn notify_startup_failure_on_error(
    startup: &mut Option<ListenerStartupSignal>,
    result: ListenerResult<()>,
) -> ListenerResult<()> {
    if let Err(err) = result.as_ref() {
        if let Some(startup) = startup.take() {
            let _ = startup.send(Err(err.to_string()));
        }
    }
    result
}

struct ListenerCaptureWriter {
    writer: Savefile,
}

impl ListenerCaptureWriter {
    fn new(path: &std::path::Path, linktype: Linktype) -> ListenerResult<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| {
                    PcapListenerError::CaptureDirectory {
                        path: parent.display().to_string(),
                        source,
                    }
                })?;
            }
        }

        let handle = Capture::dead(linktype)
            .map_err(|source| PcapListenerError::CaptureHandle { source })?;
        let writer = handle
            .savefile(path)
            .map_err(|source| PcapListenerError::CaptureOpen {
                path: path.display().to_string(),
                source,
            })?;

        Ok(Self { writer })
    }

    fn record(&mut self, frame: &[u8]) -> ListenerResult<()> {
        let now = SystemTime::now();
        let duration = match now.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration,
            Err(err) => {
                warn!(
                    "system clock is before UNIX_EPOCH; using zero timestamp for listener capture: {err}"
                );
                std::time::Duration::default()
            }
        };
        let frame_len =
            u32::try_from(frame.len()).map_err(|source| PcapListenerError::CaptureFrameLength {
                len: frame.len(),
                source,
            })?;
        let header = PacketHeader {
            ts: libc::timeval {
                tv_sec: duration.as_secs() as libc::time_t,
                tv_usec: duration.subsec_micros() as libc::suseconds_t,
            },
            caplen: frame_len,
            len: frame_len,
        };
        let packet = PcapPacket::new(&header, frame);
        self.writer.write(&packet);
        Ok(())
    }

    fn flush(&mut self) -> ListenerResult<()> {
        self.writer
            .flush()
            .map_err(|source| PcapListenerError::CaptureFlush { source }.into())
    }
}

fn create_capture_writer(
    capture_file: Option<&std::path::Path>,
    linktype: Linktype,
) -> ListenerResult<Option<ListenerCaptureWriter>> {
    match capture_file {
        Some(path) => {
            let writer = ListenerCaptureWriter::new(path, linktype)?;
            info!("Recording listener capture to {}", path.display());
            Ok(Some(writer))
        }
        None => Ok(None),
    }
}

fn capture_loop(
    runtime: ListenerRuntimeConfig,
    interface: datalink::NetworkInterface,
    packet_tx: mpsc::Sender<Vec<u8>>,
    running: Arc<AtomicBool>,
    startup: &mut Option<ListenerStartupSignal>,
) -> ListenerResult<()> {
    if interface.name.is_empty() {
        return Err(PcapListenerError::CaptureChannel {
            interface: "<unspecified>".to_string(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name required for capture",
            ),
        }
        .into());
    }

    let config = DatalinkConfig {
        read_timeout: Some(CHANNEL_TIMEOUT),
        read_buffer_size: CAPTURE_BUFFER_SIZE,
        write_buffer_size: CAPTURE_BUFFER_SIZE,
        promiscuous: runtime.promiscuous,
        ..Default::default()
    };

    let channel = match datalink::channel(&interface, config) {
        Ok(channel) => channel,
        Err(err) => {
            return Err(PcapListenerError::CaptureChannel {
                interface: interface.name.clone(),
                source: err,
            }
            .into());
        }
    };

    let (_, mut rx) = match channel {
        Channel::Ethernet(_, rx) => ((), rx),
        _ => {
            return Err(PcapListenerError::UnsupportedChannel {
                interface: interface.name.clone(),
            }
            .into());
        }
    };

    let capture_label = runtime
        .capture_file
        .as_ref()
        .map(|path| path.display().to_string());

    let mut recorder = create_capture_writer(runtime.capture_file.as_deref(), Linktype::ETHERNET)?;

    notify_startup_ready(startup);

    let start = Instant::now();
    let timeout = runtime.timeout;
    let mut dropped_packets = 0usize;

    while capture_session_active(&running, start, timeout) {
        match rx.next() {
            Ok(frame) => {
                let mut drop_writer = false;
                {
                    if let Some(writer) = recorder.as_mut() {
                        if let Err(err) = writer.record(frame) {
                            // Continue streaming even if capture persistence fails
                            if let Some(label) = capture_label.as_ref() {
                                warn!("failed to record packet to {}: {err}", label);
                            } else {
                                warn!("failed to record packet to capture file: {err}");
                            }
                            drop_writer = true;
                        }
                    }
                }
                if drop_writer {
                    recorder = None;
                }

                match packet_tx.try_send(frame.to_vec()) {
                    Ok(_) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        dropped_packets += 1;
                        telemetry::record_listener_dropped_packet("queue_full");
                        if dropped_packets == 1
                            || dropped_packets.is_multiple_of(DROP_WARNING_INTERVAL)
                        {
                            warn!(
                                "listener queue full on {}; dropped {} packet(s)",
                                interface.name, dropped_packets
                            );
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        break;
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                continue;
            }
            Err(err) => {
                warn!("error reading packet from {}: {err}", interface.name);
                return Err(PcapListenerError::CaptureRead {
                    interface: interface.name.clone(),
                    source: err,
                }
                .into());
            }
        }
    }

    if dropped_packets > 0 {
        warn!(
            "listener dropped {} packet(s) on {} because queue was full",
            dropped_packets, interface.name
        );
    }

    if let Some(writer) = recorder.as_mut() {
        if let Err(err) = writer.flush() {
            if let Some(label) = capture_label.as_ref() {
                warn!("failed to flush listener capture {}: {err}", label);
            } else {
                warn!("failed to flush listener capture: {err}");
            }
        }
    }

    Ok(())
}

fn capture_session_active(
    running: &Arc<AtomicBool>,
    start: Instant,
    timeout: Option<Duration>,
) -> bool {
    running.load(Ordering::SeqCst) && capture_within_timeout(start, timeout)
}

fn capture_within_timeout(start: Instant, timeout: Option<Duration>) -> bool {
    match timeout {
        Some(limit) => start.elapsed() < limit,
        None => true,
    }
}

fn capture_loop_with_pcap(
    runtime: ListenerRuntimeConfig,
    interface: datalink::NetworkInterface,
    packet_tx: mpsc::Sender<Vec<u8>>,
    running: Arc<AtomicBool>,
    startup: &mut Option<ListenerStartupSignal>,
) -> ListenerResult<()> {
    let device = match resolve_pcap_device(&interface.name) {
        Ok(device) => device,
        Err(err) => {
            warn!(
                "failed to resolve pcap device for {}: {err}; falling back to datalink capture",
                interface.name
            );
            return capture_loop(runtime, interface, packet_tx, running, startup);
        }
    };

    let timeout_ms = CHANNEL_TIMEOUT.as_millis() as i32;
    let mut capture = match Capture::from_device(device).and_then(|builder| {
        builder
            .promisc(runtime.promiscuous)
            .timeout(timeout_ms)
            .buffer_size(CAPTURE_BUFFER_SIZE as i32)
            .open()
    }) {
        Ok(cap) => cap,
        Err(err) => {
            warn!(
                "failed to open pcap capture on {}: {err}; falling back to datalink capture",
                interface.name
            );
            return capture_loop(runtime, interface, packet_tx, running, startup);
        }
    };

    if let Some(filter) = runtime.filter.as_ref() {
        capture
            .filter(filter, true)
            .map_err(|err| PcapListenerError::BpfFilterFailed {
                filter: filter.clone(),
                interface: interface.name.clone(),
                detail: err.to_string(),
            })?;
    }

    capture_loop_from_pcap(
        &mut capture,
        runtime,
        interface,
        packet_tx,
        running,
        startup,
    )
}

fn capture_loop_from_pcap(
    capture: &mut Capture<Active>,
    runtime: ListenerRuntimeConfig,
    interface: datalink::NetworkInterface,
    packet_tx: mpsc::Sender<Vec<u8>>,
    running: Arc<AtomicBool>,
    startup: &mut Option<ListenerStartupSignal>,
) -> ListenerResult<()> {
    let capture_label = runtime
        .capture_file
        .as_ref()
        .map(|path| path.display().to_string());
    let mut recorder =
        create_capture_writer(runtime.capture_file.as_deref(), capture.get_datalink())?;

    notify_startup_ready(startup);

    let start = Instant::now();
    let timeout = runtime.timeout;
    let mut dropped_packets = 0usize;

    while capture_session_active(&running, start, timeout) {
        match capture.next_packet() {
            Ok(packet) => {
                let mut drop_writer = false;
                if let Some(writer) = recorder.as_mut() {
                    if let Err(err) = writer.record(packet.data) {
                        // Disable writes after failure to avoid noise
                        if let Some(label) = capture_label.as_ref() {
                            warn!("failed to record packet to {}: {err}", label);
                        } else {
                            warn!("failed to record packet to capture file: {err}");
                        }
                        drop_writer = true;
                    }
                }
                if drop_writer {
                    recorder = None;
                }

                match packet_tx.try_send(packet.data.to_vec()) {
                    Ok(_) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        dropped_packets += 1;
                        telemetry::record_listener_dropped_packet("queue_full");
                        if dropped_packets == 1
                            || dropped_packets.is_multiple_of(DROP_WARNING_INTERVAL)
                        {
                            warn!(
                                "listener queue full on {} (pcap); dropped {} packet(s)",
                                interface.name, dropped_packets
                            );
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        break;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(err) => {
                warn!(
                    "error reading packet from {} via pcap: {err}",
                    interface.name
                );
                return Err(PcapListenerError::CaptureReadPcap {
                    interface: interface.name.clone(),
                    source: err,
                }
                .into());
            }
        }
    }

    if dropped_packets > 0 {
        warn!(
            "listener dropped {} packet(s) on {} via pcap because queue was full",
            dropped_packets, interface.name
        );
    }

    if let Some(writer) = recorder.as_mut() {
        if let Err(err) = writer.flush() {
            if let Some(label) = capture_label.as_ref() {
                warn!("failed to flush listener capture {}: {err}", label);
            } else {
                warn!("failed to flush listener capture: {err}");
            }
        }
    }

    Ok(())
}

fn resolve_pcap_device(name: &str) -> ListenerResult<Device> {
    let devices = Device::list().map_err(|source| PcapListenerError::PcapDeviceList { source })?;
    devices
        .into_iter()
        .find(|device| device.name == name)
        .ok_or_else(|| PcapListenerError::PcapDeviceNotFound {
            name: name.to_string(),
        })
        .map_err(ListenerError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn capture_within_timeout_allows_sessions_without_timeout() {
        assert!(capture_within_timeout(Instant::now(), None));
    }

    #[test]
    fn capture_within_timeout_stops_after_timeout_elapsed() {
        let start = Instant::now() - Duration::from_millis(10);

        assert!(!capture_within_timeout(
            start,
            Some(Duration::from_millis(1))
        ));
    }

    #[test]
    fn capture_session_active_requires_running_flag_and_timeout_window() {
        let running = Arc::new(AtomicBool::new(true));
        assert!(capture_session_active(
            &running,
            Instant::now(),
            Some(Duration::from_secs(1))
        ));

        running.store(false, Ordering::SeqCst);
        assert!(!capture_session_active(&running, Instant::now(), None));
    }

    #[tokio::test]
    async fn notify_startup_ready_sends_success_and_consumes_signal() {
        let (startup_tx, startup_rx) = tokio::sync::oneshot::channel();
        let mut startup = Some(startup_tx);

        notify_startup_ready(&mut startup);

        assert!(startup.is_none());
        assert_eq!(startup_rx.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn notify_startup_failure_on_error_sends_error_and_preserves_result() {
        let (startup_tx, startup_rx) = tokio::sync::oneshot::channel();
        let mut startup = Some(startup_tx);
        let err = PcapListenerError::UnsupportedChannel {
            interface: "eth-test".to_string(),
        };

        let result = notify_startup_failure_on_error(&mut startup, Err(err.into()));

        assert!(result.is_err());
        assert!(startup.is_none());
        assert!(startup_rx
            .await
            .unwrap()
            .unwrap_err()
            .contains("does not support Ethernet"));
    }
}
