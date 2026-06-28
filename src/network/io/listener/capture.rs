use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(feature = "pcap")]
use std::time::SystemTime;
use std::time::{Duration, Instant};

#[cfg(feature = "pcap")]
use libc;
#[cfg(feature = "pcap")]
use log::info;
use log::{error, warn};
#[cfg(feature = "pcap")]
use pcap::{Active, Capture, Device, Linktype, Packet as PcapPacket, PacketHeader, Savefile};
use pnet::datalink::{self, Channel, Config as DatalinkConfig};
#[cfg(feature = "pcap")]
use std::fs;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::config::ListenerRuntimeConfig;
use super::error::ListenerError;
use crate::util::telemetry;

pub type ListenerResult<T> = std::result::Result<T, ListenerError>;

const CHANNEL_TIMEOUT: Duration = Duration::from_millis(500);
const CAPTURE_BUFFER_SIZE: usize = 65_535;
const DROP_WARNING_INTERVAL: usize = 1_000;

pub(crate) fn spawn_capture_thread(
    runtime: ListenerRuntimeConfig,
    interface: datalink::NetworkInterface,
    packet_tx: mpsc::Sender<Vec<u8>>,
    running: Arc<AtomicBool>,
) -> Option<JoinHandle<ListenerResult<()>>> {
    let recovery_running = running;
    Some(tokio::spawn(async move {
        let capture_running = Arc::clone(&recovery_running);
        let result = tokio::task::spawn_blocking(move || {
            if runtime.filter.is_some() {
                #[cfg(feature = "pcap")]
                {
                    return capture_loop_with_pcap(
                        runtime,
                        interface,
                        packet_tx,
                        Arc::clone(&capture_running),
                    );
                }

                #[cfg(not(feature = "pcap"))]
                {
                    if let Some(filter) = runtime.filter.as_ref() {
                        warn!(
                            "pcap feature disabled at compile time; ignoring filter '{}' on {}",
                            filter, interface.name
                        );
                    }
                    return capture_loop(
                        runtime,
                        interface,
                        packet_tx,
                        Arc::clone(&capture_running),
                    );
                }
            }

            capture_loop(runtime, interface, packet_tx, capture_running)
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
                Err(ListenerError::CaptureWorkerAborted { source: err })
            }
        }
    }))
}

#[cfg(feature = "pcap")]
struct ListenerCaptureWriter {
    writer: Savefile,
}

#[cfg(feature = "pcap")]
impl ListenerCaptureWriter {
    fn new(path: &std::path::Path, linktype: Linktype) -> ListenerResult<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| ListenerError::CaptureDirectory {
                    path: parent.display().to_string(),
                    source,
                })?;
            }
        }

        let handle =
            Capture::dead(linktype).map_err(|source| ListenerError::CaptureHandle { source })?;
        let writer = handle
            .savefile(path)
            .map_err(|source| ListenerError::CaptureOpen {
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
            u32::try_from(frame.len()).map_err(|source| ListenerError::CaptureFrameLength {
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
            .map_err(|source| ListenerError::CaptureFlush { source })
    }
}

#[cfg(feature = "pcap")]
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
) -> ListenerResult<()> {
    if interface.name.is_empty() {
        return Err(ListenerError::CaptureChannel {
            interface: "<unspecified>".to_string(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name required for capture",
            ),
        });
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
            return Err(ListenerError::CaptureChannel {
                interface: interface.name.clone(),
                source: err,
            });
        }
    };

    let (_, mut rx) = match channel {
        Channel::Ethernet(_, rx) => ((), rx),
        _ => {
            return Err(ListenerError::UnsupportedChannel {
                interface: interface.name.clone(),
            });
        }
    };

    #[cfg(feature = "pcap")]
    let capture_label = runtime
        .capture_file
        .as_ref()
        .map(|path| path.display().to_string());

    #[cfg(feature = "pcap")]
    let mut recorder = create_capture_writer(runtime.capture_file.as_deref(), Linktype::ETHERNET)?;

    let start = Instant::now();
    let timeout = runtime.timeout;
    let mut dropped_packets = 0usize;

    while capture_session_active(&running, start, timeout) {
        match rx.next() {
            Ok(frame) => {
                #[cfg(feature = "pcap")]
                let mut drop_writer = false;
                #[cfg(feature = "pcap")]
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
                #[cfg(feature = "pcap")]
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
                return Err(ListenerError::CaptureRead {
                    interface: interface.name.clone(),
                    source: err,
                });
            }
        }
    }

    if dropped_packets > 0 {
        warn!(
            "listener dropped {} packet(s) on {} because queue was full",
            dropped_packets, interface.name
        );
    }

    #[cfg(feature = "pcap")]
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

#[cfg(feature = "pcap")]
fn capture_loop_with_pcap(
    runtime: ListenerRuntimeConfig,
    interface: datalink::NetworkInterface,
    packet_tx: mpsc::Sender<Vec<u8>>,
    running: Arc<AtomicBool>,
) -> ListenerResult<()> {
    let device = match resolve_pcap_device(&interface.name) {
        Ok(device) => device,
        Err(err) => {
            warn!(
                "failed to resolve pcap device for {}: {err}; falling back to datalink capture",
                interface.name
            );
            return capture_loop(runtime, interface, packet_tx, running);
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
            return capture_loop(runtime, interface, packet_tx, running);
        }
    };

    if let Some(filter) = runtime.filter.as_ref() {
        capture
            .filter(filter, true)
            .map_err(|err| ListenerError::BpfFilterFailed {
                filter: filter.clone(),
                interface: interface.name.clone(),
                detail: err.to_string(),
            })?;
    }

    capture_loop_from_pcap(&mut capture, runtime, interface, packet_tx, running)
}

#[cfg(feature = "pcap")]
fn capture_loop_from_pcap(
    capture: &mut Capture<Active>,
    runtime: ListenerRuntimeConfig,
    interface: datalink::NetworkInterface,
    packet_tx: mpsc::Sender<Vec<u8>>,
    running: Arc<AtomicBool>,
) -> ListenerResult<()> {
    let capture_label = runtime
        .capture_file
        .as_ref()
        .map(|path| path.display().to_string());
    let mut recorder =
        create_capture_writer(runtime.capture_file.as_deref(), capture.get_datalink())?;

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
                return Err(ListenerError::CaptureReadPcap {
                    interface: interface.name.clone(),
                    source: err,
                });
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

#[cfg(feature = "pcap")]
fn resolve_pcap_device(name: &str) -> ListenerResult<Device> {
    let devices = Device::list().map_err(|source| ListenerError::PcapDeviceList { source })?;
    devices
        .into_iter()
        .find(|device| device.name == name)
        .ok_or_else(|| ListenerError::PcapDeviceNotFound {
            name: name.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "net_integration")]
    use crate::network::listener::config::DEFAULT_QUEUE_CAPACITY;
    #[cfg(feature = "pcap")]
    use tempfile::TempDir;

    #[cfg(feature = "net_integration")]
    #[ignore = "opens a pnet datalink capture channel with an invalid interface"]
    #[test]
    fn capture_loop_returns_error_for_unavailable_channel() {
        let runtime = ListenerRuntimeConfig {
            filter: None,
            promiscuous: false,
            timeout: Some(Duration::from_millis(10)),
            show_reply: false,
            capture_file: None,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
        };
        let interface = datalink::NetworkInterface {
            name: String::new(),
            description: String::new(),
            index: 0,
            mac: None,
            ips: vec![],
            flags: 0,
        };
        let (tx, _rx) = mpsc::channel(1);
        let running = Arc::new(AtomicBool::new(true));

        let result = capture_loop(runtime, interface, tx, running);

        assert!(matches!(
            result,
            Err(ListenerError::CaptureChannel { .. } | ListenerError::UnsupportedChannel { .. })
        ));
    }

    #[test]
    fn capture_within_timeout_returns_true_when_no_timeout() {
        let start = Instant::now();
        assert!(capture_within_timeout(start, None));
    }

    #[cfg(feature = "pcap")]
    #[test]
    fn capture_writer_open_failure_is_returned() {
        let dir = TempDir::new().expect("create temporary directory");

        let result = create_capture_writer(Some(dir.path()), Linktype::ETHERNET);

        assert!(
            matches!(result, Err(ListenerError::CaptureOpen { .. })),
            "directory paths should fail to open as pcap files"
        );
    }

    #[test]
    fn capture_within_timeout_returns_true_when_within_limit() {
        let start = Instant::now();
        let timeout = Some(Duration::from_secs(10));
        assert!(capture_within_timeout(start, timeout));
    }

    #[test]
    fn capture_within_timeout_returns_false_when_exceeded() {
        let start = Instant::now() - Duration::from_secs(10);
        let timeout = Some(Duration::from_secs(5));
        assert!(!capture_within_timeout(start, timeout));
    }

    #[test]
    fn capture_session_active_respects_running_flag() {
        let start = Instant::now();
        let timeout = None;
        let running = Arc::new(AtomicBool::new(true));
        assert!(capture_session_active(&running, start, timeout));

        running.store(false, Ordering::SeqCst);
        assert!(!capture_session_active(&running, start, timeout));
    }

    #[test]
    fn capture_session_active_returns_false_when_timeout_exceeded() {
        let start = Instant::now() - Duration::from_secs(10);
        let timeout = Some(Duration::from_secs(5));
        let running = Arc::new(AtomicBool::new(true));

        assert!(!capture_session_active(&running, start, timeout));
    }

    #[cfg(feature = "net_integration")]
    #[ignore = "opens a pnet datalink capture channel with an invalid interface"]
    #[test]
    fn capture_loop_returns_error_for_empty_interface_name() {
        let runtime = ListenerRuntimeConfig {
            filter: None,
            promiscuous: false,
            timeout: None,
            show_reply: false,
            capture_file: None,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
        };
        let interface = datalink::NetworkInterface {
            name: String::new(),
            description: String::new(),
            index: 0,
            mac: None,
            ips: vec![],
            flags: 0,
        };
        let (tx, _rx) = mpsc::channel(1);
        let running = Arc::new(AtomicBool::new(true));

        let result = capture_loop(runtime, interface, tx, running);

        match result {
            Err(ListenerError::CaptureChannel {
                interface: iface_name,
                source,
            }) => {
                assert!(!iface_name.is_empty());
                assert_eq!(source.kind(), io::ErrorKind::InvalidInput);
            }
            _ => panic!("expected CaptureChannel error with invalid input"),
        }
    }
}
