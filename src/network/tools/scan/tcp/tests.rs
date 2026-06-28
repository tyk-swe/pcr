use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;

fn build_tcp_packet(source: u16, destination: u16, flags: u8) -> TcpPacket<'static> {
    let mut buffer = vec![0u8; 20];
    {
        let mut packet = MutableTcpPacket::new(&mut buffer).expect("packet");
        packet.set_source(source);
        packet.set_destination(destination);
        packet.set_flags(flags);
    }
    TcpPacket::owned(buffer).expect("owned packet")
}

#[test]
fn send_tcp_with_retry_handles_transient_errors() {
    let packet_bytes = build_tcp_packet(12345, 80, TcpFlags::SYN).packet().to_vec();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempt_counter = Arc::clone(&attempts);

    let result = send_tcp_with_retry(
        &packet_bytes,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
        |_, _| {
            let current = attempt_counter.fetch_add(1, Ordering::SeqCst);
            if current < 2 {
                Err(std::io::Error::from_raw_os_error(libc::ENOBUFS))
            } else {
                Ok(())
            }
        },
    );

    assert!(result.is_ok(), "{:?}", result);
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[test]
fn send_tcp_with_retry_stops_after_max_attempts() {
    let packet_bytes = build_tcp_packet(23456, 443, TcpFlags::SYN)
        .packet()
        .to_vec();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempt_counter = Arc::clone(&attempts);
    let start = Instant::now();

    let result = send_tcp_with_retry(
        &packet_bytes,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        |_, _| {
            attempt_counter.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::from_raw_os_error(libc::ENOBUFS))
        },
    );

    assert!(result.is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 4);
    assert!(start.elapsed() >= Duration::from_millis(7));
}

struct SmartMockRx {
    tx_capture: Arc<Mutex<Vec<(u16, IpAddr, u16)>>>, // (source_port, dest_ip, dest_port)
    response_template: Option<(u8, PortState)>,      // If set, reply to all probes
    generated: bool,
}

impl TcpScanRx for SmartMockRx {
    fn next_event(&mut self, _: Duration) -> Result<Option<ScanEvent>> {
        // Check if any packet was sent
        let sent = self.tx_capture.lock().unwrap().clone();
        if sent.is_empty() {
            return Ok(None);
        }

        if self.generated {
            return Ok(None); // Only generate once per test
        }

        if let Some((flags, _state)) = self.response_template {
            let (src_port, dst_ip, dst_port) = sent[0];
            self.generated = true;

            return Ok(Some(ScanEvent::PacketResponse {
                source_port: dst_port, // Remote responds from its port
                dest_port: src_port,   // To our local port
                flags: Some(flags),
                src_addr: dst_ip,
            }));
        }

        Ok(None)
    }
}

#[derive(Debug, Clone, Copy)]
struct RateLimitScan;
impl TcpScanStrategy for RateLimitScan {
    fn protocol_name(&self) -> &'static str {
        "TCP RATE LIMIT"
    }
    fn report_name(&self) -> &'static str {
        "tcp-ratelimit"
    }
    fn get_tcp_flags(&self) -> TcpFlagSet {
        TcpFlagSet {
            syn: true,
            ..Default::default()
        }
    }
    fn classify(&self, _flags: u8) -> Option<PortState> {
        None
    }
    fn timeout_state(&self) -> PortState {
        PortState::Filtered
    }
}

struct CapturingTcpSender {
    sent: Arc<Mutex<Vec<(u16, IpAddr, u16)>>>, // src_port, dst_ip, dst_port
}

impl TcpSender for CapturingTcpSender {
    fn send_tcp(&mut self, packet: TcpPacket<'_>, destination: SocketAddr) -> Result<()> {
        self.sent.lock().unwrap().push((
            packet.get_source(),
            destination.ip(),
            packet.get_destination(),
        ));
        Ok(())
    }
}

#[test]
fn scan_ports_concurrent_detects_open_port() {
    let sent_packets = Arc::new(Mutex::new(Vec::new()));
    let mut tx = CapturingTcpSender {
        sent: sent_packets.clone(),
    };

    let mut rx = SmartMockRx {
        tx_capture: sent_packets,
        response_template: Some((TcpFlags::SYN | TcpFlags::ACK, PortState::Open)),
        generated: false,
    };

    let results = scan_ports_concurrent(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &[80],
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Duration::from_millis(200),
        &GenericTcpScan::syn(),
        &mut tx,
        &mut rx,
    )
    .expect("scan failed");

    assert_eq!(results.get(&80), Some(&PortState::Open));
}

#[test]
fn scan_ports_concurrent_detects_closed_port() {
    let sent_packets = Arc::new(Mutex::new(Vec::new()));
    let mut tx = CapturingTcpSender {
        sent: sent_packets.clone(),
    };

    let mut rx = SmartMockRx {
        tx_capture: sent_packets,
        response_template: Some((TcpFlags::RST, PortState::Closed)),
        generated: false,
    };

    let results = scan_ports_concurrent(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &[80],
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Duration::from_millis(200),
        &GenericTcpScan::syn(),
        &mut tx,
        &mut rx,
    )
    .expect("scan failed");

    assert_eq!(results.get(&80), Some(&PortState::Closed));
}

struct FailingTcpSender;

impl TcpSender for FailingTcpSender {
    fn send_tcp(&mut self, _packet: TcpPacket<'_>, _destination: SocketAddr) -> Result<()> {
        Err(anyhow!("send failure"))
    }
}

struct NoopTcpRx;

impl TcpScanRx for NoopTcpRx {
    fn next_event(&mut self, _: Duration) -> Result<Option<ScanEvent>> {
        Ok(None)
    }
}

#[test]
fn scan_ports_concurrent_propagates_send_errors() {
    let mut tx = FailingTcpSender;
    let mut rx = NoopTcpRx;

    let result = scan_ports_concurrent(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &[80],
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Duration::from_millis(10),
        &GenericTcpScan::syn(),
        &mut tx,
        &mut rx,
    );

    assert!(result.is_err());
}

#[test]
fn classify_tcp_packet_identifies_open_ports() {
    let result = GenericTcpScan::syn().classify(TcpFlags::SYN | TcpFlags::ACK);
    assert_eq!(result, Some(PortState::Open));
}

#[test]
fn classify_tcp_packet_identifies_closed_ports() {
    let result = GenericTcpScan::syn().classify(TcpFlags::RST);
    assert_eq!(result, Some(PortState::Closed));
}

#[test]
fn perform_tcp_scan_ipv4_requires_ipv4_override() {
    let config = TcpScanConfig {
        address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        ports: vec![80],
        timeout: Duration::from_millis(100),
        source_override: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)), // Mismatch
        scan_strategy: GenericTcpScan::syn(),
    };

    let result = perform_tcp_scan(config);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("IPv6 interface override cannot be used for IPv4 target"));
}

use std::collections::VecDeque;

struct FlexibleMockRx {
    tx_capture: Arc<Mutex<Vec<(u16, IpAddr, u16)>>>,
    processed_count: usize,
    events: VecDeque<ScanEvent>,
    responses: HashMap<u16, (u8, PortState)>, // Map target_port -> (flags, state)
    default_response: Option<(u8, PortState)>,
}

impl TcpScanRx for FlexibleMockRx {
    fn next_event(&mut self, _: Duration) -> Result<Option<ScanEvent>> {
        // Process any newly sent packets
        let new_packets_to_process = {
            let sent = self.tx_capture.lock().unwrap();
            let start_index = self.processed_count;
            if start_index < sent.len() {
                self.processed_count = sent.len();
                sent[start_index..].to_vec()
            } else {
                Vec::new()
            }
        };

        for (src_port, dst_ip, dst_port) in new_packets_to_process {
            let response = self
                .responses
                .get(&dst_port)
                .copied()
                .or(self.default_response);

            if let Some((flags, _)) = response {
                self.events.push_back(ScanEvent::PacketResponse {
                    source_port: dst_port, // Remote responds from its port
                    dest_port: src_port,   // To our local port
                    flags: Some(flags),
                    src_addr: dst_ip,
                });
            }
        }

        if let Some(event) = self.events.pop_front() {
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }
}

#[test]
fn test_tcp_syn_open_port_detection() {
    let sent_packets = Arc::new(Mutex::new(Vec::new()));
    let mut tx = CapturingTcpSender {
        sent: sent_packets.clone(),
    };

    let mut rx = FlexibleMockRx {
        tx_capture: sent_packets,
        processed_count: 0,
        events: VecDeque::new(),
        responses: HashMap::new(),
        default_response: Some((TcpFlags::SYN | TcpFlags::ACK, PortState::Open)),
    };

    let results = scan_ports_concurrent(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &[80],
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Duration::from_millis(200),
        &GenericTcpScan::syn(),
        &mut tx,
        &mut rx,
    )
    .expect("scan failed");

    assert_eq!(results.get(&80), Some(&PortState::Open));
}

#[test]
fn test_tcp_syn_closed_port_detection() {
    let sent_packets = Arc::new(Mutex::new(Vec::new()));
    let mut tx = CapturingTcpSender {
        sent: sent_packets.clone(),
    };

    let mut rx = FlexibleMockRx {
        tx_capture: sent_packets,
        processed_count: 0,
        events: VecDeque::new(),
        responses: HashMap::new(),
        default_response: Some((TcpFlags::RST, PortState::Closed)),
    };

    let results = scan_ports_concurrent(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &[80],
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Duration::from_millis(200),
        &GenericTcpScan::syn(),
        &mut tx,
        &mut rx,
    )
    .expect("scan failed");

    assert_eq!(results.get(&80), Some(&PortState::Closed));
}

#[test]
fn test_tcp_syn_timeout_handling() {
    let sent_packets = Arc::new(Mutex::new(Vec::new()));
    let mut tx = CapturingTcpSender {
        sent: sent_packets.clone(),
    };

    let mut rx = FlexibleMockRx {
        tx_capture: sent_packets,
        processed_count: 0,
        events: VecDeque::new(),
        responses: HashMap::new(),
        default_response: None, // No response implies timeout
    };

    let results = scan_ports_concurrent(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &[80],
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Duration::from_millis(200),
        &GenericTcpScan::syn(),
        &mut tx,
        &mut rx,
    )
    .expect("scan failed");

    assert_eq!(results.get(&80), Some(&PortState::Filtered));
}

#[test]
fn test_tcp_syn_multiple_ports() {
    let sent_packets = Arc::new(Mutex::new(Vec::new()));
    let mut tx = CapturingTcpSender {
        sent: sent_packets.clone(),
    };

    let mut responses = HashMap::new();
    responses.insert(80, (TcpFlags::SYN | TcpFlags::ACK, PortState::Open));
    responses.insert(443, (TcpFlags::RST, PortState::Closed));
    // 8080 will get no response (timeout/Filtered)

    let mut rx = FlexibleMockRx {
        tx_capture: sent_packets,
        processed_count: 0,
        events: VecDeque::new(),
        responses,
        default_response: None,
    };

    let ports = [80, 443, 8080];
    let results = scan_ports_concurrent(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &ports,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Duration::from_millis(200),
        &GenericTcpScan::syn(),
        &mut tx,
        &mut rx,
    )
    .expect("scan failed");

    assert_eq!(results.get(&80), Some(&PortState::Open));
    assert_eq!(results.get(&443), Some(&PortState::Closed));
    assert_eq!(results.get(&8080), Some(&PortState::Filtered));
}

#[test]
fn test_strategy_metadata() {
    assert_eq!(GenericTcpScan::syn().protocol_name(), "TCP SYN");
    assert_eq!(GenericTcpScan::syn().report_name(), "tcp-syn");

    assert_eq!(GenericTcpScan::fin().protocol_name(), "TCP FIN");
    assert_eq!(GenericTcpScan::fin().report_name(), "tcp-fin");

    assert_eq!(GenericTcpScan::null().protocol_name(), "TCP NULL");
    assert_eq!(GenericTcpScan::null().report_name(), "tcp-null");

    assert_eq!(GenericTcpScan::xmas().protocol_name(), "TCP XMAS");
    assert_eq!(GenericTcpScan::xmas().report_name(), "tcp-xmas");

    assert_eq!(GenericTcpScan::ack().protocol_name(), "TCP ACK");
    assert_eq!(GenericTcpScan::ack().report_name(), "tcp-ack");
}

#[test]
fn test_strategy_flags() {
    assert!(GenericTcpScan::syn().get_tcp_flags().syn);
    assert!(!GenericTcpScan::syn().get_tcp_flags().fin);

    assert!(GenericTcpScan::fin().get_tcp_flags().fin);
    assert!(!GenericTcpScan::fin().get_tcp_flags().syn);

    let null_flags = GenericTcpScan::null().get_tcp_flags();
    assert!(!null_flags.syn && !null_flags.fin && !null_flags.ack && !null_flags.rst);

    let xmas_flags = GenericTcpScan::xmas().get_tcp_flags();
    assert!(xmas_flags.fin && xmas_flags.psh && xmas_flags.urg);
    assert!(!xmas_flags.syn && !xmas_flags.ack);

    assert!(GenericTcpScan::ack().get_tcp_flags().ack);
    assert!(!GenericTcpScan::ack().get_tcp_flags().syn);
}

#[test]
fn test_strategy_classification() {
    // SYN Scan
    assert_eq!(
        GenericTcpScan::syn().classify(TcpFlags::SYN | TcpFlags::ACK),
        Some(PortState::Open)
    );
    assert_eq!(
        GenericTcpScan::syn().classify(TcpFlags::RST),
        Some(PortState::Closed)
    );
    assert_eq!(GenericTcpScan::syn().classify(TcpFlags::SYN), None);
    assert_eq!(GenericTcpScan::syn().classify(0), None);

    // FIN Scan
    assert_eq!(
        GenericTcpScan::fin().classify(TcpFlags::RST),
        Some(PortState::Closed)
    );
    assert_eq!(
        GenericTcpScan::fin().classify(TcpFlags::SYN | TcpFlags::ACK),
        None
    );
    assert_eq!(GenericTcpScan::fin().classify(0), None);

    // NULL Scan
    assert_eq!(
        GenericTcpScan::null().classify(TcpFlags::RST),
        Some(PortState::Closed)
    );
    assert_eq!(
        GenericTcpScan::null().classify(TcpFlags::SYN | TcpFlags::ACK),
        None
    );
    assert_eq!(GenericTcpScan::null().classify(0), None);

    // XMAS Scan
    assert_eq!(
        GenericTcpScan::xmas().classify(TcpFlags::RST),
        Some(PortState::Closed)
    );
    assert_eq!(
        GenericTcpScan::xmas().classify(TcpFlags::SYN | TcpFlags::ACK),
        None
    );
    assert_eq!(GenericTcpScan::xmas().classify(0), None);

    // ACK Scan
    assert_eq!(
        GenericTcpScan::ack().classify(TcpFlags::RST),
        Some(PortState::Unfiltered)
    );
    assert_eq!(
        GenericTcpScan::ack().classify(TcpFlags::SYN | TcpFlags::ACK),
        None
    );
    assert_eq!(GenericTcpScan::ack().classify(0), None);
}

#[test]
fn test_strategy_timeout_state() {
    assert_eq!(GenericTcpScan::syn().timeout_state(), PortState::Filtered);
    assert_eq!(
        GenericTcpScan::fin().timeout_state(),
        PortState::OpenOrFiltered
    );
    assert_eq!(
        GenericTcpScan::null().timeout_state(),
        PortState::OpenOrFiltered
    );
    assert_eq!(
        GenericTcpScan::xmas().timeout_state(),
        PortState::OpenOrFiltered
    );
    assert_eq!(GenericTcpScan::ack().timeout_state(), PortState::Filtered);
}

#[test]
fn test_rate_limiting() {
    let sent_packets = Arc::new(Mutex::new(Vec::new()));
    let mut tx = CapturingTcpSender {
        sent: sent_packets.clone(),
    };

    let mut rx = NoopTcpRx;

    let ports: Vec<u16> = (0..1000).collect(); // 1000 ports
    let start = Instant::now();

    // Use RateLimitScan strategy (or any strategy)
    // Use a very short timeout so we can measure the sending duration primarily
    let _ = scan_ports_concurrent(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &ports,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Duration::from_millis(1),
        &RateLimitScan,
        &mut tx,
        &mut rx,
    );

    let duration = start.elapsed();
    // With 100us delay, 1000 ports should take >= 100ms.
    // We check for >= 50ms.
    // Without fix, it should be much faster (e.g. < 20ms) because we use a small timeout.
    assert!(
        duration >= Duration::from_millis(50),
        "Scan was too fast ({:?}), rate limiting likely missing",
        duration
    );
}
