// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::differential::ResponderCollector;
use std::net::TcpStream;

fn free_port() -> u16 {
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = udp.local_addr().unwrap().port();
    drop(udp);
    port
}

#[test]
fn reservation_covers_generated_queries_beyond_the_response_limit() {
    let mut request = Request::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53),
        [7_u8; TOKEN_LEN],
    );
    request.repeats = 1;
    request.limits.max_message_bytes = 16;
    let attempts = prepare_attempts(&request).unwrap();
    let expected = attempts.iter().fold(0_u64, |total, attempt| {
        let framing = match attempt.transport {
            Transport::Tcp => 2,
            Transport::Udp => 0,
        };
        total + attempt.query.len() as u64 + framing + 16 + framing
    });
    let limits = socket_limits(&request, &attempts);
    assert_eq!(limits.connections(), attempts.len() as u64);
    assert_eq!(limits.messages(), attempts.len() as u64 * 2);
    assert_eq!(limits.application_bytes(), expected);
    assert!(expected > attempts.len() as u64 * 32);
}

struct TimeoutUdp;

impl packetcraftr_netio::udp::Provider for TimeoutUdp {
    fn exchange(
        &self,
        endpoint: SocketAddr,
        request: &[u8],
        _max_response: usize,
        _deadline: &Deadline,
    ) -> Result<packetcraftr_netio::udp::Reply, packetcraftr_netio::udp::Error> {
        Ok(packetcraftr_netio::udp::Reply {
            peer: endpoint,
            local: "127.0.0.1:40000".parse().unwrap(),
            exchange: packetcraftr_netio::bounded::Exchange {
                response: Bytes::new(),
                bytes_sent: request.len(),
                outcome: packetcraftr_netio::bounded::Outcome::TimedOut,
            },
        })
    }
}

struct CancellingStream {
    peer: SocketAddr,
    cancellation: packetcraftr_core::budget::Cancellation,
}

impl std::io::Read for CancellingStream {
    fn read(&mut self, _bytes: &mut [u8]) -> std::io::Result<usize> {
        self.cancellation.cancel();
        Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    }
}

impl std::io::Write for CancellingStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl packetcraftr_netio::tcp::Stream for CancellingStream {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok("127.0.0.1:40001".parse().unwrap())
    }

    fn set_read_timeout(&self, _timeout: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, _timeout: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct CancellingTcp {
    cancellation: packetcraftr_core::budget::Cancellation,
}

impl packetcraftr_netio::tcp::Provider for CancellingTcp {
    type Stream = CancellingStream;

    fn connect(
        &self,
        endpoint: SocketAddr,
        _deadline: &Deadline,
    ) -> Result<Self::Stream, packetcraftr_netio::tcp::Error> {
        Ok(CancellingStream {
            peer: endpoint,
            cancellation: self.cancellation.clone(),
        })
    }
}

#[test]
fn cancellation_during_final_tcp_attempt_is_propagated() {
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    let client = crate::Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        crate::policy::Policy::default(),
        crate::ProviderSet::tcp(
            CancellingTcp {
                cancellation: cancellation.clone(),
            },
            (),
        )
        .with_udp(TimeoutUdp),
    )
    .with_cancellation(cancellation);
    let mut request = Request::new(
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53),
        [7_u8; TOKEN_LEN],
    );
    request.repeats = 1;
    request.timeout = Duration::from_millis(200);
    request.max_duration = Duration::from_secs(10);
    let result = client.dns_differential(&request);
    assert!(matches!(result, Err(Error::Execution { .. })), "{result:?}");
}

#[test]
fn unplanned_dns_identities_are_ignored() {
    let port = free_port();
    let token = [7_u8; TOKEN_LEN];
    let collector = ResponderCollector::default();
    let thread_collector = collector.clone();
    let handle = std::thread::spawn(move || {
        let mut request = ResponderRequest::new(Ipv4Addr::LOCALHOST, port, token);
        request.max_duration = Duration::from_secs(3);
        request.idle_after_first = Some(Duration::from_millis(200));
        request.max_datagrams = 1;
        respond(request, thread_collector)
    });
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let _ready = (0..100)
        .find_map(|_| {
            TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .inspect_err(|_| std::thread::sleep(Duration::from_millis(10)))
                .ok()
        })
        .expect("responder TCP listener should become ready");
    let (valid, _, _) = build_query(&token, 0, &CATALOG[0], 0).unwrap();
    let mut wrong_transaction = valid.to_vec();
    wrong_transaction[0..2].copy_from_slice(&0xbeef_u16.to_be_bytes());
    let (unplanned_sequence, _, _) = build_query(&token, 0, &CATALOG[0], 999).unwrap();
    let (unplanned_variant, _, _) = build_query(&token, 99, &CATALOG[0], 0).unwrap();
    let mut response = [0_u8; 2048];
    let queries: [&[u8]; 3] = [&wrong_transaction, &unplanned_sequence, &unplanned_variant];
    for query in queries {
        udp.send_to(query, (Ipv4Addr::LOCALHOST, port)).unwrap();
        assert!(udp.recv(&mut response).is_err());
    }
    udp.send_to(&valid, (Ipv4Addr::LOCALHOST, port)).unwrap();
    udp.recv(&mut response).unwrap();
    let report = handle.join().unwrap().unwrap();
    assert_eq!(report.received, 1);
    assert_eq!(report.replies_sent, 1);
    assert!(report.ignored >= 3);
    let records = collector.into_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].attempt_seq, 0);
}

#[test]
fn junk_datagrams_do_not_consume_the_matching_budget() {
    let port = free_port();
    let token = [7_u8; TOKEN_LEN];
    let collector = ResponderCollector::default();
    let thread_collector = collector.clone();
    let handle = std::thread::spawn(move || {
        let mut request = ResponderRequest::new(Ipv4Addr::LOCALHOST, port, token);
        request.max_duration = Duration::from_secs(3);
        request.idle_after_first = Some(Duration::from_millis(200));
        request.max_datagrams = 1;
        respond(request, thread_collector)
    });
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let _ready = (0..100)
        .find_map(|_| {
            std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .inspect_err(|_| std::thread::sleep(Duration::from_millis(10)))
                .ok()
        })
        .expect("responder TCP listener should become ready");
    udp.send_to(b"junk", (Ipv4Addr::LOCALHOST, port)).unwrap();
    let (query, _, _) = build_query(&token, 0, &CATALOG[0], 0).unwrap();
    let mut received = false;
    for _ in 0..20 {
        udp.send_to(&query, (Ipv4Addr::LOCALHOST, port)).unwrap();
        let mut response = [0_u8; 2048];
        if udp.recv(&mut response).is_ok() {
            received = true;
            break;
        }
    }
    assert!(received, "junk consumed the one-datagram budget");
    let report = handle.join().unwrap().unwrap();
    assert_eq!(report.received, 1);
    assert!(report.ignored >= 1);
    assert_eq!(collector.into_records().len(), 1);
}

#[test]
fn replayed_dns_identities_do_not_consume_budget_or_poison_records() {
    let port = free_port();
    let token = [7_u8; TOKEN_LEN];
    let collector = ResponderCollector::default();
    let thread_collector = collector.clone();
    let handle = std::thread::spawn(move || {
        let mut request = ResponderRequest::new(Ipv4Addr::LOCALHOST, port, token);
        request.max_duration = Duration::from_secs(3);
        request.idle_after_first = Some(Duration::from_millis(500));
        request.max_datagrams = 2;
        respond(request, thread_collector)
    });
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let _ready = (0..100)
        .find_map(|_| {
            TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .inspect_err(|_| std::thread::sleep(Duration::from_millis(10)))
                .ok()
        })
        .expect("responder TCP listener should become ready");
    let (first, _, _) = build_query(&token, 0, &CATALOG[0], 0).unwrap();
    let (second, _, _) = build_query(&token, 0, &CATALOG[0], 1).unwrap();
    let mut response = [0_u8; 2048];
    let mut answered = false;
    for _ in 0..50 {
        udp.send_to(&first, (Ipv4Addr::LOCALHOST, port)).unwrap();
        if udp.recv(&mut response).is_ok() {
            answered = true;
            break;
        }
    }
    assert!(answered, "responder did not answer the first query");
    udp.send_to(&first, (Ipv4Addr::LOCALHOST, port)).unwrap();
    assert!(udp.recv(&mut response).is_err());
    let mut replay_with_new_transaction = first.to_vec();
    replay_with_new_transaction[0..2].copy_from_slice(&0xbeef_u16.to_be_bytes());
    udp.send_to(&replay_with_new_transaction, (Ipv4Addr::LOCALHOST, port))
        .unwrap();
    assert!(udp.recv(&mut response).is_err());
    let mut answered = false;
    for _ in 0..50 {
        udp.send_to(&second, (Ipv4Addr::LOCALHOST, port)).unwrap();
        if udp.recv(&mut response).is_ok() {
            answered = true;
            break;
        }
    }
    assert!(answered, "responder did not answer the second query");
    let report = handle.join().unwrap().unwrap();
    assert_eq!(report.received, 2);
    assert_eq!(report.replies_sent, 2);
    assert!(report.ignored >= 1);
    let records = collector.into_records();
    assert_eq!(
        records
            .iter()
            .map(|record| record.attempt_seq)
            .collect::<Vec<_>>(),
        [0, 1]
    );
}

#[test]
fn tcp_reply_is_flushed_before_the_reception_limit_exits() {
    let port = free_port();
    let token = [7_u8; TOKEN_LEN];
    let collector = ResponderCollector::default();
    let thread_collector = collector.clone();
    let handle = std::thread::spawn(move || {
        let mut request = ResponderRequest::new(Ipv4Addr::LOCALHOST, port, token);
        request.max_duration = Duration::from_secs(3);
        request.max_datagrams = 1;
        respond(request, thread_collector)
    });
    let mut stream = (0..100)
        .find_map(|_| {
            TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .inspect_err(|_| std::thread::sleep(Duration::from_millis(10)))
                .ok()
        })
        .expect("TCP responder should connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (query, _, _) = build_query(&token, 0, &CATALOG[0], 0).unwrap();
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .unwrap();
    stream.write_all(&query).unwrap();
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).unwrap();
    let length = usize::from(u16::from_be_bytes(header));
    assert!(length > 0);
    let mut response = vec![0_u8; length];
    stream.read_exact(&mut response).unwrap();
    let report = handle.join().unwrap().unwrap();
    assert_eq!(report.received, 1);
    assert_eq!(collector.into_records().len(), 1);
}

#[test]
fn tcp_reception_limit_is_checked_between_simultaneous_queries() {
    let port = free_port();
    let token = [7_u8; TOKEN_LEN];
    let collector = ResponderCollector::default();
    let thread_collector = collector.clone();
    let handle = std::thread::spawn(move || {
        let mut request = ResponderRequest::new(Ipv4Addr::LOCALHOST, port, token);
        request.max_duration = Duration::from_secs(3);
        request.idle_after_first = None;
        request.max_datagrams = 1;
        respond(request, thread_collector)
    });
    let mut streams = Vec::new();
    for _ in 0..8 {
        let stream = (0..100)
            .find_map(|_| {
                TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .inspect_err(|_| std::thread::sleep(Duration::from_millis(10)))
                    .ok()
            })
            .expect("TCP responder should connect");
        streams.push(stream);
    }
    let barrier = Arc::new(std::sync::Barrier::new(streams.len() + 1));
    let writers: Vec<_> = streams
        .iter()
        .enumerate()
        .map(|(index, stream)| {
            let mut stream = stream.try_clone().unwrap();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let (query, _, _) = build_query(&token, 0, &CATALOG[0], index as u32).unwrap();
                barrier.wait();
                std::thread::sleep(Duration::from_millis(250));
                let _ = stream.write_all(&(query.len() as u16).to_be_bytes());
                let _ = stream.write_all(&query);
            })
        })
        .collect();
    barrier.wait();
    for writer in writers {
        writer.join().unwrap();
    }
    let report = handle.join().unwrap().unwrap();
    assert_eq!(report.received, 1);
    assert_eq!(report.replies_sent, 1);
    assert_eq!(collector.into_records().len(), 1);
    drop(streams);
}

#[test]
fn idle_tcp_connection_does_not_block_udp_answers() {
    let port = free_port();
    let token = [7_u8; TOKEN_LEN];
    let collector = ResponderCollector::default();
    let thread_collector = collector.clone();
    let handle = std::thread::spawn(move || {
        let mut request = ResponderRequest::new(Ipv4Addr::LOCALHOST, port, token);
        request.max_duration = Duration::from_secs(3);
        request.idle_after_first = Some(Duration::from_millis(200));
        respond(request, thread_collector)
    });
    let mut idle = (0..100)
        .find_map(|_| {
            TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .inspect_err(|_| std::thread::sleep(Duration::from_millis(10)))
                .ok()
        })
        .expect("idle TCP should connect");
    idle.write_all(&[0]).unwrap();

    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let (query, _, _) = build_query(&token, 0, &CATALOG[0], 0).unwrap();
    let mut received = false;
    for _ in 0..20 {
        udp.send_to(&query, (Ipv4Addr::LOCALHOST, port)).unwrap();
        let mut response = [0_u8; 2048];
        if udp.recv(&mut response).is_ok() {
            received = true;
            break;
        }
    }
    assert!(received, "idle TCP connection blocked the UDP responder");
    drop(idle);
    let report = handle.join().unwrap().unwrap();
    assert_eq!(report.received, 1);
    assert_eq!(collector.into_records().len(), 1);
}
