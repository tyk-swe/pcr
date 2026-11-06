// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::clock::{Clock, SystemClock};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;

use super::ResponderRequest;
use super::canary;
use super::error::Error;
use super::report::{ReceptionRecord, ResponderEvent, ResponderReport, hex};
use crate::Sink;

const POLL: Duration = Duration::from_millis(50);
const MAX_DATAGRAM: usize = 65_535;

fn io_error(source: io::Error) -> Error {
    Error::ResponderIo {
        message: source.to_string(),
    }
}

pub fn respond<S>(request: ResponderRequest, mut sink: S) -> Result<ResponderReport, Error>
where
    S: Sink<ResponderEvent, Ack = ()>,
{
    request.validate()?;
    let socket =
        UdpSocket::bind(SocketAddr::from((request.bind, request.port))).map_err(io_error)?;
    socket.set_read_timeout(Some(POLL)).map_err(io_error)?;

    let deadline =
        Deadline::new(request.max_duration).with_cancellation(request.cancellation.clone());
    let mut last_received: Option<Instant> = None;
    let mut report = ResponderReport::default();
    let mut buffer = vec![0_u8; MAX_DATAGRAM];

    loop {
        if let Some(cancellation) = &request.cancellation {
            cancellation.check().map_err(Error::from)?;
        }
        if deadline.check().is_err() {
            return Ok(report);
        }
        if let (Some(idle), Some(last)) = (request.idle_after_first, last_received)
            && last.elapsed() >= idle
        {
            return Ok(report);
        }
        if report.received + report.ignored >= request.max_datagrams {
            return Ok(report);
        }
        let (len, source) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error) if packetcraftr_netio::bounded::retryable(&error) => {
                continue;
            }
            Err(error) => return Err(io_error(error)),
        };
        if deadline.check().is_err() {
            return Ok(report);
        }
        let Some(probe) = canary::parse_probe(&buffer[..len]) else {
            report.ignored += 1;
            continue;
        };
        if probe.token != request.token {
            report.ignored += 1;
            continue;
        }
        last_received = Some(SystemClock.now());
        report.received += 1;
        let record = ReceptionRecord {
            variant_index: probe.variant_index,
            attempt_seq: probe.attempt_seq,
            source,
            payload_sha256: hex(&probe.payload_sha256),
        };
        sink.publish_controlled(ResponderEvent::Received(record), &deadline)
            .map_err(|source: BoundaryError| Error::Output { source })?;
        if deadline.check().is_err() {
            return Ok(report);
        }
        let reply = canary::build_reply(&probe);
        if reply.len() < len {
            socket.send_to(&reply, source).map_err(io_error)?;
            report.replies_sent += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::differential::{ResponderCollector, generate_token};
    use std::net::Ipv4Addr;
    use std::thread;

    #[test]
    fn responder_answers_only_token_bearing_probes() {
        let token = generate_token().expect("token");
        let probe_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind probe");
        probe_socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .expect("timeout");
        let payload = canary::build_probe(&token, 2, 9, 512);
        let mut buffer = [0_u8; 128];

        let mut started = None;
        for _ in 0..5 {
            let port = {
                let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
                socket.local_addr().expect("addr").port()
            };
            let collector = ResponderCollector::default();
            let responder_collector = collector.clone();
            let handle = thread::spawn(move || {
                let mut request = ResponderRequest::new(Ipv4Addr::LOCALHOST, port, token);
                request.max_duration = Duration::from_secs(10);
                request.idle_after_first = Some(Duration::from_millis(300));
                respond(request, responder_collector)
            });
            let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            let mut reply = None;
            let probe_deadline = SystemClock.now() + Duration::from_secs(3);
            while SystemClock.now() < probe_deadline {
                if handle.is_finished() {
                    break;
                }
                probe_socket.send_to(&payload, target).expect("send probe");
                match probe_socket.recv_from(&mut buffer) {
                    Ok((len, _)) => {
                        reply = canary::parse_reply(&buffer[..len]);
                        if reply.is_some() {
                            break;
                        }
                    }
                    Err(_) => thread::sleep(Duration::from_millis(50)),
                }
            }
            if reply.is_some() {
                let second = canary::build_probe(&token, 2, 10, 512);
                let junk_deadline = SystemClock.now() + Duration::from_secs(3);
                let mut second_answered = false;
                while SystemClock.now() < junk_deadline && !second_answered {
                    probe_socket
                        .send_to(b"not a canary", target)
                        .expect("send junk");
                    probe_socket
                        .send_to(&second, target)
                        .expect("send second probe");
                    match probe_socket.recv_from(&mut buffer) {
                        Ok((len, _)) => {
                            second_answered = canary::parse_reply(&buffer[..len])
                                .is_some_and(|parsed| parsed.attempt_seq == 10);
                        }
                        Err(_) => thread::sleep(Duration::from_millis(50)),
                    }
                }
            }
            if reply.is_some() {
                started = Some((handle, collector, reply));
                break;
            }
            if handle.is_finished() {
                if let Ok(Err(error)) = handle.join() {
                    eprintln!("responder start failed, retrying on a new port: {error}");
                    continue;
                }
                panic!("responder exited without answering");
            }
        }
        let (handle, collector, reply) = started.expect("responder never answered");
        let reply = reply.expect("reply parsed");
        assert_eq!(reply.variant_index, 2);
        assert_eq!(reply.attempt_seq, 9);
        assert_eq!(
            reply.received_payload_sha256,
            canary::payload_sha256(&payload)
        );

        let report = handle.join().expect("responder thread").expect("responds");
        assert!(report.received >= 1, "received {}", report.received);
        assert!(report.ignored >= 1, "ignored {}", report.ignored);
        assert!(report.replies_sent >= 1);
        let aggregate = collector.finish(report);
        assert!(
            aggregate
                .records
                .iter()
                .any(|record| record.attempt_seq == 9)
        );
    }

    #[test]
    fn responder_does_not_reply_after_a_blocked_sink_outlives_its_duration() {
        let port = {
            let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            socket.local_addr().unwrap().port()
        };
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let token = [0x42; 16];
        let handle = thread::spawn(move || {
            let mut request = ResponderRequest::new(Ipv4Addr::LOCALHOST, port, token);
            request.max_duration = Duration::from_millis(400);
            respond(request, move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });
        let payload = canary::build_probe(&token, 1, 7, 256);
        let start_deadline = SystemClock.now() + Duration::from_secs(2);
        let mut entered = false;
        while SystemClock.now() < start_deadline && !handle.is_finished() {
            socket
                .send_to(&payload, (Ipv4Addr::LOCALHOST, port))
                .unwrap();
            if entered_rx.recv_timeout(Duration::from_millis(20)).is_ok() {
                entered = true;
                break;
            }
        }
        assert!(entered, "sink received the probe");
        thread::sleep(Duration::from_millis(550));
        release_tx.send(()).unwrap();
        let mut reply = [0_u8; 128];
        assert!(socket.recv_from(&mut reply).is_err(), "no late UDP reply");
        let report = handle.join().unwrap().expect("responder stops normally");
        assert_eq!(report.received, 1);
        assert_eq!(report.replies_sent, 0);
    }
}
