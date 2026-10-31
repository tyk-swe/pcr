// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

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

    let started = Instant::now();
    let mut last_received: Option<Instant> = None;
    let mut report = ResponderReport::default();
    let mut buffer = vec![0_u8; MAX_DATAGRAM];

    loop {
        if let Some(cancellation) = &request.cancellation {
            cancellation.check().map_err(Error::from)?;
        }
        if started.elapsed() >= request.max_duration {
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
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(io_error(error)),
        };
        let Some(probe) = canary::parse_probe(&buffer[..len]) else {
            report.ignored += 1;
            continue;
        };
        if probe.token != request.token {
            report.ignored += 1;
            continue;
        }
        last_received = Some(Instant::now());
        report.received += 1;
        let record = ReceptionRecord {
            variant_index: probe.variant_index,
            attempt_seq: probe.attempt_seq,
            source,
            payload_sha256: hex(&probe.payload_sha256),
        };
        sink.publish(ResponderEvent::Received(record))
            .map_err(|source: BoundaryError| Error::Output { source })?;
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
        probe_socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        thread::sleep(Duration::from_millis(200));
        probe_socket
            .send_to(b"not a canary", target)
            .expect("send junk");
        let payload = canary::build_probe(&token, 2, 9, 512);
        probe_socket.send_to(&payload, target).expect("send probe");
        let mut buffer = [0_u8; 128];
        let (len, _) = probe_socket.recv_from(&mut buffer).expect("reply arrives");
        let reply = canary::parse_reply(&buffer[..len]).expect("reply parses");
        assert_eq!(reply.variant_index, 2);
        assert_eq!(reply.attempt_seq, 9);
        assert_eq!(
            reply.received_payload_sha256,
            canary::payload_sha256(&payload)
        );

        let report = handle.join().expect("responder thread").expect("responds");
        assert_eq!(report.received, 1);
        assert_eq!(report.ignored, 1);
        assert_eq!(report.replies_sent, 1);
        let aggregate = collector.finish(report);
        assert_eq!(aggregate.records.len(), 1);
        assert_eq!(aggregate.records[0].attempt_seq, 9);
    }
}
