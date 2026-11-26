// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::field::hex::compact_hex;

use super::ResponderRequest;
use super::canary;
use super::error::Error;
use super::report::{ReceptionRecord, ResponderEvent, ResponderReport};
use crate::clock::Clock;
use crate::policy::{Operation, Policy, SocketLimits, SocketOperation};
use crate::providers::UdpProviders;
use crate::{Client, Sink};

const POLL: Duration = Duration::from_millis(50);
const MAX_DATAGRAM: usize = 65_535;

fn io_error(source: io::Error) -> Error {
    Error::ResponderIo {
        message: source.to_string(),
    }
}

trait ResponderSocket {
    fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize>;
}

impl ResponderSocket for UdpSocket {
    fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Self::recv_from(self, buffer)
    }

    fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        Self::send_to(self, payload, target)
    }
}

fn authorize_responder(policy: &Policy, request: &ResponderRequest) -> Result<(), Error> {
    policy
        .validate()
        .map_err(|source| Error::Authorization(BoundaryError::from_error(source)))?;
    policy
        .authorize_destination(IpAddr::V4(request.bind))
        .map_err(|source| Error::Authorization(BoundaryError::from_error(source)))?;
    let reply_count = u64::try_from(request.max_datagrams).unwrap_or(u64::MAX);
    let reply_bytes = reply_count.saturating_mul(canary::REPLY_LEN as u64);
    let operation = SocketOperation::new(&[], SocketLimits::new(0, reply_count, reply_bytes))
        .map_err(|source| Error::Authorization(BoundaryError::from_error(source)))?;
    policy
        .authorize(Operation::Socket(operation))
        .map_err(|source| Error::Authorization(BoundaryError::from_error(source)))
}

fn run_responder<S, C, Q>(
    request: &ResponderRequest,
    socket: &Q,
    policy: &Policy,
    clock: &C,
    deadline: &Deadline,
    mut sink: S,
) -> Result<ResponderReport, Error>
where
    S: Sink<ResponderEvent, Ack = ()>,
    C: Clock,
    Q: ResponderSocket,
{
    let mut last_received: Option<Instant> = None;
    let mut report = ResponderReport::default();
    let mut buffer = vec![0_u8; MAX_DATAGRAM];

    loop {
        deadline.check_cancelled().map_err(Error::from)?;
        if deadline.check().is_err() {
            return Ok(report);
        }
        if let (Some(idle), Some(last)) = (request.idle_after_first, last_received)
            && clock.now().saturating_duration_since(last) >= idle
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
        deadline.check_cancelled().map_err(Error::from)?;
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
        policy
            .authorize_destination(source.ip())
            .map_err(|source| Error::Authorization(BoundaryError::from_error(source)))?;
        last_received = Some(clock.now());
        report.received += 1;
        let record = ReceptionRecord {
            variant_index: probe.variant_index,
            attempt_seq: probe.attempt_seq,
            source,
            payload_sha256: compact_hex(&probe.payload_sha256),
        };
        sink.publish_controlled(ResponderEvent::Received(record), deadline)
            .map_err(|source: BoundaryError| Error::Output { source })?;
        deadline.check_cancelled().map_err(Error::from)?;
        if deadline.check().is_err() {
            return Ok(report);
        }
        socket
            .send_to(&canary::build_reply(&probe), source)
            .map_err(io_error)?;
        report.replies_sent += 1;
    }
}

impl<P: UdpProviders, K: Clock> Client<P, K> {
    /// Policy-gated differential canary responder using this client's policy and clock.
    pub fn respond_differential<S>(
        &self,
        request: ResponderRequest,
        sink: S,
    ) -> Result<ResponderReport, Error>
    where
        S: Sink<ResponderEvent, Ack = ()>,
    {
        request.validate()?;
        authorize_responder(&self.policy, &request)?;
        let socket =
            UdpSocket::bind(SocketAddr::from((request.bind, request.port))).map_err(io_error)?;
        socket.set_read_timeout(Some(POLL)).map_err(io_error)?;
        let mut deadline = self.deadline(request.max_duration);
        if let Some(cancellation) = request.cancellation.clone() {
            let clock = self.clock.clone();
            let request_deadline =
                Deadline::with_time_source(request.max_duration, move || clock.now())
                    .with_cancellation(Some(cancellation));
            deadline = deadline.with_parent(Some(Arc::new(request_deadline)));
        }
        run_responder(
            &request,
            &socket,
            &self.policy,
            &self.clock,
            &deadline,
            sink,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::differential::{ResponderCollector, generate_token};
    use std::net::Ipv4Addr;
    use std::thread;

    fn test_client() -> Client<impl UdpProviders> {
        Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            Policy::default(),
            crate::ProviderSet::udp(packetcraftr_netio::udp::SystemProvider),
        )
    }

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
            let handle = thread::spawn(move || {
                let mut collector = ResponderCollector::default();
                let mut request = ResponderRequest::new(Ipv4Addr::LOCALHOST, port, token);
                request.max_duration = Duration::from_secs(10);
                request.idle_after_first = Some(Duration::from_millis(300));
                let outcome = test_client().respond_differential(request, &mut collector);
                (outcome, collector)
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
                started = Some((handle, reply));
                break;
            }
            if handle.is_finished() {
                match handle.join() {
                    Ok((Err(error), _)) => {
                        eprintln!("responder start failed, retrying on a new port: {error}");
                        continue;
                    }
                    Ok((Ok(_), _)) => panic!("responder exited without answering"),
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            }
        }
        let (handle, reply) = started.expect("responder never answered");
        let reply = reply.expect("reply parsed");
        assert_eq!(reply.variant_index, 2);
        assert_eq!(reply.attempt_seq, 9);
        assert_eq!(
            reply.received_payload_sha256,
            canary::payload_sha256(&payload)
        );

        let (report, collector) = handle.join().expect("responder thread");
        let report = report.expect("responds");
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
        let report = respond_with_blocked_sink(None).expect("responder stops normally");
        assert_eq!(report.received, 1);
        assert_eq!(report.replies_sent, 0);
    }

    #[test]
    fn responder_reports_cancellation_after_a_blocked_sink_outlives_its_duration() {
        let cancellation = packetcraftr_core::budget::Cancellation::default();
        let outcome = respond_with_blocked_sink(Some(cancellation));
        assert!(
            matches!(&outcome, Err(Error::Cancelled(_))),
            "expected cancellation, got {outcome:?}"
        );
    }

    fn respond_with_blocked_sink(
        cancellation: Option<packetcraftr_core::budget::Cancellation>,
    ) -> Result<ResponderReport, Error> {
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
        let responder_cancellation = cancellation.clone();
        let token = [0x42; 16];
        let handle = thread::spawn(move || {
            let mut request = ResponderRequest::new(Ipv4Addr::LOCALHOST, port, token);
            request.max_duration = Duration::from_millis(400);
            request.cancellation = responder_cancellation;
            test_client().respond_differential(
                request,
                crate::forwarding(move |_, _| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                }),
            )
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
        if let Some(cancellation) = cancellation {
            cancellation.cancel();
        }
        thread::sleep(Duration::from_millis(550));
        release_tx.send(()).unwrap();
        let mut reply = [0_u8; 128];
        assert!(socket.recv_from(&mut reply).is_err(), "no late UDP reply");
        handle.join().unwrap()
    }

    #[test]
    fn client_responder_rejects_unauthorized_bind_and_peer_and_honors_virtual_clock() {
        use std::collections::VecDeque;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicU64, Ordering};

        #[derive(Clone)]
        struct VirtualClock {
            base: Instant,
            millis: Arc<AtomicU64>,
        }

        impl Clock for VirtualClock {
            type Error = std::convert::Infallible;

            fn now(&self) -> Instant {
                self.base + Duration::from_millis(self.millis.load(Ordering::SeqCst))
            }

            fn wall_now(&self) -> std::time::SystemTime {
                SystemClock.wall_now()
            }

            fn sleep(&self, delay: Duration, _: &Deadline) -> Result<(), Self::Error> {
                self.millis
                    .fetch_add(delay.as_millis() as u64, Ordering::SeqCst);
                Ok(())
            }
        }

        type IncomingDatagram = io::Result<(Vec<u8>, SocketAddr)>;

        struct ScriptedSocket {
            incoming: Mutex<VecDeque<IncomingDatagram>>,
            sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
            advance_on_poll: Arc<AtomicU64>,
        }

        impl ResponderSocket for ScriptedSocket {
            fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                match self.incoming.lock().unwrap().pop_front() {
                    Some(Ok((bytes, peer))) => {
                        buffer[..bytes.len()].copy_from_slice(&bytes);
                        Ok((bytes.len(), peer))
                    }
                    Some(Err(error)) => Err(error),
                    None => {
                        self.advance_on_poll.fetch_add(250, Ordering::SeqCst);
                        Err(io::Error::from(io::ErrorKind::WouldBlock))
                    }
                }
            }

            fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
                self.sent.lock().unwrap().push((payload.to_vec(), target));
                Ok(payload.len())
            }
        }

        let token = [0x5a; 16];
        let public_bind = ResponderRequest::new(Ipv4Addr::new(8, 8, 8, 8), 40000, token);
        let client = test_client();
        let err = client
            .respond_differential(public_bind, &mut ResponderCollector::default())
            .unwrap_err();
        assert!(matches!(err, Error::Authorization(_)), "{err:?}");

        let millis = Arc::new(AtomicU64::new(0));
        let clock = VirtualClock {
            base: SystemClock.now(),
            millis: Arc::clone(&millis),
        };
        let mut request = ResponderRequest::new(Ipv4Addr::LOCALHOST, 40001, token);
        request.max_duration = Duration::from_secs(60);
        request.idle_after_first = Some(Duration::from_millis(500));
        let probe = canary::build_probe(&token, 1, 3, 128);
        let socket = ScriptedSocket {
            incoming: Mutex::new(VecDeque::from([Ok((
                probe.clone(),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 50000)),
            ))])),
            sent: Mutex::new(Vec::new()),
            advance_on_poll: Arc::clone(&millis),
        };
        let time = clock.clone();
        let deadline = Deadline::with_time_source(request.max_duration, move || time.now());
        let mut collector = ResponderCollector::default();
        let report = run_responder(
            &request,
            &socket,
            &Policy::default(),
            &clock,
            &deadline,
            &mut collector,
        )
        .expect("virtual clock idle stop succeeds");
        assert_eq!(report.received, 1);
        assert_eq!(report.replies_sent, 1);
        assert_eq!(socket.sent.lock().unwrap().len(), 1);
        assert!(millis.load(Ordering::SeqCst) >= 500);

        let public_peer_socket = ScriptedSocket {
            incoming: Mutex::new(VecDeque::from([Ok((
                probe,
                SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 50000)),
            ))])),
            sent: Mutex::new(Vec::new()),
            advance_on_poll: Arc::new(AtomicU64::new(0)),
        };
        let err = run_responder(
            &request,
            &public_peer_socket,
            &Policy::default(),
            &clock,
            &deadline,
            &mut ResponderCollector::default(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Authorization(_)), "{err:?}");
        assert!(public_peer_socket.sent.lock().unwrap().is_empty());

        let failing_socket = ScriptedSocket {
            incoming: Mutex::new(VecDeque::from([Ok((
                canary::build_probe(&token, 1, 4, 128),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 50001)),
            ))])),
            sent: Mutex::new(Vec::new()),
            advance_on_poll: Arc::new(AtomicU64::new(0)),
        };
        let fail_millis = Arc::new(AtomicU64::new(0));
        let fail_clock = VirtualClock {
            base: SystemClock.now(),
            millis: Arc::clone(&fail_millis),
        };
        let fail_time = fail_clock.clone();
        let fail_deadline =
            Deadline::with_time_source(Duration::from_millis(100), move || fail_time.now());
        let err = run_responder(
            &request,
            &failing_socket,
            &Policy::default(),
            &fail_clock,
            &fail_deadline,
            crate::forwarding(move |_, _| {
                fail_millis.store(200, Ordering::SeqCst);
                Err(BoundaryError::from_error(Error::ResponderIo {
                    message: "sink broken".to_owned(),
                }))
            }),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Output { .. }), "{err:?}");
        assert!(failing_socket.sent.lock().unwrap().is_empty());
    }
}
