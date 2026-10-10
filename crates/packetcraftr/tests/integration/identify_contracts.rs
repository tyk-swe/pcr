// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeSet, VecDeque};
use std::io::{self, Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use packetcraftr::{Client, ProviderSet, SystemProviders, identify, policy::Policy};
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::document::service_probes::{Confidence, Corpus, ObservationOutcome};
use packetcraftr_core::protocol::{
    application::dns::{Dns, Record, RecordValue},
    builtin,
};
use packetcraftr_netio::{bounded, tcp, udp};

#[derive(Clone, Default)]
struct FakeTcp {
    replies: Arc<Mutex<VecDeque<Vec<u8>>>>,
    endpoints: Arc<Mutex<Vec<SocketAddr>>>,
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
    failures: Arc<Mutex<VecDeque<io::ErrorKind>>>,
    advance: Option<TestClock>,
    peer: Option<SocketAddr>,
    pending_cancellation: Option<PendingCancellation>,
    dns_reply: Option<DnsReply>,
    timeout_after_response: bool,
    read_chunk: Option<usize>,
}

#[derive(Clone, Copy)]
enum DnsReply {
    Echo,
    WrongId,
}

#[derive(Clone)]
struct PendingCancellation {
    signal: Cancellation,
    release: Arc<(Mutex<bool>, Condvar)>,
}

impl FakeTcp {
    fn replying(replies: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            replies: Arc::new(Mutex::new(replies.into_iter().collect())),
            ..Self::default()
        }
    }
}

impl tcp::Provider for FakeTcp {
    type Stream = FakeStream;

    fn connect(&self, endpoint: SocketAddr, deadline: &Deadline) -> Result<FakeStream, tcp::Error> {
        let max_timeout = if self.pending_cancellation.is_some() {
            10
        } else {
            2
        };
        assert!(deadline.remaining().expect("live deadline") <= Duration::from_secs(max_timeout));
        self.endpoints.lock().expect("endpoints").push(endpoint);
        if let Some(pending) = &self.pending_cancellation {
            pending.signal.cancel();
            let (release, ready) = &*pending.release;
            let (_released, timeout) = ready
                .wait_timeout_while(
                    release.lock().unwrap(),
                    Duration::from_secs(5),
                    |released| !*released,
                )
                .expect("pending cancellation gate");
            assert!(
                !timeout.timed_out(),
                "caller must release its cancelled worker"
            );
            return Err(pending.signal.check().expect_err("cancelled").into());
        }
        if let Some(clock) = &self.advance {
            clock.advance(Duration::from_secs(1));
        }
        if let Some(failure) = self.failures.lock().expect("failures").pop_front() {
            return Err(io::Error::from(failure).into());
        }
        Ok(FakeStream {
            response: Cursor::new(
                self.replies
                    .lock()
                    .expect("responses")
                    .pop_front()
                    .unwrap_or_default(),
            ),
            writes: Arc::clone(&self.writes),
            peer: self.peer.unwrap_or(endpoint),
            dns_reply: self.dns_reply,
            timeout_after_response: self.timeout_after_response,
            read_chunk: self.read_chunk,
        })
    }
}

struct FakeStream {
    response: Cursor<Vec<u8>>,
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
    peer: SocketAddr,
    dns_reply: Option<DnsReply>,
    timeout_after_response: bool,
    read_chunk: Option<usize>,
}

impl Read for FakeStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.timeout_after_response
            && self.response.position() == self.response.get_ref().len() as u64
        {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let limit = self.read_chunk.unwrap_or(bytes.len()).min(bytes.len());
        self.response.read(&mut bytes[..limit])
    }
}

impl Write for FakeStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes.lock().expect("writes").push(bytes.to_vec());
        if let Some(reply) = self.dns_reply {
            let mut response = dns_response(&bytes[2..]);
            if matches!(reply, DnsReply::WrongId) {
                response[0] ^= 0xff;
            }
            let mut frame = (response.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&response);
            self.response = Cursor::new(frame);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl tcp::Stream for FakeStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:40000".parse().expect("local"))
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        assert!(
            timeout
                .is_some_and(|timeout| !timeout.is_zero() && timeout <= Duration::from_millis(25))
        );
        Ok(())
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }
}

#[derive(Clone, Default)]
struct FakeUdp {
    calls: Arc<Mutex<Vec<DatagramCall>>>,
    wrong_id: bool,
    cancellation: Option<Cancellation>,
    empty_response: bool,
    peer: Option<SocketAddr>,
    failures: Arc<Mutex<VecDeque<io::ErrorKind>>>,
}

type DatagramCall = (SocketAddr, Vec<u8>, usize);
type FakeProviders = packetcraftr::WithUdp<ProviderSet<(), (), (), (), FakeTcp, ()>, FakeUdp>;

impl udp::Provider for FakeUdp {
    fn exchange(
        &self,
        endpoint: SocketAddr,
        request: &[u8],
        max_response: usize,
        deadline: &Deadline,
    ) -> Result<udp::Reply, udp::Error> {
        assert!(!deadline.remaining().expect("live deadline").is_zero());
        self.calls
            .lock()
            .expect("UDP calls")
            .push((endpoint, request.to_vec(), max_response));
        if let Some(failure) = self.failures.lock().unwrap().pop_front() {
            return Err(io::Error::from(failure).into());
        }
        let mut response = if self.empty_response {
            Vec::new()
        } else {
            dns_response(request)
        };
        if self.wrong_id && !response.is_empty() {
            response[0] ^= 0xff;
        }
        let truncated = response.len() >= max_response;
        response.truncate(max_response);
        if let Some(signal) = &self.cancellation {
            signal.cancel();
        }
        Ok(udp::Reply {
            peer: self.peer.unwrap_or(endpoint),
            local: "127.0.0.1:40001".parse().expect("local"),
            exchange: bounded::Exchange {
                response: Bytes::from(response),
                bytes_sent: request.len(),
                outcome: if self.cancellation.is_some() {
                    bounded::Outcome::Cancelled
                } else if truncated {
                    bounded::Outcome::Truncated
                } else {
                    bounded::Outcome::Complete
                },
            },
        })
    }
}

#[derive(Clone)]
struct TestClock {
    started: Instant,
    elapsed: Arc<Mutex<Duration>>,
}

impl TestClock {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            elapsed: Arc::new(Mutex::new(Duration::ZERO)),
        }
    }
    fn advance(&self, elapsed: Duration) {
        *self.elapsed.lock().expect("clock") += elapsed;
    }
}

impl packetcraftr::clock::Clock for TestClock {
    type Error = std::convert::Infallible;
    fn now(&self) -> Instant {
        self.started + *self.elapsed.lock().expect("clock")
    }
    fn sleep(&self, elapsed: Duration, _: &Deadline) -> Result<(), Self::Error> {
        self.advance(elapsed);
        Ok(())
    }
}

fn dns_response(request: &[u8]) -> Vec<u8> {
    let mut message = Dns::try_from(request).expect("read-only DNS query");
    message.edit(|message| {
        message.response = true;
        if message.questions[0].query_type == 16 {
            message.answers.push(Record {
                owner: message.questions[0].name.clone(),
                class: 3,
                ttl: 0,
                value: RecordValue::Txt(vec![Bytes::from_static(b"BIND 9.20.1")]),
            });
        }
    });
    message.to_wire().expect("DNS reply").to_vec()
}

fn endpoint(port: u16, transport: identify::Transport) -> identify::Endpoint {
    identify::Endpoint {
        address: SocketAddr::from(([127, 0, 0, 1], port)),
        transport,
    }
}

fn request(endpoints: Vec<identify::Endpoint>) -> identify::Request {
    identify::Request::new(
        endpoints,
        identify::builtin_corpus().expect("corpus"),
        identify::builtin_exclusions().expect("exclusions"),
    )
}

fn corpus_with(request: &mut identify::Request, probe: &str) {
    let mut corpus: Corpus = (*request.corpus).clone();
    corpus.probes.retain(|entry| entry.id == probe);
    corpus.matches.retain(|entry| entry.probe == probe);
    request.corpus = Arc::new(corpus);
}

fn client(tcp: FakeTcp, udp: FakeUdp) -> Client<FakeProviders> {
    Client::new(
        builtin::registry(),
        Policy::default(),
        ProviderSet::tcp(tcp, ()).with_udp(udp),
    )
}

#[test]
fn ssh_banner_on_nonstandard_port_is_only_a_claim_and_sends_no_bytes() {
    let tcp = FakeTcp::replying([b"notice\r\nSSH-2.0-OpenSSH_9.8p1 fixture\r\n".to_vec()]);
    let mut request = request(vec![endpoint(32222, identify::Transport::Tcp)]);
    request.intensity = 1;
    let report = client(tcp.clone(), FakeUdp::default())
        .identify(&request)
        .expect("identify");
    assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
    assert_eq!(report.records[0].candidates[0].product, "OpenSSH");
    assert_eq!(
        report.records[0].candidates[0].version.as_deref(),
        Some("9.8p1")
    );
    assert_eq!(
        report.records[0].candidates[0].confidence,
        Confidence::Claim
    );
    assert!(tcp.writes.lock().expect("writes").is_empty());
    assert_eq!(
        *tcp.endpoints.lock().expect("endpoints"),
        vec![request.endpoints[0].address]
    );
    assert_eq!(report.usage.attempts, 1);
    assert_eq!(report.usage.write_bytes, 0);
    assert_eq!(
        report.usage.read_bytes,
        report.records[0].probes[0].response.len() as u64
    );
}

#[test]
fn http_redirect_and_authentication_headers_never_trigger_another_request() {
    let reply = b"HTTP/1.0 302 Found\r\nServer: nginx/1.27.2\r\nLocation: http://192.0.2.9/private\r\nWWW-Authenticate: Basic realm=fixture\r\n\r\n";
    let tcp = FakeTcp::replying([reply.to_vec()]);
    let mut request = request(vec![endpoint(38080, identify::Transport::Tcp)]);
    corpus_with(&mut request, "http-head");
    let report = client(tcp.clone(), FakeUdp::default())
        .identify(&request)
        .expect("identify");
    assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
    assert_eq!(
        report.records[0].candidates[0].version.as_deref(),
        Some("1.27.2")
    );
    assert_eq!(tcp.endpoints.lock().expect("endpoints").len(), 1);
    assert_eq!(
        *tcp.writes.lock().expect("writes"),
        vec![b"HEAD / HTTP/1.0\r\n\r\n".to_vec()]
    );
    assert_eq!(report.records[0].probes[0].response, reply);
}

#[test]
fn unknown_malformed_truncated_and_misleading_banners_have_explicit_outcomes() {
    for (bytes, limit, outcome) in [
        (
            &b"not a known service\r\n"[..],
            1024,
            identify::Outcome::Unknown,
        ),
        (
            &b"SSH-3.0-OpenSSH_9.8\r\n"[..],
            1024,
            identify::Outcome::Malformed,
        ),
        (
            &b"SSH-2.0-OpenSSH_9.8\r\n"[..],
            12,
            identify::Outcome::Truncated,
        ),
        (
            &b"HTTP/1.0 200 OK\r\nServer: OpenSSH_9.8\r\n\r\n"[..],
            1024,
            identify::Outcome::Unknown,
        ),
    ] {
        let mut request = request(vec![endpoint(32222, identify::Transport::Tcp)]);
        request.intensity = 1;
        request.limits.probe.read_bytes = limit;
        let report = client(FakeTcp::replying([bytes.to_vec()]), FakeUdp::default())
            .identify(&request)
            .expect("identify");
        assert_eq!(report.records[0].outcome, outcome);
        assert!(report.records[0].candidates.is_empty());
        assert_eq!(
            report.records[0].probes[0].response,
            &bytes[..bytes.len().min(limit as usize)]
        );
    }
}

#[test]
fn conflicting_claims_cannot_publish_an_exact_version() {
    let tcp = FakeTcp::replying([
        b"HTTP/1.0 200 OK\r\nServer: nginx/1.27.2\r\nServer: Apache/2.4.62\r\n\r\n".to_vec(),
    ]);
    let mut request = request(vec![endpoint(38080, identify::Transport::Tcp)]);
    corpus_with(&mut request, "http-head");
    let report = client(tcp, FakeUdp::default())
        .identify(&request)
        .expect("identify");
    assert_eq!(report.records[0].outcome, identify::Outcome::Ambiguous);
    assert_eq!(report.records[0].candidates.len(), 2);
    assert!(
        report.records[0]
            .candidates
            .iter()
            .all(|candidate| candidate.version.is_none())
    );
}

#[test]
fn matching_truncation_is_distinct_from_a_complete_protocol_observation() {
    let reply = b"HTTP/1.0 200 OK\r\nServer: nginx/1.20\r\nServer: nginx/1.21\r\nServer: nginx/1.22\r\nServer: nginx/1.23\r\n\r\n";
    let tcp = FakeTcp::replying([reply.to_vec()]);
    let mut request = request(vec![endpoint(38080, identify::Transport::Tcp)]);
    corpus_with(&mut request, "http-head");
    let mut corpus = (*request.corpus).clone();
    let rule = corpus
        .matches
        .iter()
        .find(|rule| rule.product == "nginx")
        .expect("nginx rule")
        .clone();
    corpus.matches = (0..129)
        .map(|index| {
            let mut rule = rule.clone();
            rule.id = format!("candidate-{index}");
            rule
        })
        .collect();
    request.corpus = Arc::new(corpus);
    let report = client(tcp, FakeUdp::default())
        .identify(&request)
        .expect("bounded matching");
    assert!(report.complete);
    let record = &report.records[0];
    assert_eq!(record.outcome, identify::Outcome::Truncated);
    assert!(record.candidates.is_empty());
    let evidence = &record.probes[0];
    assert_eq!(evidence.response, reply);
    assert_eq!(evidence.observation.outcome, ObservationOutcome::Complete);
    assert_eq!(
        evidence.identification.outcome,
        packetcraftr_core::document::service_probes::MatchOutcome::Truncated
    );
    assert!(evidence.identification.candidates.is_empty());
}

#[test]
fn udp_dns_protocol_and_product_claim_support_one_endpoint_without_false_ambiguity() {
    let udp = FakeUdp::default();
    let mut request = request(vec![endpoint(35353, identify::Transport::Udp)]);
    request.intensity = 3;
    let report = client(FakeTcp::default(), udp.clone())
        .identify(&request)
        .expect("identify");
    assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
    assert!(
        report.records[0]
            .candidates
            .iter()
            .any(|candidate| candidate.product == "DNS service" && candidate.version.is_none())
    );
    assert!(
        report.records[0]
            .candidates
            .iter()
            .any(|candidate| candidate.product == "BIND"
                && candidate.version.as_deref() == Some("9.20.1"))
    );
    let calls = udp.calls.lock().expect("UDP calls");
    assert_eq!(calls.len(), 2);
    assert!(
        calls
            .iter()
            .all(|(address, _, _)| *address == request.endpoints[0].address)
    );
    assert_ne!(&calls[0].1[..2], &calls[1].1[..2]);
    assert_eq!(
        report.usage.write_bytes,
        calls
            .iter()
            .map(|(_, bytes, _)| bytes.len() as u64)
            .sum::<u64>()
    );
}

#[test]
fn udp_wrong_transaction_id_remains_malformed_evidence() {
    let udp = FakeUdp {
        wrong_id: true,
        ..FakeUdp::default()
    };
    let request = request(vec![endpoint(35353, identify::Transport::Udp)]);
    let report = client(FakeTcp::default(), udp)
        .identify(&request)
        .expect("identify");
    assert_eq!(report.records[0].outcome, identify::Outcome::Malformed);
    assert!(!report.records[0].probes[0].response.is_empty());
    assert!(report.records[0].candidates.is_empty());
}

#[test]
fn dns_retries_use_distinct_operation_identities_despite_document_id_bases() {
    let udp = FakeUdp {
        failures: Arc::new(Mutex::new(VecDeque::from([io::ErrorKind::TimedOut; 2]))),
        ..FakeUdp::default()
    };
    let mut request = request(vec![endpoint(35353, identify::Transport::Udp)]);
    let mut corpus = (*request.corpus).clone();
    for probe in &mut corpus.probes {
        if let packetcraftr_core::document::service_probes::Request::Dns {
            payload: packetcraftr_core::document::udp_profiles::Payload::Dns { id_base, .. },
        } = &mut probe.request
        {
            *id_base = if probe.id.contains("version") {
                u16::MAX
            } else {
                0
            };
        }
    }
    request.corpus = Arc::new(corpus);
    request.intensity = 3;
    request.limits.probe.attempts = 3;
    let report = client(FakeTcp::default(), udp.clone())
        .identify(&request)
        .expect("DNS identify");
    assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
    let calls = udp.calls.lock().expect("calls");
    let ids: Vec<_> = calls
        .iter()
        .map(|call| u16::from_be_bytes(call.1[..2].try_into().unwrap()))
        .collect();
    assert_eq!(ids.len(), 4);
    assert_eq!(ids.iter().copied().collect::<BTreeSet<_>>().len(), 4);
    assert!(ids.windows(2).all(|ids| ids[1] == ids[0].wrapping_add(1)));
    assert_eq!(report.usage.attempts, 4);
}

#[test]
fn tcp_dns_keeps_exact_frames_and_rejects_malformed_lengths() {
    let mut request = request(vec![endpoint(35353, identify::Transport::Tcp)]);
    corpus_with(&mut request, "dns-tcp");
    let report = client(
        FakeTcp {
            dns_reply: Some(DnsReply::Echo),
            ..FakeTcp::default()
        },
        FakeUdp::default(),
    )
    .identify(&request)
    .expect("TCP DNS");
    assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
    let evidence = &report.records[0].probes[0];
    let response = dns_response(&evidence.request[2..]);
    let mut frame = (response.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(&response);
    assert_eq!(report.records[0].probes[0].response, frame);
    let wrong_id = client(
        FakeTcp {
            dns_reply: Some(DnsReply::WrongId),
            ..FakeTcp::default()
        },
        FakeUdp::default(),
    )
    .identify(&request)
    .unwrap();
    assert_eq!(wrong_id.records[0].outcome, identify::Outcome::Malformed);
    assert!(wrong_id.records[0].candidates.is_empty());
    for malformed in [vec![0], vec![0, 0], vec![0, 20, 1, 2, 3]] {
        let report = client(FakeTcp::replying([malformed.clone()]), FakeUdp::default())
            .identify(&request)
            .expect("malformed evidence");
        assert_eq!(report.records[0].outcome, identify::Outcome::Malformed);
        assert_eq!(report.records[0].probes[0].response, malformed);
        assert!(report.records[0].candidates.is_empty());
    }
}

#[test]
fn retries_are_explicit_and_cumulative_across_probe_and_host_scopes() {
    let tcp = FakeTcp {
        failures: Arc::new(Mutex::new(VecDeque::from([io::ErrorKind::TimedOut]))),
        ..FakeTcp::replying([b"SSH-2.0-OpenSSH_9.8\r\n".to_vec()])
    };
    let mut request = request(vec![endpoint(32222, identify::Transport::Tcp)]);
    request.intensity = 1;
    request.limits.probe.attempts = 2;
    let report = client(tcp.clone(), FakeUdp::default())
        .identify(&request)
        .expect("retry");
    assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
    assert_eq!(report.records[0].probes.len(), 2);
    assert_eq!(
        report.records[0].probes[0].io_outcome,
        identify::IoOutcome::TimedOut
    );
    assert_eq!(report.records[0].probes[1].attempt, 2);
    assert_eq!(report.usage.attempts, 2);
    assert_eq!(tcp.endpoints.lock().expect("endpoints").len(), 2);
}

#[test]
fn every_byte_scope_prevents_oversized_writes_and_bounds_response_retention() {
    for scope in 0..4 {
        let mut request = request(vec![endpoint(38080, identify::Transport::Tcp)]);
        corpus_with(&mut request, "http-head");
        let limits = match scope {
            0 => &mut request.limits.operation,
            1 => &mut request.limits.host,
            2 => &mut request.limits.connection,
            _ => &mut request.limits.probe,
        };
        limits.write_bytes = 1;
        let tcp = FakeTcp::default();
        let report = client(tcp.clone(), FakeUdp::default())
            .identify(&request)
            .expect("bounded request");
        assert_eq!(
            report.records[0].outcome,
            identify::Outcome::BudgetExhausted
        );
        assert!(tcp.endpoints.lock().expect("endpoints").is_empty());
        let limits = match scope {
            0 => &mut request.limits.operation,
            1 => &mut request.limits.host,
            2 => &mut request.limits.connection,
            _ => &mut request.limits.probe,
        };
        limits.write_bytes = 1024;
        limits.read_bytes = 8;
        let report = client(
            FakeTcp::replying([b"HTTP/1.0 200 OK\r\n\r\n".to_vec()]),
            FakeUdp::default(),
        )
        .identify(&request)
        .expect("bounded response");
        assert_eq!(report.records[0].probes[0].response.len(), 8);
        assert_eq!(report.usage.read_bytes, 8);
        assert_eq!(report.records[0].outcome, identify::Outcome::Truncated);
    }
}

#[test]
fn every_time_scope_bounds_the_final_connection_and_prevents_writes_after_expiry() {
    for scope in 0..4 {
        let clock = TestClock::new();
        let tcp = FakeTcp {
            advance: Some(clock.clone()),
            ..FakeTcp::default()
        };
        let mut request = request(vec![endpoint(38080, identify::Transport::Tcp)]);
        corpus_with(&mut request, "http-head");
        let limit = match scope {
            0 => &mut request.limits.operation,
            1 => &mut request.limits.host,
            2 => &mut request.limits.connection,
            _ => &mut request.limits.probe,
        };
        limit.timeout = Duration::from_millis(500);
        let report = client(tcp.clone(), FakeUdp::default())
            .with_clock(clock)
            .identify(&request)
            .expect("deadline evidence");
        assert_eq!(report.usage.attempts, 1);
        assert_eq!(report.usage.write_bytes, 0);
        assert!(tcp.writes.lock().expect("writes").is_empty());
        assert_eq!(
            report.records[0].probes[0].io_outcome,
            identify::IoOutcome::TimedOut
        );
    }
}

#[test]
fn cancellation_after_a_datagram_retains_bytes_and_prevents_all_later_probes() {
    let signal = Cancellation::default();
    let udp = FakeUdp {
        cancellation: Some(signal.clone()),
        ..FakeUdp::default()
    };
    let request = request(vec![
        endpoint(35353, identify::Transport::Udp),
        endpoint(35354, identify::Transport::Udp),
    ]);
    let report = client(FakeTcp::default(), udp.clone())
        .with_cancellation(signal)
        .identify(&request)
        .expect("partial report");
    assert!(report.cancelled);
    assert!(!report.complete);
    assert_eq!(report.usage.attempts, 1);
    assert_eq!(udp.calls.lock().expect("calls").len(), 1);
    assert_eq!(
        report.records[0].probes[0].io_outcome,
        identify::IoOutcome::Cancelled
    );
    assert!(!report.records[0].probes[0].response.is_empty());
    assert!(report.records[0].candidates.is_empty());
    assert_eq!(
        report.records[1].outcome,
        identify::Outcome::BudgetExhausted
    );
}

#[test]
fn final_host_or_operation_timeout_marks_the_report_incomplete() {
    for scope in [0, 1] {
        let clock = TestClock::new();
        let tcp = FakeTcp {
            advance: Some(clock.clone()),
            ..FakeTcp::default()
        };
        let mut request = request(vec![endpoint(38080, identify::Transport::Tcp)]);
        corpus_with(&mut request, "http-head");
        let limit = if scope == 0 {
            &mut request.limits.operation
        } else {
            &mut request.limits.host
        };
        limit.timeout = Duration::from_millis(500);
        let report = client(tcp, FakeUdp::default())
            .with_clock(clock)
            .identify(&request)
            .expect("timeout report");
        assert_eq!(
            report.records[0].outcome,
            identify::Outcome::BudgetExhausted
        );
        assert!(!report.complete);
        assert!(!report.cancelled);
    }
}

#[test]
fn aggregate_candidate_amplification_is_bounded_without_discarding_received_bytes() {
    let mut request = request(
        (32220..32230)
            .map(|port| endpoint(port, identify::Transport::Tcp))
            .collect(),
    );
    request.intensity = 1;
    corpus_with(&mut request, "ssh-banner");
    let mut corpus = (*request.corpus).clone();
    let rule = corpus.matches[0].clone();
    corpus.matches = (0..512)
        .map(|index| {
            let mut rule = rule.clone();
            rule.id = format!("candidate-{index}");
            rule
        })
        .collect();
    request.corpus = Arc::new(corpus);
    let banner = b"SSH-2.0-OpenSSH_9.8\r\n";
    let tcp = FakeTcp::replying((0..10).map(|_| banner.to_vec()));
    let report = client(tcp.clone(), FakeUdp::default())
        .identify(&request)
        .expect("bounded candidates");
    let entries: usize = report
        .records
        .iter()
        .map(|record| {
            record.candidates.len()
                + record
                    .probes
                    .iter()
                    .map(|probe| probe.identification.candidates.len())
                    .sum::<usize>()
        })
        .sum();
    assert_eq!(entries, identify::MAX_RESULT_CANDIDATES);
    assert_eq!(tcp.endpoints.lock().expect("endpoints").len(), 9);
    assert!(!report.complete);
    assert_eq!(
        report.records[8].outcome,
        identify::Outcome::BudgetExhausted
    );
    assert_eq!(report.records[8].probes[0].response, banner);
    assert_eq!(
        report.records[8].probes[0].identification.outcome,
        packetcraftr_core::document::service_probes::MatchOutcome::Truncated
    );
    assert_eq!(
        report.records[8].probes[0].observation.outcome,
        ObservationOutcome::Complete
    );
    assert_eq!(
        report.records[9].outcome,
        identify::Outcome::BudgetExhausted
    );
    assert!(report.records[9].probes.is_empty());
}

#[test]
fn exclusions_and_intensity_are_applied_before_any_probe_is_planned() {
    let tcp = FakeTcp::default();
    let udp = FakeUdp::default();
    let mut request = request(vec![
        endpoint(9100, identify::Transport::Tcp),
        endpoint(35353, identify::Transport::Udp),
    ]);
    request.intensity = 1;
    let report = client(tcp.clone(), udp.clone())
        .identify(&request)
        .expect("identify");
    assert_eq!(report.records[0].outcome, identify::Outcome::Excluded);
    assert!(report.records.iter().all(|record| record.probes.is_empty()));
    assert!(tcp.endpoints.lock().expect("endpoints").is_empty());
    assert!(udp.calls.lock().expect("UDP calls").is_empty());
}

#[test]
fn scan_endpoint_selection_requires_open_tcp_or_open_or_filtered_udp_and_retains_scope() {
    use packetcraftr::scan::{Inference, Rule, State};
    let mut scanned = packetcraftr::scan::Endpoint {
        address: "127.0.0.1".parse().expect("fixture IP"),
        scope: None,
        transport: packetcraftr::probe::Transport::Tcp,
        port: Some(32222),
        classification: packetcraftr::scan::Classification::Open,
        port_hint: None,
        inference: Some(Inference {
            state: Some(State::Open),
            rule: Rule::SynAck,
            supporting: vec![1],
            conflicting: vec![],
            unanswered: vec![],
            failed: vec![],
        }),
        probes: vec![],
    };
    assert_eq!(
        identify::Endpoint::from_scan(&scanned),
        Some(endpoint(32222, identify::Transport::Tcp))
    );
    scanned.inference.as_mut().expect("inference").state = Some(State::Closed);
    assert!(identify::Endpoint::from_scan(&scanned).is_none());
    scanned.transport = packetcraftr::probe::Transport::Udp;
    scanned.inference.as_mut().expect("inference").state = Some(State::OpenOrFiltered);
    assert_eq!(
        identify::Endpoint::from_scan(&scanned),
        Some(endpoint(32222, identify::Transport::Udp))
    );
    scanned.address = "fe80::1".parse().expect("scoped fixture IP");
    scanned.scope = Some(packetcraftr::target::ResolvedZone {
        zone: packetcraftr::target::Zone::new("7").expect("fixture zone"),
        interface: packetcraftr_netio::interface::Id {
            name: "fixture7".into(),
            index: 7,
        },
    });
    assert_eq!(
        identify::Endpoint::from_scan(&scanned)
            .expect("scoped selection")
            .address,
        SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().expect("fixture IPv6"),
            32222,
            0,
            7
        ))
    );
    scanned.port = None;
    assert!(identify::Endpoint::from_scan(&scanned).is_none());
}

#[test]
fn denied_numeric_destinations_and_insufficient_write_budgets_precede_io() {
    let tcp = FakeTcp::default();
    let mut request = request(vec![identify::Endpoint {
        address: "192.0.2.9:8080".parse().expect("endpoint"),
        transport: identify::Transport::Tcp,
    }]);
    corpus_with(&mut request, "http-head");
    let policy = Policy {
        allowed_destinations: vec!["127.0.0.1".parse().expect("allowlisted fixture")],
        ..Policy::default()
    };
    assert!(matches!(
        Client::new(
            builtin::registry(),
            policy,
            ProviderSet::tcp(tcp.clone(), ()).with_udp(FakeUdp::default())
        )
        .identify(&request),
        Err(identify::Error::Policy(_))
    ));
    request.endpoints[0] = endpoint(38080, identify::Transport::Tcp);
    request.limits.connection.write_bytes = 1;
    let report = client(tcp.clone(), FakeUdp::default())
        .identify(&request)
        .expect("bounded result");
    assert_eq!(
        report.records[0].outcome,
        identify::Outcome::BudgetExhausted
    );
    assert!(!report.complete);
    assert!(tcp.endpoints.lock().expect("endpoints").is_empty());
}

#[test]
fn invalid_unicast_destinations_and_their_mapped_forms_precede_provider_calls() {
    for address in [
        "255.255.255.255:35353",
        "[::ffff:255.255.255.255]:35353",
        "0.0.0.0:35353",
        "[::ffff:0.0.0.0]:35353",
        "224.0.0.1:35353",
        "[::ffff:224.0.0.1]:35353",
    ] {
        let tcp = FakeTcp::default();
        let udp = FakeUdp::default();
        let request = request(vec![identify::Endpoint {
            address: address.parse().expect("numeric endpoint"),
            transport: identify::Transport::Udp,
        }]);
        let policy = Policy {
            allow_public_destinations: true,
            ..Policy::default()
        };
        let client = Client::new(
            builtin::registry(),
            policy,
            ProviderSet::tcp(tcp.clone(), ()).with_udp(udp.clone()),
        );
        assert!(matches!(
            client.identify(&request),
            Err(identify::Error::Request { .. })
        ));
        assert!(tcp.endpoints.lock().expect("endpoints").is_empty());
        assert!(udp.calls.lock().expect("UDP calls").is_empty());
    }
}

#[test]
fn operation_and_host_attempt_limits_stop_extra_connections() {
    for host_limit in [false, true] {
        let tcp = FakeTcp::default();
        let mut request = request(vec![
            endpoint(38080, identify::Transport::Tcp),
            endpoint(38081, identify::Transport::Tcp),
        ]);
        corpus_with(&mut request, "http-head");
        if host_limit {
            request.limits.host.attempts = 1;
        } else {
            request.limits.operation.attempts = 1;
        }
        let report = client(tcp.clone(), FakeUdp::default())
            .identify(&request)
            .expect("identify");
        assert_eq!(report.usage.attempts, 1);
        assert_eq!(tcp.endpoints.lock().expect("endpoints").len(), 1);
        assert_eq!(
            report.records[1].outcome,
            identify::Outcome::BudgetExhausted
        );
    }
}

#[test]
fn host_budgets_canonicalize_aliases_and_preserve_relevant_ipv6_scope() {
    for (addresses, expected_attempts) in [
        (["127.0.0.1:35353", "[::ffff:127.0.0.1%7]:35354"], 1),
        (["[2001:db8::1%7]:35353", "[2001:db8::1%8]:35354"], 1),
        (["[fe80::1%7]:35353", "[fe80::1%8]:35353"], 2),
    ] {
        let udp = FakeUdp {
            empty_response: true,
            ..FakeUdp::default()
        };
        let endpoints: Vec<_> = addresses
            .into_iter()
            .map(|address| identify::Endpoint {
                address: address.parse().expect("numeric fixture"),
                transport: identify::Transport::Udp,
            })
            .collect();
        let mut request = request(endpoints.clone());
        corpus_with(&mut request, "dns-udp");
        request.limits.host.attempts = 1;
        let policy = Policy {
            allow_public_destinations: true,
            ..Policy::default()
        };
        let client = Client::new(
            builtin::registry(),
            policy,
            ProviderSet::tcp(FakeTcp::default(), ()).with_udp(udp.clone()),
        );
        let report = client.identify(&request).expect("shared host budget");
        let calls = udp.calls.lock().expect("UDP calls");
        assert_eq!(calls.len(), expected_attempts);
        assert_eq!(calls[0].0, endpoints[0].address);
        assert!(report.records[0].probes[0].response.is_empty());
        assert_eq!(report.records[1].endpoint, endpoints[1]);
        assert_eq!(report.records[1].probes.len(), expected_attempts - 1);
        assert_eq!(report.usage.attempts, expected_attempts as u64);
        assert_eq!(report.complete, expected_attempts == 2);
        if expected_attempts == 1 {
            assert_eq!(
                report.records[1].outcome,
                identify::Outcome::BudgetExhausted
            );
        }
    }
}

#[test]
fn host_and_operation_read_limits_bound_retained_bytes() {
    for host_limit in [false, true] {
        let tcp = FakeTcp::replying([b"SSH-2.0-OpenSSH_9.8\r\n".to_vec()]);
        let mut request = request(vec![
            endpoint(32222, identify::Transport::Tcp),
            endpoint(32223, identify::Transport::Tcp),
        ]);
        request.intensity = 1;
        if host_limit {
            request.limits.host.read_bytes = 5;
        } else {
            request.limits.operation.read_bytes = 5;
        }
        let report = client(tcp.clone(), FakeUdp::default())
            .identify(&request)
            .expect("identify");
        assert_eq!(report.usage.read_bytes, 5);
        assert_eq!(
            report.records[0].probes[0].io_outcome,
            identify::IoOutcome::Truncated
        );
        assert_eq!(
            report.records[1].outcome,
            identify::Outcome::BudgetExhausted
        );
        assert_eq!(tcp.endpoints.lock().expect("endpoints").len(), 1);
    }
}

#[test]
fn ssh_identification_completes_even_when_binary_data_arrives_in_the_same_read() {
    let response = b"notice\r\nSSH-2.0-OpenSSH_9.8p1\r\n\x00\x00\x00\x0c\x06\x14binary";
    let tcp = FakeTcp::replying([response.to_vec()]);
    let mut request = request(vec![endpoint(32222, identify::Transport::Tcp)]);
    corpus_with(&mut request, "ssh-banner");
    let report = client(tcp, FakeUdp::default()).identify(&request).unwrap();
    assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
    let evidence = &report.records[0].probes[0];
    assert_eq!(evidence.io_outcome, identify::IoOutcome::Complete);
    assert_eq!(evidence.response, response);
    assert_eq!(
        report.records[0].candidates[0].version.as_deref(),
        Some("9.8p1")
    );
}

#[test]
fn malformed_ssh_line_completes_without_waiting_for_the_peer_to_close() {
    let response = b"SSH-2.0-OpenSSH_9.8p1\n";
    let tcp = FakeTcp {
        timeout_after_response: true,
        ..FakeTcp::replying([response.to_vec()])
    };
    let mut request = request(vec![endpoint(32222, identify::Transport::Tcp)]);
    corpus_with(&mut request, "ssh-banner");
    let report = client(tcp, FakeUdp::default()).identify(&request).unwrap();
    let evidence = &report.records[0].probes[0];
    assert_eq!(evidence.io_outcome, identify::IoOutcome::Complete);
    assert_eq!(evidence.observation.outcome, ObservationOutcome::Malformed);
    assert_eq!(evidence.response, response);
    assert!(evidence.identification.candidates.is_empty());
    assert_eq!(report.records[0].outcome, identify::Outcome::Malformed);
}

#[test]
fn ssh_preamble_limits_finish_collection_and_preserve_later_probe_work() {
    for (response, diagnostic) in [
        (
            "notice\r\n".repeat(17).into_bytes(),
            "SSH preamble exceeds 16 lines",
        ),
        (vec![b'a'; 1025], "SSH preamble line exceeds its limit"),
    ] {
        let tcp = FakeTcp {
            timeout_after_response: true,
            ..FakeTcp::replying([
                response.clone(),
                b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\n\r\n".to_vec(),
            ])
        };
        let mut request = request(vec![endpoint(38080, identify::Transport::Tcp)]);
        let corpus = Arc::make_mut(&mut request.corpus);
        corpus
            .probes
            .retain(|probe| matches!(probe.id.as_str(), "ssh-banner" | "http-head"));
        corpus
            .matches
            .retain(|rule| matches!(rule.probe.as_str(), "ssh-banner" | "http-head"));
        let report = client(tcp, FakeUdp::default()).identify(&request).unwrap();
        assert!(report.complete);
        assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
        assert_eq!(report.records[0].probes.len(), 2);
        let evidence = &report.records[0].probes[0];
        assert_eq!(evidence.io_outcome, identify::IoOutcome::Complete);
        assert_eq!(evidence.response, response);
        assert_eq!(evidence.observation.outcome, ObservationOutcome::Truncated);
        assert_eq!(evidence.observation.diagnostic.as_deref(), Some(diagnostic));
        assert!(evidence.identification.candidates.is_empty());
        assert_eq!(
            report.records[0].probes[1].io_outcome,
            identify::IoOutcome::Complete
        );
        assert_eq!(
            report.records[0].candidates[0].version.as_deref(),
            Some("1.26.2")
        );
    }
}

#[test]
fn fragmented_ssh_after_sixteen_preamble_lines_remains_collectable() {
    let response = format!("{}SSH-2.0-OpenSSH_9.8p1\r\n", "notice\r\n".repeat(16));
    let tcp = FakeTcp {
        timeout_after_response: true,
        read_chunk: Some(1),
        ..FakeTcp::replying([response.as_bytes().to_vec()])
    };
    let mut request = request(vec![endpoint(32222, identify::Transport::Tcp)]);
    corpus_with(&mut request, "ssh-banner");
    let report = client(tcp, FakeUdp::default()).identify(&request).unwrap();
    assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
    assert_eq!(
        report.records[0].probes[0].io_outcome,
        identify::IoOutcome::Complete
    );
    assert_eq!(report.records[0].probes[0].response, response.as_bytes());
    assert_eq!(
        report.records[0].candidates[0].version.as_deref(),
        Some("9.8p1")
    );
}

#[test]
fn definitive_http_errors_complete_without_waiting_for_the_peer_to_close() {
    for (response, expected) in [
        (
            b"HTTP/1.1 200 OK\n\n".to_vec(),
            ObservationOutcome::Malformed,
        ),
        (
            b"HTTP/1.1 200 OK\rX".to_vec(),
            ObservationOutcome::Malformed,
        ),
        (
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\n".to_vec(),
            ObservationOutcome::Malformed,
        ),
        (
            [b"HTTP/1.1 200 ".as_slice(), &vec![b'a'; 8192]].concat(),
            ObservationOutcome::Truncated,
        ),
    ] {
        let tcp = FakeTcp {
            timeout_after_response: true,
            ..FakeTcp::replying([response.clone()])
        };
        let mut request = request(vec![endpoint(38080, identify::Transport::Tcp)]);
        corpus_with(&mut request, "http-head");
        let report = client(tcp, FakeUdp::default()).identify(&request).unwrap();
        let evidence = &report.records[0].probes[0];
        assert_eq!(evidence.io_outcome, identify::IoOutcome::Complete);
        assert_eq!(evidence.observation.outcome, expected);
        assert_eq!(evidence.response, response);
        assert!(evidence.identification.candidates.is_empty());
        assert_eq!(
            report.records[0].outcome,
            if expected == ObservationOutcome::Malformed {
                identify::Outcome::Malformed
            } else {
                identify::Outcome::Truncated
            }
        );
    }
}

#[test]
fn fragmented_valid_http_line_endings_keep_collecting_until_the_head_is_complete() {
    let response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\n\r\n";
    let tcp = FakeTcp {
        timeout_after_response: true,
        read_chunk: Some(1),
        ..FakeTcp::replying([response.to_vec()])
    };
    let mut request = request(vec![endpoint(38080, identify::Transport::Tcp)]);
    corpus_with(&mut request, "http-head");
    let report = client(tcp, FakeUdp::default()).identify(&request).unwrap();
    assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
    assert_eq!(report.records[0].probes[0].response, response);
    assert_eq!(
        report.records[0].probes[0].io_outcome,
        identify::IoOutcome::Complete
    );
    assert_eq!(
        report.records[0].candidates[0].version.as_deref(),
        Some("1.26.2")
    );
}

#[test]
fn mapped_exact_allowlist_survives_final_native_peer_authorization() {
    for (requested, allowed) in [
        ("[::ffff:127.0.0.1]:38080", "::ffff:127.0.0.1"),
        ("127.0.0.1:38080", "::ffff:127.0.0.1"),
        ("[::ffff:127.0.0.1]:38080", "127.0.0.1"),
    ] {
        let tcp = FakeTcp {
            peer: Some("127.0.0.1:38080".parse().unwrap()),
            ..FakeTcp::replying([b"HTTP/1.0 200 OK\r\nServer: nginx/1.27.2\r\n\r\n".to_vec()])
        };
        let policy = Policy {
            allowed_destinations: vec![allowed.parse().unwrap()],
            ..Policy::default()
        };
        let mut request = request(vec![identify::Endpoint {
            address: requested.parse().unwrap(),
            transport: identify::Transport::Tcp,
        }]);
        corpus_with(&mut request, "http-head");
        let report = Client::new(
            builtin::registry(),
            policy,
            ProviderSet::tcp(tcp.clone(), ()).with_udp(FakeUdp::default()),
        )
        .identify(&request)
        .unwrap();
        assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
        assert_eq!(*tcp.writes.lock().unwrap(), [b"HEAD / HTTP/1.0\r\n\r\n"]);
    }
}

#[test]
fn changed_peer_is_rejected_before_any_request_bytes_are_written() {
    let tcp = FakeTcp {
        peer: Some("127.0.0.2:38080".parse().expect("other peer")),
        ..FakeTcp::default()
    };
    let mut request = request(vec![endpoint(38080, identify::Transport::Tcp)]);
    corpus_with(&mut request, "http-head");
    assert!(matches!(
        client(tcp.clone(), FakeUdp::default()).identify(&request),
        Err(identify::Error::Provider { .. })
    ));
    assert!(tcp.writes.lock().expect("writes").is_empty());
}

#[test]
fn peer_checks_normalize_mapped_ipv4_and_preserve_relevant_ipv6_scopes() {
    for transport in [identify::Transport::Tcp, identify::Transport::Udp] {
        for (expected, actual, accepted) in [
            ("[::ffff:127.0.0.1%7]:38080", "127.0.0.1:38080", true),
            ("127.0.0.1:38080", "[::ffff:127.0.0.1%7]:38080", true),
            ("[::ffff:127.0.0.1%7]:38080", "127.0.0.2:38080", false),
            ("[::ffff:127.0.0.1%7]:38080", "127.0.0.1:38081", false),
            ("[::1]:38080", "127.0.0.1:38080", false),
            ("[::1%7]:38080", "[::1]:38080", true),
            ("[2001:db8::1%7]:38080", "[2001:db8::1]:38080", true),
            ("[fe80::1%7]:38080", "[fe80::1%7]:38080", true),
            ("[fe80::1%7]:38080", "[fe80::1%8]:38080", false),
            ("[fe80::1%7]:38080", "[fe80::1]:38080", false),
            ("[::1%7]:38080", "[::2]:38080", false),
            ("[::1%7]:38080", "[::1]:38081", false),
        ] {
            let peer = Some(actual.parse().unwrap());
            let tcp = FakeTcp {
                peer,
                ..FakeTcp::replying([b"HTTP/1.0 200 OK\r\nServer: nginx/1.27.2\r\n\r\n".to_vec()])
            };
            let udp = FakeUdp {
                peer,
                ..FakeUdp::default()
            };
            let mut request = request(vec![identify::Endpoint {
                address: expected.parse().unwrap(),
                transport,
            }]);
            corpus_with(
                &mut request,
                if transport == identify::Transport::Tcp {
                    "http-head"
                } else {
                    "dns-udp"
                },
            );
            let client = Client::new(
                builtin::registry(),
                Policy {
                    allow_public_destinations: true,
                    ..Policy::default()
                },
                ProviderSet::tcp(tcp.clone(), ()).with_udp(udp),
            );
            let result = client.identify(&request);
            if accepted {
                assert_eq!(
                    result.unwrap().records[0].outcome,
                    identify::Outcome::Matched
                );
            } else {
                assert!(matches!(result, Err(identify::Error::Provider { .. })));
                assert!(tcp.writes.lock().unwrap().is_empty());
            }
        }
    }
}

#[test]
fn policy_traffic_limits_follow_the_selected_transport_and_probe_plan() {
    for (probe, transport, units) in [
        ("ssh-banner", identify::Transport::Tcp, 1),
        ("http-head", identify::Transport::Tcp, 2),
        ("dns-tcp", identify::Transport::Tcp, 2),
        ("dns-udp", identify::Transport::Udp, 1),
    ] {
        for allowed in [units - 1, units] {
            let tcp = FakeTcp::default();
            let udp = FakeUdp::default();
            let mut request = request(vec![endpoint(38080, transport)]);
            corpus_with(&mut request, probe);
            let bytes = request.corpus.probes[0].request_bytes(1).unwrap().len() as u64
                + u64::from(probe == "dns-tcp") * 2;
            let client = Client::new(
                builtin::registry(),
                Policy {
                    max_packets_per_operation: allowed,
                    max_bytes_per_operation: bytes,
                    ..Policy::default()
                },
                ProviderSet::tcp(tcp.clone(), ()).with_udp(udp.clone()),
            );
            let result = client.identify(&request);
            if allowed == units {
                assert_eq!(result.unwrap().usage.attempts, 1, "{probe}");
            } else {
                assert!(matches!(result, Err(identify::Error::Policy(_))), "{probe}");
                assert!(tcp.endpoints.lock().unwrap().is_empty());
                assert!(udp.calls.lock().unwrap().is_empty());
            }
        }
    }
}

#[test]
fn mixed_transport_declarations_respect_shared_attempt_allowances() {
    for host_bound in [false, true] {
        for udp_first in [false, true] {
            let tcp = FakeTcp::default();
            let udp = FakeUdp::default();
            let mut endpoints = vec![
                endpoint(32222, identify::Transport::Tcp),
                endpoint(32222, identify::Transport::Udp),
            ];
            if udp_first {
                endpoints.reverse();
            }
            let mut request = request(endpoints);
            let mut corpus = (*request.corpus).clone();
            corpus
                .probes
                .retain(|probe| matches!(probe.id.as_str(), "ssh-banner" | "dns-udp"));
            corpus
                .matches
                .retain(|rule| matches!(rule.probe.as_str(), "ssh-banner" | "dns-udp"));
            request.corpus = Arc::new(corpus);
            if host_bound {
                request.limits.host.attempts = 1;
            } else {
                request.limits.operation.attempts = 1;
            }
            let client = Client::new(
                builtin::registry(),
                Policy {
                    max_packets_per_operation: 1,
                    ..Policy::default()
                },
                ProviderSet::tcp(tcp.clone(), ()).with_udp(udp.clone()),
            );
            let report = client.identify(&request).expect("one shared traffic unit");
            assert_eq!(report.usage.attempts, 1);
            assert_eq!(tcp.endpoints.lock().unwrap().len(), usize::from(!udp_first));
            assert_eq!(udp.calls.lock().unwrap().len(), usize::from(udp_first));
            assert!(!report.complete);
        }
    }
}

#[test]
fn zero_traffic_plans_do_not_authorize_unselected_or_unwritable_endpoints() {
    for (probe, port, transport, unwritable) in [
        ("ssh-banner", 38080, identify::Transport::Udp, false),
        ("http-head", 38080, identify::Transport::Tcp, true),
        ("http-head", 9100, identify::Transport::Tcp, false),
    ] {
        let tcp = FakeTcp::default();
        let udp = FakeUdp::default();
        let mut request = request(vec![identify::Endpoint {
            address: SocketAddr::from(([192, 0, 2, 1], port)),
            transport,
        }]);
        corpus_with(&mut request, probe);
        if unwritable {
            request.limits.connection.write_bytes = 0;
        }
        let client = Client::new(
            builtin::registry(),
            Policy {
                max_packets_per_operation: 0,
                max_bytes_per_operation: 0,
                ..Policy::default()
            },
            ProviderSet::tcp(tcp.clone(), ()).with_udp(udp.clone()),
        );
        let report = client.identify(&request).expect("no traffic to authorize");
        assert_eq!(report.usage.attempts, 0);
        assert!(tcp.endpoints.lock().unwrap().is_empty());
        assert!(udp.calls.lock().unwrap().is_empty());
    }
}

#[test]
fn unwritable_active_probes_do_not_block_later_speak_first_collection() {
    for scope in 0..4 {
        for allowance in [0, 1] {
            let banner = b"SSH-2.0-OpenSSH_9.8p1\r\n";
            let tcp = FakeTcp::replying([banner.to_vec()]);
            let mut request = request(vec![endpoint(32222, identify::Transport::Tcp)]);
            let mut corpus = (*request.corpus).clone();
            corpus
                .probes
                .retain(|probe| probe.transport == identify::Transport::Tcp);
            corpus.probes.sort_by_key(|probe| probe.id == "ssh-banner");
            corpus
                .matches
                .retain(|rule| corpus.probes.iter().any(|probe| probe.id == rule.probe));
            request.corpus = Arc::new(corpus);
            let limit = match scope {
                0 => &mut request.limits.operation,
                1 => &mut request.limits.host,
                2 => &mut request.limits.connection,
                _ => &mut request.limits.probe,
            };
            limit.write_bytes = allowance;
            let client = Client::new(
                builtin::registry(),
                Policy {
                    max_packets_per_operation: 1,
                    max_bytes_per_operation: 0,
                    ..Policy::default()
                },
                ProviderSet::tcp(tcp.clone(), ()).with_udp(FakeUdp::default()),
            );
            let report = client.identify(&request).expect("banner remains admitted");
            assert!(report.complete, "scope {scope}, allowance {allowance}");
            assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
            assert_eq!(report.records[0].probes.len(), 1);
            assert_eq!(report.records[0].probes[0].probe, "ssh-banner");
            assert_eq!(report.records[0].probes[0].response, banner);
            assert_eq!(report.usage.attempts, 1);
            assert_eq!(report.usage.write_bytes, 0);
            assert_eq!(tcp.endpoints.lock().unwrap().len(), 1);
            assert!(tcp.writes.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn exhausted_write_usage_still_stops_before_later_probes() {
    let tcp = FakeTcp::replying([b"HTTP/1.0 200 OK\r\nServer: nginx/1.26.2\r\n\r\n".to_vec()]);
    let mut request = request(vec![endpoint(38080, identify::Transport::Tcp)]);
    let mut corpus = (*request.corpus).clone();
    let http = corpus
        .probes
        .iter()
        .find(|probe| probe.id == "http-head")
        .unwrap()
        .clone();
    let mut second = http.clone();
    second.id = "second-http".into();
    let ssh = corpus
        .probes
        .iter()
        .find(|probe| probe.id == "ssh-banner")
        .unwrap()
        .clone();
    corpus.probes = vec![http, second, ssh];
    corpus
        .matches
        .retain(|rule| matches!(rule.probe.as_str(), "http-head" | "ssh-banner"));
    request.corpus = Arc::new(corpus);
    request.limits.operation.write_bytes = 19;
    let report = client(tcp.clone(), FakeUdp::default())
        .identify(&request)
        .unwrap();
    assert!(!report.complete);
    assert_eq!(
        report.records[0].outcome,
        identify::Outcome::BudgetExhausted
    );
    assert_eq!(report.records[0].probes.len(), 1);
    assert_eq!(report.records[0].probes[0].probe, "http-head");
    assert!(!report.records[0].candidates.is_empty());
    assert_eq!(tcp.endpoints.lock().unwrap().len(), 1);
    assert_eq!(report.usage.write_bytes, 19);
}

#[test]
fn duplicate_peer_aliases_are_rejected_before_provider_calls() {
    for (addresses, duplicate) in [
        (["[::1%7]:32222", "[::1%8]:32222"], true),
        (["[2001:db8::1%7]:32222", "[2001:db8::1%8]:32222"], true),
        (["[fe80::1%7]:32222", "[fe80::1%7]:32222"], true),
        (["127.0.0.1:32222", "[::ffff:127.0.0.1%7]:32222"], true),
        (["[fe80::1%7]:32222", "[fe80::1%8]:32222"], false),
        (["[::1%7]:32222", "[::1%8]:32223"], false),
    ] {
        let tcp = FakeTcp::default();
        let udp = FakeUdp::default();
        let mut endpoints: Vec<_> = addresses
            .into_iter()
            .map(|address| identify::Endpoint {
                address: address.parse().unwrap(),
                transport: identify::Transport::Tcp,
            })
            .collect();
        if let SocketAddr::V6(address) = &mut endpoints[1].address {
            address.set_flowinfo(123);
        }
        let mut request = request(endpoints);
        request.intensity = 1;
        let client = Client::new(
            builtin::registry(),
            Policy {
                allow_public_destinations: true,
                ..Policy::default()
            },
            ProviderSet::tcp(tcp.clone(), ()).with_udp(udp.clone()),
        );
        let result = client.identify(&request);
        if duplicate {
            assert!(
                matches!(result, Err(identify::Error::Request { .. })),
                "{addresses:?}"
            );
            assert!(tcp.endpoints.lock().unwrap().is_empty());
            assert!(udp.calls.lock().unwrap().is_empty());
        } else {
            assert_eq!(result.unwrap().usage.attempts, 2);
        }
    }
    let mut request = request(vec![
        endpoint(32222, identify::Transport::Tcp),
        endpoint(32222, identify::Transport::Udp),
    ]);
    request.intensity = 2;
    request
        .validate(&Policy::default())
        .expect("transport is part of peer identity");
}

#[test]
fn cancellation_while_tcp_connect_is_pending_retains_cancelled_evidence() {
    let signal = Cancellation::default();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let tcp = FakeTcp {
        pending_cancellation: Some(PendingCancellation {
            signal: signal.clone(),
            release: Arc::clone(&release),
        }),
        ..FakeTcp::default()
    };
    let mut request = request(vec![endpoint(32222, identify::Transport::Tcp)]);
    request.intensity = 1;
    request.limits.connection.timeout = Duration::from_secs(10);
    request.limits.probe.timeout = Duration::from_secs(10);
    let result = client(tcp.clone(), FakeUdp::default())
        .with_cancellation(signal)
        .identify(&request);
    *release.0.lock().unwrap() = true;
    release.1.notify_all();
    let report = result.expect("cancelled evidence");
    assert!(report.cancelled);
    assert!(!report.complete);
    let evidence = &report.records[0].probes[0];
    assert_eq!(evidence.io_outcome, identify::IoOutcome::Cancelled);
    assert!(matches!(
        evidence
            .source
            .as_ref()
            .unwrap()
            .downcast_ref::<tcp::Error>(),
        Some(tcp::Error::Cancelled(_))
    ));
    assert!(tcp.writes.lock().unwrap().is_empty());
}

#[test]
fn cancelled_and_expired_invocations_make_no_provider_calls() {
    let tcp = FakeTcp::default();
    let signal = Cancellation::default();
    signal.cancel();
    let mut request = request(vec![endpoint(32222, identify::Transport::Tcp)]);
    let client = client(tcp.clone(), FakeUdp::default()).with_cancellation(signal);
    assert!(matches!(
        client.identify(&request),
        Err(identify::Error::Cancelled(_))
    ));
    request.parent_deadline = Some(Arc::new(Deadline::new(Duration::ZERO)));
    let report = self::client(tcp.clone(), FakeUdp::default())
        .identify(&request)
        .expect("bounded result");
    assert_eq!(
        report.records[0].outcome,
        identify::Outcome::BudgetExhausted
    );
    assert!(tcp.endpoints.lock().expect("endpoints").is_empty());
}

#[test]
fn real_loopback_tcp_http_and_udp_dns_use_the_public_operation() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let endpoint = identify::Endpoint {
        address: listener.local_addr().expect("local"),
        transport: identify::Transport::Tcp,
    };
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let mut request = [0u8; 19];
        stream.read_exact(&mut request).expect("read HEAD");
        assert_eq!(&request, b"HEAD / HTTP/1.0\r\n\r\n");
        stream
            .write_all(b"HTTP/1.0 200 OK\r\nServer: nginx/1.27.2\r\n\r\n")
            .expect("HTTP reply");
    });
    let mut request = request(vec![endpoint]);
    corpus_with(&mut request, "http-head");
    let client = Client::new(builtin::registry(), Policy::default(), SystemProviders);
    assert_eq!(
        client.identify(&request).expect("HTTP identify").records[0].outcome,
        identify::Outcome::Matched
    );
    server.join().expect("HTTP server");

    let socket = UdpSocket::bind("127.0.0.1:0").expect("UDP listener");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let endpoint = identify::Endpoint {
        address: socket.local_addr().expect("UDP local"),
        transport: identify::Transport::Udp,
    };
    let server = std::thread::spawn(move || {
        let mut bytes = [0u8; 512];
        let (count, peer) = socket.recv_from(&mut bytes).expect("receive DNS");
        socket
            .send_to(&dns_response(&bytes[..count]), peer)
            .expect("reply DNS");
    });
    let report = client
        .identify(&self::request(vec![endpoint]))
        .expect("DNS identify");
    assert_eq!(report.records[0].outcome, identify::Outcome::Matched);
    assert_eq!(
        report.records[0].probes[0].observation.outcome,
        ObservationOutcome::Complete
    );
    server.join().expect("DNS server");
}
