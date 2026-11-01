// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::{
    ProviderSet,
    policy::{Error as PolicyError, Policy},
};
use packetcraftr_core::registry::Registry;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::collections::VecDeque;
use std::convert::Infallible;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

const ENDPOINT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
const CA: &[u8] = include_bytes!("test-ca.pem");
const UNTRUSTED_CA: &[u8] = include_bytes!("test-untrusted-ca.pem");
const MAX_STEPS: usize = 256;
const MAX_WIRE_BYTES_SENT: usize = 4096;
const TLS_UNITS: u64 = 1 + MAX_STEPS as u64;
const TLS_BYTES: u64 = MAX_WIRE_BYTES_SENT as u64;
const WRITE_CHUNK: usize = 7;
const REQUEST: &[u8] = b"HEAD / HTTP/1.1\r\nHost: 127.0.0.1:443\r\nConnection: close\r\nUser-Agent: PacketcraftR-audit\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

#[derive(Default)]
struct Observed {
    connects: usize,
    /// Accepted length of every native write call, zero for a refused retry.
    writes: Vec<usize>,
    /// Application bytes the server received: decrypted for TLS, raw otherwise.
    received: Vec<u8>,
}

impl Observed {
    fn bytes(&self) -> usize {
        self.writes.iter().sum()
    }

    fn units(&self) -> usize {
        self.connects + self.writes.len()
    }

    fn assert_within(&self, policy: &Policy) {
        assert!(
            self.units() as u64 <= policy.max_packets_per_operation,
            "{} connects and {} writes exceed {} units",
            self.connects,
            self.writes.len(),
            policy.max_packets_per_operation
        );
        assert!(self.bytes() as u64 <= policy.max_bytes_per_operation);
    }

    fn assert_untouched(&self) {
        assert_eq!(
            (self.connects, self.writes.len(), self.bytes()),
            (0, 0, 0),
            "rejected operation reached the provider"
        );
    }
}

#[derive(Clone, Copy)]
enum Server {
    Tls,
    Plain,
}

enum Session {
    Tls(Box<rustls::ServerConnection>),
    Plain,
}

struct FakeStream {
    session: Session,
    peer: SocketAddr,
    response: &'static [u8],
    read_failure: bool,
    jump: Option<Arc<AtomicBool>>,
    outbound: VecDeque<u8>,
    write_retried: bool,
    read_retried: bool,
    responded: bool,
    observed: Arc<Mutex<Observed>>,
}

impl FakeStream {
    fn respond_once_request_is_complete(&mut self, received: &[u8]) -> io::Result<()> {
        if self.responded || !received.ends_with(b"\r\n\r\n") {
            return Ok(());
        }
        self.responded = true;
        match &mut self.session {
            Session::Tls(server) => server.writer().write_all(self.response),
            Session::Plain => {
                self.outbound.extend(self.response);
                Ok(())
            }
        }
    }
}

impl Read for FakeStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if !self.read_retried {
            self.read_retried = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if let Some(jump) = &self.jump {
            jump.store(true, Ordering::SeqCst);
        }
        if self.read_failure {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        if let Session::Tls(server) = &mut self.session {
            while server.wants_write() {
                server.write_tls(&mut self.outbound)?;
            }
        }
        if self.outbound.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.outbound.read(bytes)
    }
}

impl Write for FakeStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let observed = Arc::clone(&self.observed);
        let mut observed = observed.lock().unwrap();
        if !self.write_retried {
            self.write_retried = true;
            observed.writes.push(0);
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let accepted = &bytes[..bytes.len().min(WRITE_CHUNK)];
        observed.writes.push(accepted.len());
        match &mut self.session {
            Session::Tls(server) => {
                server.read_tls(&mut &accepted[..])?;
                server.process_new_packets().map_err(io::Error::other)?;
                let mut plaintext = [0; 512];
                while let Ok(count @ 1..) = server.reader().read(&mut plaintext) {
                    observed.received.extend_from_slice(&plaintext[..count]);
                }
            }
            Session::Plain => observed.received.extend_from_slice(accepted),
        }
        self.respond_once_request_is_complete(&observed.received)?;
        Ok(accepted.len())
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
        Ok(SocketAddr::from(([127, 0, 0, 1], 40_000)))
    }

    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

struct FakeTcp {
    server: Server,
    peer: Option<SocketAddr>,
    response: &'static [u8],
    read_failure: bool,
    jump: Option<Arc<AtomicBool>>,
    observed: Arc<Mutex<Observed>>,
}

fn tls_server() -> rustls::ServerConnection {
    let chain = CertificateDer::pem_slice_iter(include_bytes!("test-leaf.pem"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("test-leaf-key.pem")).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    rustls::ServerConnection::new(Arc::new(config)).unwrap()
}

impl tcp::Provider for FakeTcp {
    type Stream = FakeStream;

    fn connect(
        &self,
        endpoint: SocketAddr,
        _deadline: &Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        self.observed.lock().unwrap().connects += 1;
        Ok(FakeStream {
            session: match self.server {
                Server::Tls => Session::Tls(Box::new(tls_server())),
                Server::Plain => Session::Plain,
            },
            peer: self.peer.unwrap_or(endpoint),
            response: self.response,
            read_failure: self.read_failure,
            jump: self.jump.clone(),
            outbound: VecDeque::new(),
            write_retried: false,
            read_retried: false,
            responded: false,
            observed: Arc::clone(&self.observed),
        })
    }
}

type FakeClient = Client<ProviderSet<(), (), (), (), FakeTcp, ()>>;

fn fake_tcp(
    server: Server,
    peer: Option<SocketAddr>,
    response: &'static [u8],
    read_failure: bool,
    jump: Option<Arc<AtomicBool>>,
) -> FakeTcp {
    FakeTcp {
        server,
        peer,
        response,
        read_failure,
        jump,
        observed: Arc::new(Mutex::new(Observed::default())),
    }
}

fn client_with(policy: &Policy, tcp: FakeTcp) -> (FakeClient, Arc<Mutex<Observed>>) {
    let observed = Arc::clone(&tcp.observed);
    let client = Client::new(
        Arc::new(Registry::default()),
        policy.clone(),
        ProviderSet::tcp(tcp, ()),
    );
    (client, observed)
}

fn fake_client(
    policy: &Policy,
    server: Server,
    peer: Option<SocketAddr>,
) -> (FakeClient, Arc<Mutex<Observed>>) {
    client_with(policy, fake_tcp(server, peer, RESPONSE, false, None))
}

/// A real-time clock that reports one far-future instant after the stream
/// raises `jump`, simulating the deadline expiring inside the exchange while
/// the caller's own deadline checks still see a live clock.
#[derive(Clone)]
struct JumpClock {
    jump: Arc<AtomicBool>,
}

impl Clock for JumpClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        let now = Instant::now();
        if self.jump.swap(false, Ordering::SeqCst) {
            now + Duration::from_secs(7200)
        } else {
            now
        }
    }

    fn sleep(&self, _delay: Duration, _deadline: &Deadline) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn budget(units: u64, bytes: u64) -> Policy {
    Policy {
        max_packets_per_operation: units,
        max_bytes_per_operation: bytes,
        ..Policy::default()
    }
}

fn tls_request(trust: &[u8]) -> TlsRequest {
    TlsRequest {
        trust: tls::TrustStore::from_pem(trust).unwrap(),
        limits: tls::Limits {
            max_steps: MAX_STEPS,
            max_wire_bytes_sent: MAX_WIRE_BYTES_SENT,
            ..tls::Limits::default()
        },
        ..TlsRequest::new(ENDPOINT)
    }
}

fn https_request(trust: &[u8]) -> HttpRequest {
    HttpRequest {
        connection: tls_request(trust),
        tls: true,
        ..HttpRequest::new(ENDPOINT)
    }
}

fn plain_units_and_bytes() -> (u64, u64) {
    (2, REQUEST.len() as u64)
}

fn assert_traffic_unit_limit<T: std::fmt::Debug>(result: Result<T, Error>) {
    assert!(
        matches!(
            result,
            Err(Error::Policy(PolicyError::TrafficUnitLimit { .. }))
        ),
        "{result:?}"
    );
}

fn assert_traffic_byte_limit<T: std::fmt::Debug>(result: Result<T, Error>) {
    assert!(
        matches!(
            result,
            Err(Error::Policy(PolicyError::TrafficByteLimit { .. }))
        ),
        "{result:?}"
    );
}

#[test]
fn tls_audit_completes_within_the_reserved_connection_steps_and_bytes() {
    for policy in [
        budget(TLS_UNITS, TLS_BYTES),
        budget(TLS_UNITS + 1, TLS_BYTES + 1),
    ] {
        let (client, observed) = fake_client(&policy, Server::Tls, None);
        let report = client.audit_tls(&tls_request(CA)).unwrap();
        assert!(report.completeness.complete, "{:?}", report.completeness);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        let observed = observed.lock().unwrap();
        assert_eq!(observed.connects, 1);
        assert!(observed.writes.len() > 1 && observed.writes.contains(&0));
        assert!(observed.writes.len() <= MAX_STEPS);
        assert!(observed.bytes() <= MAX_WIRE_BYTES_SENT);
        observed.assert_within(&policy);
    }
}

#[test]
fn tls_audit_never_writes_past_its_reservation_when_the_handshake_needs_more() {
    for (max_steps, max_wire_bytes_sent) in [(8, MAX_WIRE_BYTES_SENT), (MAX_STEPS, 64)] {
        let limits = tls::Limits {
            max_steps,
            max_wire_bytes_sent,
            ..tls::Limits::default()
        };
        let request = TlsRequest {
            limits,
            ..tls_request(CA)
        };
        let policy = budget(1 + max_steps as u64, max_wire_bytes_sent as u64);
        let (client, observed) = fake_client(&policy, Server::Tls, None);
        let result = client.audit_tls(&request);
        assert!(
            matches!(
                result,
                Err(Error::Tls(
                    tls::Error::StepLimit { .. } | tls::Error::WireLimit { .. }
                ))
            ),
            "{result:?}"
        );
        let observed = observed.lock().unwrap();
        assert_eq!(observed.connects, 1);
        assert!(observed.writes.len() <= max_steps);
        assert!(observed.bytes() <= max_wire_bytes_sent);
        observed.assert_within(&policy);
    }
}

#[test]
fn tls_audit_over_the_reservation_is_rejected_before_connecting() {
    let (client, observed) = fake_client(&budget(TLS_UNITS - 1, TLS_BYTES), Server::Tls, None);
    assert_traffic_unit_limit(client.audit_tls(&tls_request(CA)));
    observed.lock().unwrap().assert_untouched();

    let (client, observed) = fake_client(&budget(TLS_UNITS, TLS_BYTES - 1), Server::Tls, None);
    assert_traffic_byte_limit(client.audit_tls(&tls_request(CA)));
    observed.lock().unwrap().assert_untouched();
}

#[test]
fn one_connection_and_one_message_cannot_admit_a_multi_write_tls_session() {
    let policy = budget(2, TLS_BYTES);
    let (client, observed) = fake_client(&policy, Server::Tls, None);
    let result = client.audit_tls(&tls_request(CA));
    let tls_observed = observed.lock().unwrap();
    assert!(
        matches!(
            result,
            Err(Error::Policy(PolicyError::TrafficUnitLimit { .. }))
        ),
        "TLS audit admitted by a 2-unit policy performed {} connects and {} writes",
        tls_observed.connects,
        tls_observed.writes.len()
    );
    tls_observed.assert_untouched();

    let (client, observed) = fake_client(&policy, Server::Tls, None);
    let result = client.audit_http(&https_request(CA));
    let https_observed = observed.lock().unwrap();
    assert!(
        matches!(
            result,
            Err(Error::Policy(PolicyError::TrafficUnitLimit { .. }))
        ),
        "HTTPS audit admitted by a 2-unit policy performed {} connects and {} writes",
        https_observed.connects,
        https_observed.writes.len()
    );
    https_observed.assert_untouched();
}

#[test]
fn https_audit_sends_the_exact_request_inside_the_tls_reservation() {
    let policy = budget(TLS_UNITS, TLS_BYTES);
    let (client, observed) = fake_client(&policy, Server::Tls, None);
    let report = client.audit_http(&https_request(CA)).unwrap();
    assert_eq!(report.kind, "audit-http");
    assert_eq!(report.measurements["bytes_sent"], json!(REQUEST.len()));
    let observed = observed.lock().unwrap();
    assert_eq!(observed.received, REQUEST);
    assert_eq!(observed.connects, 1);
    assert!(observed.writes.len() <= MAX_STEPS);
    assert!(observed.bytes() <= MAX_WIRE_BYTES_SENT);
    observed.assert_within(&policy);
}

#[test]
fn https_audit_over_the_reservation_is_rejected_before_connecting() {
    let (client, observed) = fake_client(&budget(TLS_UNITS - 1, TLS_BYTES), Server::Tls, None);
    assert_traffic_unit_limit(client.audit_http(&https_request(CA)));
    observed.lock().unwrap().assert_untouched();

    let (client, observed) = fake_client(&budget(TLS_UNITS, TLS_BYTES - 1), Server::Tls, None);
    assert_traffic_byte_limit(client.audit_http(&https_request(CA)));
    observed.lock().unwrap().assert_untouched();
}

#[test]
fn https_audit_withholds_the_request_when_the_certificate_is_untrusted() {
    let policy = budget(TLS_UNITS, TLS_BYTES);
    let (client, observed) = fake_client(&policy, Server::Tls, None);
    let report = client.audit_http(&https_request(UNTRUSTED_CA)).unwrap();
    assert!(
        report
            .completeness
            .reasons
            .iter()
            .any(|reason| reason.contains("HTTP request withheld")),
        "{:?}",
        report.completeness
    );
    let observed = observed.lock().unwrap();
    assert_eq!(observed.connects, 1);
    assert!(observed.received.is_empty());
    observed.assert_within(&policy);
}

#[test]
fn plain_http_audit_sends_one_request_message_across_short_writes() {
    let (units, bytes) = plain_units_and_bytes();
    let policy = budget(units, bytes);
    let (client, observed) = fake_client(&policy, Server::Plain, None);
    let report = client.audit_http(&HttpRequest::new(ENDPOINT)).unwrap();
    assert_eq!(report.measurements["bytes_sent"], json!(REQUEST.len()));
    let observed = observed.lock().unwrap();
    assert_eq!(observed.connects, 1);
    assert_eq!(observed.received, REQUEST);
    assert_eq!(observed.bytes(), REQUEST.len());
    assert!(observed.writes.len() > 2 && observed.writes.contains(&0));
}

#[test]
fn plain_http_audit_over_one_connection_and_request_is_rejected_before_connecting() {
    let (units, bytes) = plain_units_and_bytes();
    let (client, observed) = fake_client(&budget(units, bytes - 1), Server::Plain, None);
    assert_traffic_byte_limit(client.audit_http(&HttpRequest::new(ENDPOINT)));
    observed.lock().unwrap().assert_untouched();

    let (client, observed) = fake_client(&budget(units - 1, bytes), Server::Plain, None);
    assert_traffic_unit_limit(client.audit_http(&HttpRequest::new(ENDPOINT)));
    observed.lock().unwrap().assert_untouched();
}

fn audit_all(client: &FakeClient, server: Server) -> Vec<Result<Report, Error>> {
    match server {
        Server::Tls => vec![
            client.audit_tls(&tls_request(CA)),
            client.audit_http(&https_request(CA)),
        ],
        Server::Plain => vec![client.audit_http(&HttpRequest::new(ENDPOINT))],
    }
}

#[test]
fn excluded_destination_is_rejected_before_connecting() {
    let policy = Policy {
        allowed_destinations: vec!["10.0.0.1".parse().unwrap()],
        ..budget(TLS_UNITS, TLS_BYTES)
    };
    for server in [Server::Tls, Server::Plain] {
        let (client, observed) = fake_client(&policy, server, None);
        for result in audit_all(&client, server) {
            assert!(
                matches!(
                    result,
                    Err(Error::Policy(PolicyError::DestinationNotAllowed { .. }))
                ),
                "{result:?}"
            );
        }
        observed.lock().unwrap().assert_untouched();
    }
}

#[test]
fn provider_reporting_another_peer_is_rejected_before_any_write() {
    let policy = budget(TLS_UNITS, TLS_BYTES);
    let other = Some(SocketAddr::from(([127, 0, 0, 2], 443)));
    for server in [Server::Tls, Server::Plain] {
        let (client, observed) = fake_client(&policy, server, other);
        let results = audit_all(&client, server);
        let attempts = results.len();
        for result in results {
            assert!(
                matches!(&result, Err(Error::Io(e)) if e.kind() == io::ErrorKind::InvalidData),
                "{result:?}"
            );
        }
        let observed = observed.lock().unwrap();
        assert_eq!(observed.connects, attempts);
        assert!(observed.writes.is_empty() && observed.received.is_empty());
    }
}

#[test]
fn unusable_tls_requests_are_rejected_before_connecting() {
    let policy = budget(TLS_UNITS, TLS_BYTES);
    let port_zero = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    for request in [
        TlsRequest::new(port_zero),
        TlsRequest {
            timeout: Duration::ZERO,
            ..tls_request(CA)
        },
        TlsRequest {
            timeout: Duration::from_secs(3601),
            ..tls_request(CA)
        },
    ] {
        let (client, observed) = fake_client(&policy, Server::Tls, None);
        let result = client.audit_tls(&request);
        assert!(matches!(result, Err(Error::Invalid(_))), "{result:?}");
        observed.lock().unwrap().assert_untouched();
    }
}

#[test]
fn a_one_hour_tls_timeout_is_admitted() {
    let request = TlsRequest {
        timeout: Duration::from_secs(3600),
        ..tls_request(CA)
    };
    let (client, _) = fake_client(&budget(TLS_UNITS, TLS_BYTES), Server::Tls, None);
    assert!(client.audit_tls(&request).is_ok());
}

#[test]
fn unusable_http_requests_are_rejected_before_connecting() {
    let policy = budget(u64::MAX, u64::MAX);
    for request in [
        HttpRequest {
            host: String::new(),
            ..HttpRequest::new(ENDPOINT)
        },
        HttpRequest {
            host: "a".repeat(1025),
            ..HttpRequest::new(ENDPOINT)
        },
        HttpRequest {
            host: "bad host".into(),
            ..HttpRequest::new(ENDPOINT)
        },
        HttpRequest {
            host: "bad/host".into(),
            ..HttpRequest::new(ENDPOINT)
        },
        HttpRequest {
            path: "relative".into(),
            ..HttpRequest::new(ENDPOINT)
        },
        HttpRequest {
            path: format!("/{}", "a".repeat(8192)),
            ..HttpRequest::new(ENDPOINT)
        },
        HttpRequest {
            path: "/bad path".into(),
            ..HttpRequest::new(ENDPOINT)
        },
        HttpRequest {
            max_response_bytes: 0,
            ..HttpRequest::new(ENDPOINT)
        },
        HttpRequest {
            max_response_bytes: 65_536,
            ..HttpRequest::new(ENDPOINT)
        },
    ] {
        let (client, observed) = fake_client(&policy, Server::Plain, None);
        let result = client.audit_http(&request);
        assert!(matches!(result, Err(Error::Invalid(_))), "{result:?}");
        observed.lock().unwrap().assert_untouched();
    }
}

#[test]
fn the_longest_http_host_and_path_are_admitted() {
    let request = HttpRequest {
        host: "a".repeat(1024),
        path: format!("/{}", "a".repeat(8191)),
        ..HttpRequest::new(ENDPOINT)
    };
    let (client, _) = fake_client(&budget(2, u64::MAX), Server::Plain, None);
    assert!(client.audit_http(&request).is_ok());
}

#[test]
fn an_exchange_io_failure_is_reported_as_io_not_incomplete() {
    let (client, observed) = client_with(
        &budget(2, u64::MAX),
        fake_tcp(Server::Plain, None, RESPONSE, true, None),
    );
    let result = client.audit_http(&HttpRequest::new(ENDPOINT));
    assert!(
        matches!(&result, Err(Error::Io(error)) if error.kind() == io::ErrorKind::ConnectionReset),
        "{result:?}"
    );
    assert_eq!(observed.lock().unwrap().connects, 1);
}

#[test]
fn an_exchange_timeout_reports_the_deadline_error() {
    let jump = Arc::new(AtomicBool::new(false));
    let tcp = fake_tcp(
        Server::Plain,
        None,
        RESPONSE,
        false,
        Some(Arc::clone(&jump)),
    );
    let observed = Arc::clone(&tcp.observed);
    let client = Client::new(
        Arc::new(Registry::default()),
        budget(2, u64::MAX),
        ProviderSet::tcp(tcp, ()),
    )
    .with_clock(JumpClock { jump });
    let result = client.audit_http(&HttpRequest::new(ENDPOINT));
    assert!(
        matches!(result, Err(Error::Tcp(tcp::Error::DeadlineExceeded))),
        "{result:?}"
    );
    assert_eq!(observed.lock().unwrap().connects, 1);
}

#[test]
fn the_final_response_is_the_last_informational_or_terminal_head() {
    for (response, status) in [
        (b"HTTP/1.1 101 Switching Protocols\r\n\r\n" as &[u8], 101),
        (
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            200,
        ),
    ] {
        let (client, _) = client_with(
            &budget(2, u64::MAX),
            fake_tcp(Server::Plain, None, response, false, None),
        );
        let report = client.audit_http(&HttpRequest::new(ENDPOINT)).unwrap();
        assert_eq!(report.measurements["status"], json!(status));
    }
}
