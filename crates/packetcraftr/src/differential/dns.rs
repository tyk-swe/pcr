// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::protocol::application::dns as core_dns;
use packetcraftr_netio::bounded::Outcome;
use packetcraftr_netio::udp::Provider as _;
use sha2::{Digest, Sha256};

use super::canary::TOKEN_LEN;
use super::error::Error;
use super::report::{ReceptionRecord, ResponderEvent, ResponderReport, hex};
use crate::clock::{Clock, SystemClock};
use crate::dns::wire;
use crate::dns::{MessageLimits, QueryType};
use crate::policy::{SocketLimits, SocketOperation};
use crate::providers::{TcpOf, TcpProviders, UdpProviders};
use crate::{Client, Sink};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug)]
pub struct Variant {
    pub id: &'static str,
    pub hypothesis: &'static str,
    pub transport: Transport,
    recursion_desired: bool,
    edns_payload_size: Option<u16>,
    dnssec_ok: bool,
    uppercase: bool,
}

const CATALOG: &[Variant] = &[
    Variant {
        id: "dns-baseline",
        hypothesis: "A plain recursive query without EDNS is answered",
        transport: Transport::Udp,
        recursion_desired: true,
        edns_payload_size: None,
        dnssec_ok: false,
        uppercase: false,
    },
    Variant {
        id: "dns-no-rd",
        hypothesis: "The same query without recursion desired is answered",
        transport: Transport::Udp,
        recursion_desired: false,
        edns_payload_size: None,
        dnssec_ok: false,
        uppercase: false,
    },
    Variant {
        id: "dns-edns-512",
        hypothesis: "An EDNS query advertising 512 bytes is answered",
        transport: Transport::Udp,
        recursion_desired: true,
        edns_payload_size: Some(512),
        dnssec_ok: false,
        uppercase: false,
    },
    Variant {
        id: "dns-edns-4096",
        hypothesis: "An EDNS query advertising 4096 bytes is answered",
        transport: Transport::Udp,
        recursion_desired: true,
        edns_payload_size: Some(4096),
        dnssec_ok: false,
        uppercase: false,
    },
    Variant {
        id: "dns-dnssec-ok",
        hypothesis: "An EDNS query with DNSSEC OK is answered",
        transport: Transport::Udp,
        recursion_desired: true,
        edns_payload_size: Some(1232),
        dnssec_ok: true,
        uppercase: false,
    },
    Variant {
        id: "dns-uppercase-qname",
        hypothesis: "An uppercase query name receives the same answer behavior",
        transport: Transport::Udp,
        recursion_desired: true,
        edns_payload_size: None,
        dnssec_ok: false,
        uppercase: true,
    },
    Variant {
        id: "dns-tcp",
        hypothesis: "The baseline query over TCP is answered",
        transport: Transport::Tcp,
        recursion_desired: true,
        edns_payload_size: None,
        dnssec_ok: false,
        uppercase: false,
    },
];

#[must_use]
pub fn catalog() -> &'static [Variant] {
    CATALOG
}

#[derive(Clone, Debug)]
pub struct Request {
    pub server: SocketAddrV4,
    pub token: [u8; TOKEN_LEN],
    pub repeats: u32,
    pub timeout: Duration,
    pub max_duration: Duration,
    pub limits: MessageLimits,
}

impl Request {
    #[must_use]
    pub fn new(server: SocketAddrV4, token: [u8; TOKEN_LEN]) -> Self {
        Self {
            server,
            token,
            repeats: 3,
            timeout: Duration::from_secs(2),
            max_duration: Duration::from_secs(300),
            limits: MessageLimits::default(),
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.server.port() == 0 {
            return Err(Error::InvalidRequest {
                field: "port",
                message: "DNS differential server port must be non-zero".to_owned(),
            });
        }
        if self.repeats == 0 || self.repeats > super::request::MAX_REPEATS {
            return Err(Error::InvalidRequest {
                field: "repeats",
                message: format!("must be within 1..={}", super::request::MAX_REPEATS),
            });
        }
        self.limits.validate().map_err(Error::from)?;
        if crate::deadline::duration_violation(self.timeout, packetcraftr_netio::deadline::MAX_WAIT)
            || crate::deadline::duration_violation(
                self.max_duration,
                packetcraftr_netio::deadline::MAX_WAIT,
            )
        {
            return Err(Error::InvalidTimeout {
                value: self.timeout.max(self.max_duration),
                maximum: packetcraftr_netio::deadline::MAX_WAIT,
            });
        }
        let attempts = catalog().len() as u32 * self.repeats;
        let worst = self
            .timeout
            .checked_mul(attempts)
            .ok_or(Error::DurationLimit {
                actual: Duration::MAX,
                limit: self.max_duration,
            })?;
        if worst > self.max_duration {
            return Err(Error::DurationLimit {
                actual: worst,
                limit: self.max_duration,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Row {
    pub variant_index: usize,
    pub attempts: usize,
    pub responses: usize,
    pub timeouts: usize,
    pub failures: usize,
    pub response_bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub rows: Vec<Row>,
    pub diagnostics: Vec<packetcraftr_core::diagnostic::Diagnostic>,
}

fn query_name(token: &[u8; TOKEN_LEN], variant_index: usize, seq: u32, uppercase: bool) -> String {
    let name = format!("v{variant_index}-s{seq}.{}.probe.invalid", hex(token));
    if uppercase {
        name.to_ascii_uppercase()
    } else {
        name
    }
}

fn transaction_id(token: &[u8; TOKEN_LEN], variant_index: usize, seq: u32) -> u16 {
    let mut hasher = Sha256::new();
    hasher.update(token);
    hasher.update((variant_index as u64).to_be_bytes());
    hasher.update(seq.to_be_bytes());
    let digest = hasher.finalize();
    u16::from_be_bytes([digest[0], digest[1]])
}

fn build_query(
    token: &[u8; TOKEN_LEN],
    variant_index: usize,
    variant: &Variant,
    seq: u32,
) -> Result<(Bytes, String, u16), Error> {
    let name = query_name(token, variant_index, seq, variant.uppercase);
    let id = transaction_id(token, variant_index, seq);
    let encoded_name = name.to_ascii_lowercase();
    let query = wire::encode_query(
        &encoded_name,
        QueryType::A,
        id,
        variant.recursion_desired,
        variant
            .edns_payload_size
            .map(|size| crate::dns::EdnsRequest {
                udp_payload_size: size,
                dnssec_ok: variant.dnssec_ok,
            }),
    )
    .map_err(crate::dns::Error::Query)?;
    if !variant.uppercase {
        return Ok((query, name, id));
    }
    let mut wire = query.to_vec();
    let mut offset = 12_usize;
    while let Some(&length) = wire.get(offset) {
        if length == 0 {
            break;
        }
        let start = offset + 1;
        let end = (start + usize::from(length)).min(wire.len());
        for byte in &mut wire[start..end] {
            byte.make_ascii_uppercase();
        }
        offset = end;
    }
    Ok((Bytes::from(wire), name, id))
}

impl<P: UdpProviders + TcpProviders, K: Clock> Client<P, K> {
    pub fn dns_differential(&self, request: &Request) -> Result<Report, Error> {
        request.validate()?;
        let operation = crate::engine::operation::Operation::new(self, request.max_duration);
        let attempts = catalog().len() as u64 * u64::from(request.repeats);
        let max_query = request.limits.max_message_bytes as u64;
        let limits = SocketLimits::new(
            attempts,
            attempts * 2,
            attempts * max_query.saturating_mul(2),
        );
        let endpoints = [SocketAddr::V4(request.server)];
        let socket =
            SocketOperation::new(&endpoints, limits).map_err(|error| Error::Execution {
                attempt: 0,
                source: BoundaryError::from_error(error),
            })?;
        self.policy
            .authorize_window_at(operation.admitted_at)
            .map_err(|error| Error::Execution {
                attempt: 0,
                source: BoundaryError::from_error(error),
            })?;
        self.policy
            .authorize(crate::policy::Operation::Socket(socket))
            .map_err(|error| Error::Execution {
                attempt: 0,
                source: BoundaryError::from_error(error),
            })?;

        let mut rows: Vec<Row> = catalog()
            .iter()
            .enumerate()
            .map(|(variant_index, _)| Row {
                variant_index,
                ..Row::default()
            })
            .collect();
        let mut diagnostics = Vec::new();
        for (variant_index, variant) in catalog().iter().enumerate() {
            for seq in 0..request.repeats {
                let (query, name, id) = build_query(&request.token, variant_index, variant, seq)?;
                let deadline = operation.deadline(self, request.timeout);
                rows[variant_index].attempts += 1;
                let validated = match variant.transport {
                    Transport::Udp => {
                        let reply = self.providers.udp().exchange(
                            SocketAddr::V4(request.server),
                            &query,
                            request.limits.max_message_bytes,
                            &deadline,
                        );
                        match reply {
                            Ok(reply) => match reply.exchange.outcome {
                                Outcome::Complete => wire::decode_response(
                                    &reply.exchange.response,
                                    &name,
                                    QueryType::A,
                                    id,
                                    request.limits,
                                )
                                .map(|response| (reply.exchange.response.len(), response))
                                .map_err(crate::dns::Error::Query),
                                Outcome::TimedOut => {
                                    rows[variant_index].timeouts += 1;
                                    continue;
                                }
                                Outcome::Cancelled => {
                                    operation.deadline.enforce().map_err(|error| {
                                        Error::Execution {
                                            attempt: u64::from(seq),
                                            source: BoundaryError::from_error(error),
                                        }
                                    })?;
                                    rows[variant_index].failures += 1;
                                    continue;
                                }
                                other => {
                                    diagnostics.push(
                                        packetcraftr_core::diagnostic::Diagnostic::new(
                                            packetcraftr_core::diagnostic::Severity::Warning,
                                            "dns-differential.udp-outcome",
                                            format!("{other:?}"),
                                        ),
                                    );
                                    rows[variant_index].failures += 1;
                                    continue;
                                }
                            },
                            Err(error) => {
                                diagnostics.push(packetcraftr_core::diagnostic::Diagnostic::new(
                                    packetcraftr_core::diagnostic::Severity::Warning,
                                    "dns-differential.udp",
                                    error.to_string(),
                                ));
                                rows[variant_index].failures += 1;
                                continue;
                            }
                        }
                    }
                    Transport::Tcp => {
                        let timeout =
                            deadline
                                .live_remaining()
                                .map_err(|error| Error::Execution {
                                    attempt: u64::from(seq),
                                    source: BoundaryError::from_error(error),
                                })?;
                        let response = crate::dns::tcp::query_with_clock(
                            crate::dns::tcp::Request {
                                endpoint: SocketAddr::V4(request.server),
                                query: &query,
                                timeout,
                                cancellation: self.cancellation.as_ref(),
                                max_message_bytes: request.limits.max_message_bytes,
                            },
                            Arc::new(TcpOf(Arc::clone(&self.providers))),
                            &self.clock,
                        );
                        match response {
                            Ok(response) => wire::decode_tcp_frame(
                                &response.frame,
                                &name,
                                QueryType::A,
                                id,
                                request.limits,
                            )
                            .map(|decoded| (response.frame.len().saturating_sub(2), decoded))
                            .map_err(crate::dns::Error::Query),
                            Err(error)
                                if error.category() == crate::dns::tcp::Category::Timeout =>
                            {
                                rows[variant_index].timeouts += 1;
                                continue;
                            }
                            Err(error) => {
                                diagnostics.push(packetcraftr_core::diagnostic::Diagnostic::new(
                                    packetcraftr_core::diagnostic::Severity::Warning,
                                    "dns-differential.tcp",
                                    error.to_string(),
                                ));
                                rows[variant_index].failures += 1;
                                continue;
                            }
                        }
                    }
                };
                match validated {
                    Ok((bytes, _)) => {
                        rows[variant_index].responses += 1;
                        rows[variant_index].response_bytes += bytes as u64;
                    }
                    Err(error) => {
                        diagnostics.push(packetcraftr_core::diagnostic::Diagnostic::new(
                            packetcraftr_core::diagnostic::Severity::Warning,
                            "dns-differential.decode",
                            error.to_string(),
                        ));
                        rows[variant_index].failures += 1;
                    }
                }
            }
        }
        Ok(Report { rows, diagnostics })
    }
}

#[derive(Clone, Debug)]
pub struct ResponderRequest {
    pub bind: Ipv4Addr,
    pub port: u16,
    pub token: [u8; TOKEN_LEN],
    pub max_duration: Duration,
    pub idle_after_first: Option<Duration>,
    pub max_datagrams: usize,
    pub cancellation: Option<packetcraftr_core::budget::Cancellation>,
}

impl ResponderRequest {
    #[must_use]
    pub fn new(bind: Ipv4Addr, port: u16, token: [u8; TOKEN_LEN]) -> Self {
        Self {
            bind,
            port,
            token,
            max_duration: Duration::from_secs(300),
            idle_after_first: Some(Duration::from_secs(30)),
            max_datagrams: 4096,
            cancellation: None,
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.port == 0 {
            return Err(Error::InvalidRequest {
                field: "port",
                message: "DNS responder port must be non-zero".to_owned(),
            });
        }
        if self.max_datagrams == 0 {
            return Err(Error::InvalidRequest {
                field: "max_datagrams",
                message: "must be non-zero".to_owned(),
            });
        }
        Ok(())
    }
}

fn probe_identity(message: &core_dns::Dns, token: &[u8; TOKEN_LEN]) -> Option<(u16, u32)> {
    let question = message.questions.first()?;
    let labels = question.name.labels();
    if labels.len() != 4 {
        return None;
    }
    let first = String::from_utf8_lossy(&labels[0]).to_ascii_lowercase();
    let (variant, seq) = first.split_once("-s")?;
    let presented_token = String::from_utf8_lossy(&labels[1]).to_ascii_lowercase();
    if presented_token != hex(token)
        || !String::from_utf8_lossy(&labels[2]).eq_ignore_ascii_case("probe")
        || !String::from_utf8_lossy(&labels[3]).eq_ignore_ascii_case("invalid")
    {
        return None;
    }
    Some((variant.strip_prefix('v')?.parse().ok()?, seq.parse().ok()?))
}

fn answer_message(
    bytes: &Bytes,
    token: &[u8; TOKEN_LEN],
) -> Result<Option<(u16, u32, Bytes)>, Error> {
    let Ok(mut message) = core_dns::Dns::from_wire_with_limits(
        bytes.clone(),
        crate::dns::MessageLimits::default().into(),
    ) else {
        return Ok(None);
    };
    let Some((variant_index, attempt_seq)) = probe_identity(&message, token) else {
        return Ok(None);
    };
    message.edit(|message| {
        message.response = true;
        message.authoritative_answer = true;
        message.answers.clear();
        message.authorities.clear();
        message.additionals.clear();
    });
    let response = message.to_wire().map_err(|error| Error::ResponderIo {
        message: error.to_string(),
    })?;
    Ok(Some((variant_index, attempt_seq, response)))
}

const TCP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TCP_CONNECTIONS: usize = 128;

struct TcpConnection {
    stream: TcpStream,
    source: SocketAddr,
    inbound: Vec<u8>,
    outbound: std::collections::VecDeque<u8>,
    deadline: Deadline,
    recorded: bool,
}

fn poll_tcp_connection<S>(
    connection: &mut TcpConnection,
    request: &ResponderRequest,
    sink: &mut S,
    report: &mut ResponderReport,
    last_received: &mut Option<Instant>,
) -> Result<bool, Error>
where
    S: Sink<ResponderEvent, Ack = ()>,
{
    connection.deadline.check_cancelled().map_err(Error::from)?;
    if connection.deadline.check().is_err() {
        return Ok(true);
    }
    if !connection.outbound.is_empty() {
        let (front, _) = connection.outbound.as_slices();
        match connection.stream.write(front) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                connection.outbound.drain(..count);
                return Ok(connection.outbound.is_empty());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(_) => return Ok(true),
        }
    }
    let mut chunk = [0_u8; 8192];
    match connection.stream.read(&mut chunk) {
        Ok(0) => return Ok(true),
        Ok(count) => connection.inbound.extend_from_slice(&chunk[..count]),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
        Err(error) => {
            return Err(Error::ResponderIo {
                message: error.to_string(),
            });
        }
    }
    if connection.inbound.len() > 65_537 {
        return Err(Error::ResponderIo {
            message: "TCP DNS frame exceeded the maximum length".to_owned(),
        });
    }
    if connection.inbound.len() < 2 {
        return Ok(false);
    }
    let declared = usize::from(u16::from_be_bytes([
        connection.inbound[0],
        connection.inbound[1],
    ]));
    if connection.inbound.len() < declared + 2 {
        return Ok(false);
    }
    let message = Bytes::copy_from_slice(&connection.inbound[2..declared + 2]);
    let Some((variant_index, attempt_seq, response)) = answer_message(&message, &request.token)?
    else {
        report.ignored += 1;
        return Ok(true);
    };
    *last_received = Some(SystemClock.now());
    report.received += 1;
    connection.recorded = true;
    sink.publish_controlled(
        ResponderEvent::Received(ReceptionRecord {
            variant_index,
            attempt_seq,
            source: connection.source,
            payload_sha256: hex(&Sha256::digest(&message)),
        }),
        &connection.deadline,
    )
    .map_err(|source| Error::Output { source })?;
    connection.outbound.extend(
        u16::try_from(response.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    connection.outbound.extend(response);
    report.replies_sent += 1;
    Ok(false)
}

pub fn respond<S>(request: ResponderRequest, mut sink: S) -> Result<ResponderReport, Error>
where
    S: Sink<ResponderEvent, Ack = ()>,
{
    request.validate()?;
    let socket =
        UdpSocket::bind(SocketAddr::from((request.bind, request.port))).map_err(|source| {
            Error::ResponderIo {
                message: source.to_string(),
            }
        })?;
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .map_err(|source| Error::ResponderIo {
            message: source.to_string(),
        })?;
    let listener =
        TcpListener::bind(SocketAddr::from((request.bind, request.port))).map_err(|source| {
            Error::ResponderIo {
                message: source.to_string(),
            }
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| Error::ResponderIo {
            message: source.to_string(),
        })?;
    let deadline = Arc::new(
        Deadline::new(request.max_duration).with_cancellation(request.cancellation.clone()),
    );
    let mut last_received: Option<Instant> = None;
    let mut report = ResponderReport::default();
    let mut buffer = vec![0_u8; 65_535];
    let mut tcp_connections: Vec<TcpConnection> = Vec::new();
    loop {
        deadline.check_cancelled().map_err(Error::from)?;
        if deadline.check().is_err() {
            return Ok(report);
        }
        if let (Some(idle), Some(last)) = (request.idle_after_first, last_received)
            && last.elapsed() >= idle
        {
            return Ok(report);
        }
        if report.received >= request.max_datagrams {
            return Ok(report);
        }
        let mut index = 0;
        while index < tcp_connections.len() {
            match poll_tcp_connection(
                &mut tcp_connections[index],
                &request,
                &mut sink,
                &mut report,
                &mut last_received,
            ) {
                Ok(true) => {
                    tcp_connections.remove(index);
                }
                Ok(false) => index += 1,
                Err(Error::ResponderIo { .. }) => {
                    if !tcp_connections[index].recorded {
                        report.ignored += 1;
                    }
                    tcp_connections.remove(index);
                }
                Err(error) => return Err(error),
            }
        }
        match listener.accept() {
            Ok((stream, source)) => {
                if tcp_connections.len() < MAX_TCP_CONNECTIONS
                    && stream.set_nonblocking(true).is_ok()
                {
                    tcp_connections.push(TcpConnection {
                        stream,
                        source,
                        inbound: Vec::new(),
                        outbound: std::collections::VecDeque::new(),
                        deadline: Deadline::new(TCP_CONNECTION_TIMEOUT)
                            .with_parent(Some(Arc::clone(&deadline))),
                        recorded: false,
                    });
                }
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                return Err(Error::ResponderIo {
                    message: error.to_string(),
                });
            }
        }
        let (len, source) = match socket.recv_from(&mut buffer) {
            Ok(received) => received,
            Err(error) if packetcraftr_netio::bounded::retryable(&error) => continue,
            Err(error) => {
                return Err(Error::ResponderIo {
                    message: error.to_string(),
                });
            }
        };
        let bytes = Bytes::copy_from_slice(&buffer[..len]);
        let Some((variant_index, attempt_seq, response)) = answer_message(&bytes, &request.token)?
        else {
            report.ignored += 1;
            continue;
        };
        last_received = Some(SystemClock.now());
        report.received += 1;
        sink.publish_controlled(
            ResponderEvent::Received(ReceptionRecord {
                variant_index,
                attempt_seq,
                source,
                payload_sha256: hex(&Sha256::digest(&bytes)),
            }),
            &deadline,
        )
        .map_err(|source| Error::Output { source })?;
        socket
            .send_to(&response, source)
            .map_err(|source| Error::ResponderIo {
                message: source.to_string(),
            })?;
        report.replies_sent += 1;
    }
}

#[cfg(test)]
mod tests {
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
        // The responder binds inside its thread; the valid-probe retry loop
        // below tolerates that startup race.
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
}
