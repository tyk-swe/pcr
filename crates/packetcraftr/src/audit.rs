// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Single-endpoint, ordinary-socket configuration audits. No DNS or target expansion.
use crate::{
    Client,
    clock::Clock,
    policy::{Operation, SocketLimits, SocketOperation},
    providers::TcpProviders,
};
use packetcraftr_core::{
    budget::Deadline,
    error::{Classification, Classified, Kind},
    security::{self, Finding, Report, Severity},
};
use packetcraftr_netio::{
    bounded,
    tcp::{self, Stream as _},
    tls,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[derive(Clone, Debug)]
pub struct TlsRequest {
    pub endpoint: SocketAddr,
    pub server_name: Option<String>,
    pub trust: tls::TrustStore,
    pub limits: tls::Limits,
    pub timeout: Duration,
}
impl TlsRequest {
    pub fn new(endpoint: SocketAddr) -> Self {
        Self {
            endpoint,
            server_name: None,
            trust: tls::TrustStore::default(),
            limits: tls::Limits::default(),
            timeout: Duration::from_secs(5),
        }
    }
    fn name(&self) -> tls::ServerName {
        self.server_name.as_ref().map_or_else(
            || tls::ServerName::Numeric(self.endpoint.ip()),
            |name| tls::ServerName::Declared(name.clone()),
        )
    }
    fn validate(&self) -> Result<(), Error> {
        self.limits.validate()?;
        self.name().validate()?;
        if self.endpoint.port() == 0
            || self.timeout.is_zero()
            || self.timeout > Duration::from_secs(3600)
        {
            return Err(Error::Invalid(
                "nonzero port and timeout at most one hour required".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub connection: TlsRequest,
    pub tls: bool,
    pub host: String,
    pub path: String,
    pub max_response_bytes: usize,
}
impl HttpRequest {
    pub fn new(endpoint: SocketAddr) -> Self {
        Self {
            connection: TlsRequest::new(endpoint),
            tls: false,
            host: endpoint.to_string(),
            path: "/".into(),
            max_response_bytes: 65_535,
        }
    }
    fn request(&self) -> Result<Vec<u8>, Error> {
        self.connection.validate()?;
        if self.host.is_empty()
            || self.host.len() > 1024
            || !self.host.bytes().all(|b| b.is_ascii_graphic())
            || self
                .host
                .bytes()
                .any(|b| matches!(b, b'/' | b'\\' | b'@' | b'#' | b'?'))
            || !self.path.starts_with('/')
            || self.path.len() > 8192
            || !self.path.bytes().all(|b| b.is_ascii_graphic())
            || !(1..=65_535).contains(&self.max_response_bytes)
        {
            return Err(Error::Invalid(
                "invalid HTTP host, path, or response byte limit".into(),
            ));
        }
        Ok(format!("HEAD {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: PacketcraftR-audit\r\n\r\n", self.path, self.host).into_bytes())
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid audit request: {0}")]
    Invalid(String),
    #[error(transparent)]
    Policy(#[from] crate::policy::Error),
    #[error(transparent)]
    Tcp(#[from] tcp::Error),
    #[error(transparent)]
    Tls(#[from] tls::Error),
    #[error(transparent)]
    Interrupted(#[from] packetcraftr_core::budget::Interrupted),
    #[error("HTTP response ended or reached its byte limit without a complete final header")]
    IncompleteResponse,
    #[error("audit I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid HTTP response: {0}")]
    Http(#[from] packetcraftr_core::protocol::application::http::Error),
}
impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Invalid(_) => Classification::new("cli.audit_request", Kind::Usage, None),
            Self::Policy(e) => e.classification(),
            Self::Tcp(e) => e.classification(),
            Self::Tls(e) => e.classification(),
            Self::Interrupted(e) => e.classification(),
            Self::Http(e) => e.classification(),
            Self::IncompleteResponse | Self::Io(_) => {
                Classification::new("io.audit", Kind::Io, None)
            }
        }
    }
}
fn authorize(
    policy: &crate::policy::Policy,
    endpoint: SocketAddr,
    connections: u64,
    bytes: usize,
) -> Result<(), Error> {
    let endpoints = [endpoint];
    let operation = SocketOperation::new(
        &endpoints,
        SocketLimits::new(connections, u64::from(bytes > 0), bytes as u64),
    )
    .map_err(|e| Error::Invalid(e.to_string()))?;
    policy.authorize(Operation::Socket(operation))?;
    Ok(())
}
struct Authorized<P> {
    providers: Arc<P>,
    policy: Arc<crate::policy::Policy>,
}
impl<P: TcpProviders> tcp::Provider for Authorized<P> {
    type Stream = <P::Tcp as tcp::Provider>::Stream;
    fn connect(
        &self,
        endpoint: SocketAddr,
        deadline: &Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        self.policy
            .authorize_destination(endpoint.ip())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        self.providers.tcp().connect(endpoint, deadline)
    }
}
fn tls_report(request: &TlsRequest, evidence: &tls::Evidence) -> Report {
    let mut report = Report::new("audit-tls");
    let verified = tls::verify(evidence, &request.name(), &request.trust);
    report
        .measurements
        .insert("endpoint".into(), json!(request.endpoint));
    report
        .measurements
        .insert("server_name".into(), json!(request.server_name));
    report
        .measurements
        .insert("protocol".into(), json!(evidence.protocol_version));
    report
        .measurements
        .insert("cipher".into(), json!(evidence.cipher_suite));
    report.measurements.insert(
        "certificate_sha256".into(),
        json!(
            evidence
                .certificates
                .iter()
                .map(|c| Sha256::digest(c)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>())
                .collect::<Vec<_>>()
        ),
    );
    report
        .measurements
        .insert("verification".into(), json!(verified));
    report
        .measurements
        .insert("wire_bytes_sent".into(), json!(evidence.wire_bytes_sent));
    report
        .measurements
        .insert("wire_bytes_read".into(), json!(evidence.wire_bytes_read));
    for (rule, check, summary, remediation) in [
        (
            "tls.chain_invalid",
            &verified.chain,
            "Certificate chain did not validate",
            "Install a valid certificate chain issued by a trusted CA.",
        ),
        (
            "tls.name_mismatch",
            &verified.name,
            "Certificate does not match the requested name or IP",
            "Use the intended server name and a certificate with the matching subject alternative name.",
        ),
    ] {
        if check.valid != Some(true) {
            let mut f = Finding::new(
                rule,
                Severity::High,
                request.endpoint.to_string(),
                summary,
                json!(check),
                remediation,
            );
            f.complete = check.valid.is_some();
            report.findings.push(f);
        }
    }
    if evidence.certificates_truncated {
        report.completeness.note("certificate evidence truncated");
    }
    if !evidence.handshake_complete {
        report.completeness.note("TLS handshake incomplete");
    }
    report
}
impl<P: TcpProviders, K: Clock> Client<P, K> {
    fn audit_connection(
        &self,
        request: &TlsRequest,
        bytes: usize,
        deadline: &Deadline,
    ) -> Result<tcp::Connection<<P::Tcp as tcp::Provider>::Stream>, Error> {
        request.validate()?;
        self.policy.validate()?;
        authorize(&self.policy, request.endpoint, 1, bytes)?;
        deadline.enforce()?;
        let provider = Arc::new(Authorized {
            providers: Arc::clone(&self.providers),
            policy: Arc::clone(&self.policy),
        });
        let mut pending = tcp::start_connect(provider, request.endpoint, deadline)?;
        let mut_result = pending
            .wait(deadline)?
            .ok_or(tcp::Error::DeadlineExceeded)?;
        let stream = mut_result.result?;
        let peer = stream.peer_addr()?;
        if !bounded::same_peer(peer, request.endpoint) {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TCP provider changed the authorized peer",
            )));
        }
        self.policy.authorize_destination(peer.ip())?;
        Ok(stream)
    }
    pub fn audit_tls(&self, request: &TlsRequest) -> Result<Report, Error> {
        let deadline = self.deadline(request.timeout);
        let stream =
            self.audit_connection(request, request.limits.max_wire_bytes_sent, &deadline)?;
        let policy = Arc::clone(&self.policy);
        let endpoint = request.endpoint;
        let handshake = tls::connect(
            stream,
            request.name(),
            request.limits,
            &deadline,
            move |bytes| {
                authorize(&policy, endpoint, 0, bytes.len()).map_err(std::io::Error::other)
            },
        )?;
        handshake.result?;
        deadline.enforce()?;
        Ok(tls_report(request, &handshake.evidence))
    }
    pub fn audit_http(&self, request: &HttpRequest) -> Result<Report, Error> {
        let bytes = request.request()?;
        let connection = &request.connection;
        let deadline = self.deadline(connection.timeout);
        let write_budget = if request.tls {
            connection.limits.max_wire_bytes_sent
        } else {
            bytes.len()
        };
        let mut stream = self.audit_connection(connection, write_budget, &deadline)?;
        let mut tls_observation = None;
        let exchange = if request.tls {
            let policy = Arc::clone(&self.policy);
            let endpoint = connection.endpoint;
            let handshake = tls::connect(
                stream,
                connection.name(),
                connection.limits,
                &deadline,
                move |bytes| {
                    authorize(&policy, endpoint, 0, bytes.len()).map_err(std::io::Error::other)
                },
            )?;
            let mut secure = handshake.result?;
            let verification =
                tls::verify(&handshake.evidence, &connection.name(), &connection.trust);
            if !verification.valid() {
                let mut report = tls_report(connection, &handshake.evidence);
                report.kind = "audit-http".into();
                report
                    .completeness
                    .note("HTTP request withheld because TLS certificate verification failed");
                return Ok(report);
            }
            authorize(&self.policy, connection.endpoint, 0, bytes.len())?;
            let exchange = tcp::exchange(
                &mut secure,
                &bytes,
                request.max_response_bytes,
                &deadline,
                response_complete,
            )?;
            if let Some(e) = secure.terminal_error() {
                return Err(Error::Io(e));
            }
            tls_observation = Some(tls_report(connection, &secure.evidence()));
            exchange
        } else {
            authorize(&self.policy, connection.endpoint, 0, bytes.len())?;
            tcp::exchange(
                &mut stream,
                &bytes,
                request.max_response_bytes,
                &deadline,
                response_complete,
            )?
        };
        deadline.enforce()?;
        match exchange.outcome {
            bounded::Outcome::Failed(e) => return Err(Error::Io(e)),
            bounded::Outcome::TimedOut | bounded::Outcome::Cancelled => {
                deadline.enforce()?;
                return Err(Error::Tcp(tcp::Error::DeadlineExceeded));
            }
            _ => {}
        }
        let head = final_head(&exchange.response)?.ok_or(Error::IncompleteResponse)?;
        let mut report =
            security::http::audit(&head, &connection.endpoint.to_string(), request.tls);
        report
            .measurements
            .insert("host".into(), json!(request.host));
        report
            .measurements
            .insert("path".into(), json!(request.path));
        report
            .measurements
            .insert("bytes_sent".into(), json!(exchange.bytes_sent));
        report
            .measurements
            .insert("bytes_read".into(), json!(exchange.response.len()));
        if let Some(tls) = tls_observation {
            report
                .measurements
                .insert("tls".into(), json!(tls.measurements));
        }
        Ok(report)
    }
}
fn final_head(
    bytes: &[u8],
) -> Result<Option<packetcraftr_core::protocol::application::http::Head>, Error> {
    let mut bytes = bytes::Bytes::copy_from_slice(bytes);
    while let Some((head, consumed)) =
        packetcraftr_core::protocol::application::http::parse_head(&bytes)?
    {
        let status = head.status().ok_or(
            packetcraftr_core::protocol::application::http::Error::Invalid(
                "expected a response start line",
            ),
        )?;
        if status >= 200 || status == 101 {
            return Ok(Some(head));
        }
        bytes = bytes.slice(consumed..);
    }
    Ok(None)
}
fn response_complete(bytes: &[u8]) -> bool {
    !matches!(final_head(bytes), Ok(None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_report_retains_observations_when_certificate_retention_is_truncated() {
        let request = TlsRequest {
            server_name: Some("example.test".into()),
            limits: tls::Limits {
                max_certificate_bytes: 0,
                ..Default::default()
            },
            ..TlsRequest::new("127.0.0.1:8443".parse().unwrap())
        };
        let evidence = tls::Evidence {
            handshake_complete: true,
            protocol_version: Some("observed protocol".into()),
            cipher_suite: Some("observed cipher".into()),
            certificates_truncated: true,
            wire_bytes_sent: 311,
            wire_bytes_read: 1024,
            ..Default::default()
        };
        let report = tls_report(&request, &evidence);
        assert_eq!(report.kind, "audit-tls");
        assert_eq!(report.measurements["endpoint"], json!(request.endpoint));
        assert_eq!(
            report.measurements["server_name"],
            json!(request.server_name)
        );
        assert_eq!(
            report.measurements["protocol"],
            json!(evidence.protocol_version)
        );
        assert_eq!(report.measurements["cipher"], json!(evidence.cipher_suite));
        assert_eq!(
            report.measurements["wire_bytes_sent"],
            json!(evidence.wire_bytes_sent)
        );
        assert_eq!(
            report.measurements["wire_bytes_read"],
            json!(evidence.wire_bytes_read)
        );
        assert_eq!(report.measurements["certificate_sha256"], json!([]));
        assert!(!report.completeness.complete);
        assert_eq!(
            report.completeness.reasons,
            ["certificate evidence truncated"]
        );
        let mut findings = report
            .findings
            .iter()
            .map(|finding| (finding.rule_id.as_str(), finding.severity, finding.complete))
            .collect::<Vec<_>>();
        findings.sort_by_key(|finding| finding.0);
        assert_eq!(
            findings,
            [
                ("tls.chain_invalid", Severity::High, false),
                ("tls.name_mismatch", Severity::High, false)
            ]
        );
        for finding in &report.findings {
            assert_eq!(finding.subject, request.endpoint.to_string());
            assert_eq!(
                finding.evidence,
                json!({"valid":null,"reason":"certificate evidence truncated"})
            );
        }
    }
}
