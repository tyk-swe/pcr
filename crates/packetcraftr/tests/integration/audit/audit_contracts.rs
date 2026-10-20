// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{
    Client, ProviderSet, SystemProviders,
    audit::{HttpRequest, TlsRequest},
    policy::Policy,
};
use packetcraftr_core::protocol::builtin;
use packetcraftr_netio::{tcp, tls};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const ROOT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../scripts/fixtures/service-identification/loopback-cert.pem"
));
const CERT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/audit-cert.pem"
));
const EXPIRED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/audit-expired.pem"
));
const KEY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/audit-key.pem"
));
fn server(cert: &'static [u8], http: bool) -> (SocketAddr, std::thread::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from_pem_slice(cert).unwrap()],
                PrivateKeyDer::from_pem_slice(KEY).unwrap(),
            )
            .unwrap();
        let mut session = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        while session.is_handshaking() {
            if session.complete_io(&mut socket).is_err() {
                return false;
            }
        }
        if !http {
            return false;
        }
        let mut stream = rustls::StreamOwned::new(session, socket);
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).unwrap_or(0);
        if count > 0 {
            assert!(bytes[..count].starts_with(b"HEAD / HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
        }
        count > 0
    });
    (endpoint, worker)
}
fn request(endpoint: SocketAddr) -> TlsRequest {
    let mut r = TlsRequest::new(endpoint);
    r.trust = tls::TrustStore::from_pem(ROOT).unwrap();
    r.server_name = Some("audit.example.test".into());
    r
}
#[test]
fn trust_name_and_expiration_are_independent() {
    for (cert, trust, name, valid_chain, valid_name) in [
        (CERT, true, "audit.example.test", true, true),
        (CERT, false, "audit.example.test", false, true),
        (CERT, true, "other.example.test", true, false),
        (EXPIRED, true, "audit.example.test", false, true),
    ] {
        let (endpoint, worker) = server(cert, false);
        let mut r = request(endpoint);
        r.server_name = Some(name.into());
        if !trust {
            r.trust = tls::TrustStore::default();
        }
        let report = Client::new(builtin::registry(), Policy::default(), SystemProviders)
            .audit_tls(&r)
            .unwrap();
        let verification = &report.measurements["verification"];
        assert_eq!(verification["chain"]["valid"], valid_chain);
        assert_eq!(verification["name"]["valid"], valid_name);
        assert_eq!(
            report.measurements["certificate_sha256"][0]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        worker.join().unwrap();
    }
}
#[test]
fn https_writes_only_after_verification() {
    for valid in [true, false] {
        let (endpoint, worker) = server(CERT, true);
        let mut r = HttpRequest::new(endpoint);
        r.tls = true;
        r.connection = request(endpoint);
        if !valid {
            r.connection.server_name = Some("wrong.test".into());
        }
        let report = Client::new(builtin::registry(), Policy::default(), SystemProviders)
            .audit_http(&r)
            .unwrap();
        assert_eq!(worker.join().unwrap(), valid);
        if valid {
            assert_eq!(report.measurements["status"], 200);
        } else {
            assert!(!report.completeness.complete);
            assert!(!report.measurements.contains_key("status"));
        }
    }
}
#[derive(Clone)]
struct Count(Arc<AtomicUsize>);
impl tcp::Provider for Count {
    type Stream = tcp::SystemStream;
    fn connect(
        &self,
        _: SocketAddr,
        _: &packetcraftr_core::budget::Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::other("unexpected connect").into())
    }
}
#[test]
fn only_tcp_provider_is_required_and_policy_runs_before_connect() {
    let count = Arc::new(AtomicUsize::new(0));
    // Unit providers deliberately implement neither capture, routes, UDP, nor DNS.
    let empty: ProviderSet = ProviderSet::default();
    let providers = empty.with_tcp(Count(count.clone()));
    let client = Client::new(builtin::registry(), Policy::default(), providers);
    let r = TlsRequest::new("8.8.8.8:443".parse().unwrap());
    assert!(client.audit_tls(&r).is_err());
    assert_eq!(count.load(Ordering::SeqCst), 0);
}
#[test]
fn malformed_http_and_silent_peer_fail_operationally() {
    for response in [Some(b"not HTTP\r\n\r\n".as_slice()), None] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut b = [0; 4096];
            let _ = s.read(&mut b);
            if let Some(r) = response {
                s.write_all(r).unwrap();
            } else {
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        let mut r = HttpRequest::new(endpoint);
        r.connection.timeout = Duration::from_millis(100);
        assert!(
            Client::new(builtin::registry(), Policy::default(), SystemProviders)
                .audit_http(&r)
                .is_err()
        );
        worker.join().unwrap();
    }
}
