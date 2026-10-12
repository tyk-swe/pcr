// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::io::{self, Cursor, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::tcp;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const CERTIFICATE: &[u8] =
    include_bytes!("../../../packetcraftr-netio/src/tls/test_support/certificate.der");
const KEY: &[u8] = include_bytes!("../../../packetcraftr-netio/src/tls/test_support/key.der");
pub(crate) const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\n\r\n";

#[derive(Default)]
pub(crate) struct Observed {
    pub response_reads: usize,
    pub application_request: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct TlsTcp {
    config: Arc<rustls::ServerConfig>,
    malformed: bool,
    pub observed: Arc<Mutex<Observed>>,
}

impl TlsTcp {
    pub(crate) fn new(version: &'static rustls::SupportedProtocolVersion, malformed: bool) -> Self {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(CERTIFICATE.to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
        )
        .unwrap();
        Self {
            config: Arc::new(config),
            malformed,
            observed: Arc::default(),
        }
    }
}

impl tcp::Provider for TlsTcp {
    type Stream = Peer;

    fn connect(&self, endpoint: SocketAddr, deadline: &Deadline) -> Result<Peer, tcp::Error> {
        deadline.enforce().unwrap();
        Ok(Peer {
            session: rustls::ServerConnection::new(Arc::clone(&self.config)).unwrap(),
            incoming: VecDeque::new(),
            responded: false,
            malformed: self.malformed,
            endpoint,
            observed: Arc::clone(&self.observed),
        })
    }
}

pub(crate) struct Peer {
    session: rustls::ServerConnection,
    incoming: VecDeque<u8>,
    responded: bool,
    malformed: bool,
    endpoint: SocketAddr,
    observed: Arc<Mutex<Observed>>,
}

impl Read for Peer {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        while self.session.wants_write() {
            let mut output = Vec::new();
            self.session.write_tls(&mut output)?;
            self.incoming.extend(output);
        }
        if self.responded {
            self.observed.lock().unwrap().response_reads += 1;
            if self.malformed {
                // Coalesce a complete application record with an invalid TLS
                // content type so the client already knows the fatal error.
                self.incoming.extend([0xff, 0x03, 0x03, 0, 1, 0]);
                self.malformed = false;
            }
        }
        let count = bytes.len().min(self.incoming.len());
        for byte in &mut bytes[..count] {
            *byte = self.incoming.pop_front().unwrap();
        }
        if count == 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(count)
    }
}

impl Write for Peer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut input = Cursor::new(bytes);
        while (input.position() as usize) < bytes.len() {
            self.session.read_tls(&mut input)?;
            self.session
                .process_new_packets()
                .map_err(io::Error::other)?;
        }
        if !self.session.is_handshaking() && !self.responded {
            let mut request = [0; 1024];
            match self.session.reader().read(&mut request) {
                Ok(count) if count > 0 => {
                    self.observed.lock().unwrap().application_request = request[..count].to_vec();
                    self.session.writer().write_all(RESPONSE)?;
                    self.responded = true;
                }
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => (),
                Ok(_) => (),
                Err(source) => return Err(source),
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl tcp::Stream for Peer {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.endpoint)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:40000".parse().unwrap())
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        assert!(timeout.is_some_and(|wait| !wait.is_zero() && wait <= Duration::from_millis(25)));
        Ok(())
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }
}
