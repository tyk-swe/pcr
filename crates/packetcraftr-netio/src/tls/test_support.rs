// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::cell::Cell;
use std::collections::VecDeque;
use std::io::{self, Cursor, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr_core::budget::Cancellation;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

pub(super) const CERTIFICATE: &[u8] = include_bytes!("test_support/certificate.der");
const KEY: &[u8] = include_bytes!("test_support/key.der");
const WRONG_KEY: &[u8] = include_bytes!("test_support/wrong-key.der");
pub(super) const RESPONSE: &[u8] = b"HTTP/1.0 200 OK\r\nServer: fixture\r\n\r\n";

#[derive(Debug)]
struct Certificate(Arc<CertifiedKey>);

impl ResolvesServerCert for Certificate {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

#[derive(Default)]
pub(super) struct Observed {
    pub ciphertext: Vec<u8>,
    pub reads: usize,
    pub writes: usize,
    pub flushes: usize,
    pub server_name: Option<String>,
}

pub(super) struct Peer {
    session: rustls::ServerConnection,
    incoming: VecDeque<u8>,
    responded: bool,
    pub observed: Arc<Mutex<Observed>>,
    pub cancel_on_timeout: Option<Cancellation>,
    pub cancel_at_timeout_call: usize,
    pub fail_after_write: Option<usize>,
    pub fail_read: bool,
    pub fail_after_response: bool,
    pub silent: bool,
    pub max_write: usize,
    timeout_calls: Cell<usize>,
}

impl Peer {
    pub(super) fn new(version: &'static rustls::SupportedProtocolVersion, wrong_key: bool) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            if wrong_key { WRONG_KEY } else { KEY }.to_vec(),
        ));
        let key = provider.key_provider.load_private_key(private_key).unwrap();
        // The mismatch fixture deliberately bypasses keys_match() so the
        // client must verify the actual handshake signature itself.
        let certified_key =
            CertifiedKey::new(vec![CertificateDer::from(CERTIFICATE.to_vec())], key);
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Certificate(Arc::new(certified_key))));
        Self {
            session: rustls::ServerConnection::new(Arc::new(config)).unwrap(),
            incoming: VecDeque::new(),
            responded: false,
            observed: Arc::default(),
            cancel_on_timeout: None,
            cancel_at_timeout_call: 1,
            fail_after_write: None,
            fail_read: false,
            fail_after_response: false,
            silent: false,
            max_write: usize::MAX,
            timeout_calls: Cell::new(0),
        }
    }
}

impl Read for Peer {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.observed.lock().unwrap().reads += 1;
        if self.fail_read {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        if self.silent {
            return Err(io::ErrorKind::TimedOut.into());
        }
        while self.session.wants_write() {
            let mut output = Vec::new();
            self.session.write_tls(&mut output)?;
            self.incoming.extend(output);
        }
        let count = bytes.len().min(self.incoming.len());
        for byte in &mut bytes[..count] {
            *byte = self.incoming.pop_front().unwrap();
        }
        if self.fail_after_response && self.responded && self.incoming.is_empty() {
            self.fail_read = true;
        }
        if count == 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(count)
    }
}

impl Write for Peer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut observed = self.observed.lock().unwrap();
        observed.writes += 1;
        let sent = observed.ciphertext.len();
        if self.fail_after_write.is_some_and(|limit| sent >= limit) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let count = bytes.len().min(self.max_write).min(
            self.fail_after_write
                .map_or(usize::MAX, |limit| limit - sent),
        );
        observed.ciphertext.extend_from_slice(&bytes[..count]);
        drop(observed);
        if !self.silent {
            let mut input = Cursor::new(&bytes[..count]);
            while (input.position() as usize) < count {
                self.session.read_tls(&mut input)?;
                self.session
                    .process_new_packets()
                    .map_err(io::Error::other)?;
            }
            self.observed.lock().unwrap().server_name =
                self.session.server_name().map(str::to_owned);
            if !self.session.is_handshaking() && !self.responded {
                let mut request = [0; 16_384];
                match self.session.reader().read(&mut request) {
                    Ok(count) if count > 0 => {
                        self.session.writer().write_all(RESPONSE)?;
                        self.responded = true;
                    }
                    Err(source) if source.kind() == io::ErrorKind::WouldBlock => (),
                    Ok(_) => (),
                    Err(source) => return Err(source),
                }
            }
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.observed.lock().unwrap().flushes += 1;
        Ok(())
    }
}

impl crate::tcp::Stream for Peer {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:443".parse().unwrap())
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:12345".parse().unwrap())
    }
    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        self.timeout_calls.set(self.timeout_calls.get() + 1);
        if let Some(signal) = &self.cancel_on_timeout
            && self.timeout_calls.get() == self.cancel_at_timeout_call
        {
            signal.cancel();
        }
        Ok(())
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }
}
