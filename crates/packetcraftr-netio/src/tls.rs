// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded TLS observation transport for authorized, read-only interrogation.
//!
//! The presented certificate chain is evidence, not a trust or hostname
//! authentication decision. Handshake signatures are still verified. This
//! transport opens no socket and performs no DNS lookup; callers connect and
//! authorize the numeric peer first, and authorize every encrypted write.

mod error;
mod verifier;
mod wire;

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use rustls::{ClientConfig, ClientConnection};

pub use error::{Direction, Error};

/// Lifetime ceilings, including the handshake and subsequent application I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_wire_bytes_sent: usize,
    pub max_wire_bytes_read: usize,
    pub max_steps: usize,
    pub max_certificates: usize,
    pub max_certificate_bytes: usize,
    pub handshake_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_wire_bytes_sent: 131_072,
            max_wire_bytes_read: 131_072,
            max_steps: 64,
            max_certificates: 8,
            max_certificate_bytes: 65_536,
            handshake_timeout: Duration::from_secs(1),
        }
    }
}

impl Limits {
    /// Rejects zero or excessive transport limits before preparing a client.
    /// Zero certificate bytes explicitly disables retention.
    pub fn validate(self) -> Result<(), Error> {
        if !(1..=1_048_576).contains(&self.max_wire_bytes_sent)
            || !(1..=1_048_576).contains(&self.max_wire_bytes_read)
            || !(1..=4096).contains(&self.max_steps)
            || !(1..=64).contains(&self.max_certificates)
            || self.max_certificate_bytes > 65_536
            || self.handshake_timeout.is_zero()
            || self.handshake_timeout > Duration::from_secs(3600)
        {
            return Err(Error::InvalidLimits);
        }
        Ok(())
    }
}

/// A numeric identity suppresses SNI. A name must come from operator input,
/// never reverse DNS or another unapproved resolution source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerName {
    Numeric(IpAddr),
    Declared(String),
}

impl ServerName {
    pub fn validate(&self) -> Result<(), Error> {
        self.clone().into_rustls().map(|_| ())
    }

    fn into_rustls(self) -> Result<rustls::pki_types::ServerName<'static>, Error> {
        match self {
            Self::Numeric(ip) => Ok(rustls::pki_types::ServerName::IpAddress(ip.into())),
            Self::Declared(name) if name.len() <= 253 => {
                let parsed = rustls::pki_types::ServerName::try_from(name)
                    .map_err(|_| Error::InvalidServerName)?;
                if matches!(parsed, rustls::pki_types::ServerName::DnsName(_)) {
                    Ok(parsed)
                } else {
                    Err(Error::InvalidServerName)
                }
            }
            Self::Declared(_) => Err(Error::InvalidServerName),
        }
    }
}

/// Retained observations, including partial evidence on handshake failure.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Evidence {
    pub handshake_complete: bool,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    /// Whole DER certificates in presented order; no certificate is sliced.
    pub certificates: Vec<Bytes>,
    pub certificates_truncated: bool,
    pub wire_bytes_sent: usize,
    pub wire_bytes_read: usize,
    /// Native transfer and flush attempts, including unsuccessful attempts.
    pub steps: usize,
}

pub struct Handshake<S, A> {
    pub evidence: Evidence,
    pub result: Result<Stream<S, A>, Error>,
}

/// A connected TLS stream retaining the underlying TCP admission permit.
///
/// The original session deadline and lifetime ceilings cannot be extended by
/// changing socket timeouts. Use [`crate::tcp::exchange`] to retain application
/// bytes and partial write/read outcomes as well as [`Self::evidence`].
pub struct Stream<S, A> {
    session: ClientConnection,
    wire: wire::Wire<S, A>,
    certificates: Arc<Mutex<verifier::Certificates>>,
    handshake_complete: bool,
}

/// Starts TLS over an already connected and authorized numeric peer.
///
/// `authorize_write` sees exactly the ciphertext slice offered to each native
/// write, including retries. It must reauthorize the final peer and bytes;
/// refusal prevents that write. Cancellation is checked again after the hook.
/// Argument errors are returned directly. Every started handshake returns
/// evidence, even when it fails, times out, or is cancelled.
pub fn connect<S, A>(
    stream: S,
    name: ServerName,
    limits: Limits,
    deadline: &Deadline,
    authorize_write: A,
) -> Result<Handshake<S, A>, Error>
where
    S: crate::tcp::Stream,
    A: FnMut(&[u8]) -> io::Result<()> + Send,
{
    limits.validate()?;
    let name = name.into_rustls()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certificates = Arc::new(Mutex::new(verifier::Certificates::default()));
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier::ObservationVerifier::new(
            provider,
            Arc::clone(&certificates),
            limits,
        )))
        .with_no_client_auth();
    let mut session = ClientConnection::new(Arc::new(config), name)?;
    // One TLS application record can be queued. Rustls separately bounds
    // handshake messages to 65535 bytes before parsing them.
    session.set_buffer_limit(Some(16_384));
    let mut stream = Stream {
        session,
        wire: wire::Wire::new(stream, limits, deadline.clone(), authorize_write),
        certificates,
        handshake_complete: false,
    };
    let result = match deadline.for_wait(limits.handshake_timeout) {
        Ok(handshake_deadline) => {
            stream.wire.deadline = handshake_deadline;
            stream.handshake()
        }
        Err(source) => match deadline.check_cancelled() {
            Err(cancelled) => Err(Error::Interrupted(cancelled.into())),
            Ok(()) => Err(Error::Interrupted(source.into())),
        },
    };
    stream.handshake_complete = result.is_ok();
    let evidence = stream.evidence();
    stream.wire.deadline = deadline.clone();
    Ok(Handshake {
        evidence,
        result: result.map(|()| stream),
    })
}

impl<S, A> Stream<S, A>
where
    S: crate::tcp::Stream,
    A: FnMut(&[u8]) -> io::Result<()> + Send,
{
    pub fn evidence(&self) -> Evidence {
        let certificates = self
            .certificates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Evidence {
            handshake_complete: self.handshake_complete,
            protocol_version: self
                .session
                .protocol_version()
                .map(|value| format!("{value:?}")),
            cipher_suite: self
                .session
                .negotiated_cipher_suite()
                .map(|value| format!("{:?}", value.suite())),
            certificates: certificates.chain.clone(),
            certificates_truncated: certificates.truncated,
            wire_bytes_sent: self.wire.bytes_sent,
            wire_bytes_read: self.wire.bytes_read,
            steps: self.wire.steps,
        }
    }

    fn handshake(&mut self) -> Result<(), Error> {
        loop {
            self.wire.deadline.enforce()?;
            self.flush_tls()?;
            if !self.session.is_handshaking() {
                return self.wire.deadline.enforce().map_err(Error::from);
            }
            self.read_tls()?;
        }
    }

    fn flush_tls(&mut self) -> Result<(), Error> {
        let mut wrote = false;
        while self.session.wants_write() {
            self.wire.deadline.enforce()?;
            match self.session.write_tls(&mut self.wire) {
                Ok(0) => return Err(Error::Io(io::ErrorKind::WriteZero.into())),
                Ok(_) => wrote = true,
                Err(source) if crate::bounded::retryable(&source) => continue,
                Err(source) => return Err(Error::from_io(source)),
            }
        }
        if wrote {
            loop {
                self.wire.deadline.enforce()?;
                match self.wire.flush() {
                    Ok(()) => break,
                    Err(source) if crate::bounded::retryable(&source) => continue,
                    Err(source) => return Err(Error::from_io(source)),
                }
            }
        }
        Ok(())
    }

    fn read_tls(&mut self) -> Result<(), Error> {
        loop {
            self.wire.deadline.enforce()?;
            match self.session.read_tls(&mut self.wire) {
                Ok(0) if self.session.is_handshaking() => {
                    return Err(Error::Io(io::ErrorKind::UnexpectedEof.into()));
                }
                Ok(_) => {
                    self.session.process_new_packets()?;
                    return Ok(());
                }
                Err(source) if crate::bounded::retryable(&source) => continue,
                Err(source) => return Err(Error::from_io(source)),
            }
        }
    }
}

impl<S, A> Read for Stream<S, A>
where
    S: crate::tcp::Stream,
    A: FnMut(&[u8]) -> io::Result<()> + Send,
{
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.wire
                .deadline
                .enforce()
                .map_err(Error::from)
                .map_err(Error::into_io)?;
            match self.session.reader().read(bytes) {
                Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                    self.flush_tls().map_err(Error::into_io)?;
                    self.read_tls().map_err(Error::into_io)?;
                }
                result => return result,
            }
        }
    }
}

impl<S, A> Write for Stream<S, A>
where
    S: crate::tcp::Stream,
    A: FnMut(&[u8]) -> io::Result<()> + Send,
{
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.wire
            .deadline
            .enforce()
            .map_err(Error::from)
            .map_err(Error::into_io)?;
        if self.session.wants_write() {
            self.flush_tls().map_err(Error::into_io)?;
        }
        // Accepted plaintext is reported before flush, as for any buffered
        // stream. Final evidence separately counts actual encrypted wire I/O.
        self.session.writer().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.wire
            .deadline
            .enforce()
            .map_err(Error::from)
            .map_err(Error::into_io)?;
        self.flush_tls().map_err(Error::into_io)
    }
}

impl<S, A> crate::tcp::Stream for Stream<S, A>
where
    S: crate::tcp::Stream,
    A: FnMut(&[u8]) -> io::Result<()> + Send,
{
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.wire.inner.peer_addr()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.wire.inner.local_addr()
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.wire.inner.set_read_timeout(timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.wire.inner.set_write_timeout(timeout)
    }
}

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;
