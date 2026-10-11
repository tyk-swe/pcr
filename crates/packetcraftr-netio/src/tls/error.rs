// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;

use packetcraftr_core::budget::Interrupted;
use packetcraftr_core::error::{Classification, Classified, Kind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Sent,
    Read,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(
        "TLS requires bounded nonzero wire-byte, step, certificate-count, and handshake-time limits"
    )]
    InvalidLimits,
    #[error("TLS server name must be an operator-declared DNS name of at most 253 bytes")]
    InvalidServerName,
    #[error(transparent)]
    Interrupted(#[from] Interrupted),
    #[error("TLS {direction:?} wire byte limit of {limit} reached")]
    WireLimit { direction: Direction, limit: usize },
    #[error("TLS I/O step limit of {limit} reached")]
    StepLimit { limit: usize },
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("TLS protocol failure: {0}")]
    Protocol(#[from] rustls::Error),
}

impl Error {
    pub(super) fn into_io(self) -> io::Error {
        let kind = match &self {
            Self::Io(source) => source.kind(),
            Self::Protocol(_) => io::ErrorKind::InvalidData,
            // Session deadlines, cancellation, and resource ceilings are
            // terminal. A retryable native-I/O kind would let a different
            // outer deadline delay an outcome that cannot be resumed.
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }

    pub(super) fn from_io(source: io::Error) -> Self {
        if let Some(inner) = source.get_ref()
            && inner.is::<Self>()
        {
            // The type was checked above; retaining the original error avoids
            // erasing wire-limit and cancellation outcomes at rustls's I/O API.
            *source.into_inner().unwrap().downcast::<Self>().unwrap()
        } else {
            Self::Io(source)
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidLimits => Classification::new("cli.tls_limits", Kind::Usage, None),
            Self::InvalidServerName => {
                Classification::new("cli.tls_server_name", Kind::Usage, None)
            }
            Self::Interrupted(source) => source.classification(),
            Self::WireLimit { .. } | Self::StepLimit { .. } => {
                Classification::new("policy.tls_limit", Kind::Policy, None)
            }
            Self::Io(_) => Classification::new("io.tls_transport", Kind::Io, None),
            Self::Protocol(_) => Classification::new("io.tls_protocol", Kind::Io, None),
        }
    }
}
