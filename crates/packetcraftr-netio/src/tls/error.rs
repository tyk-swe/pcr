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
            let kind = source.kind();
            if let Some(inner) = source.into_inner()
                && let Ok(error) = inner.downcast::<Self>()
            {
                return *error;
            }
            return Self::Io(io::Error::from(kind));
        }
        Self::Io(source)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_roundtrip_retains_the_typed_error() {
        let recovered = Error::from_io(
            Error::WireLimit {
                direction: Direction::Sent,
                limit: 9,
            }
            .into_io(),
        );
        assert!(matches!(
            recovered,
            Error::WireLimit {
                direction: Direction::Sent,
                limit: 9
            }
        ));
    }

    #[test]
    fn into_io_preserves_the_kind_each_variant_promises() {
        assert_eq!(
            Error::Io(io::Error::from(io::ErrorKind::ConnectionReset))
                .into_io()
                .kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(
            Error::Protocol(rustls::Error::DecryptError)
                .into_io()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(Error::InvalidLimits.into_io().kind(), io::ErrorKind::Other);
        assert_eq!(
            Error::InvalidServerName.into_io().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(
            Error::WireLimit {
                direction: Direction::Read,
                limit: 1
            }
            .into_io()
            .kind(),
            io::ErrorKind::Other
        );
        assert_eq!(
            Error::StepLimit { limit: 1 }.into_io().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(
            Error::Interrupted(Interrupted::Cancelled(packetcraftr_core::budget::Cancelled))
                .into_io()
                .kind(),
            io::ErrorKind::Other
        );
        let exceeded = packetcraftr_core::budget::Deadline::new(std::time::Duration::ZERO)
            .live_remaining()
            .unwrap_err();
        assert!(matches!(exceeded, Interrupted::Exceeded(_)));
        assert_eq!(
            Error::Interrupted(exceeded).into_io().kind(),
            io::ErrorKind::Other
        );
    }

    #[test]
    fn io_roundtrip_preserves_os_error_detail() {
        let recovered = Error::from_io(io::Error::from_raw_os_error(2));
        match recovered {
            Error::Io(source) => assert_eq!(source.raw_os_error(), Some(2)),
            other => panic!("expected Io, got {other:?}"),
        }
        let recovered = Error::from_io(io::Error::new(io::ErrorKind::InvalidData, "plain detail"));
        match recovered {
            Error::Io(source) => assert!(source.to_string().contains("plain detail")),
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn io_roundtrip_keeps_plain_io_errors_and_their_kind() {
        let recovered = Error::from_io(io::Error::from(io::ErrorKind::ConnectionReset));
        match recovered {
            Error::Io(source) => assert_eq!(source.kind(), io::ErrorKind::ConnectionReset),
            other => panic!("expected Io, got {other:?}"),
        }
        let recovered = Error::from_io(io::Error::new(io::ErrorKind::InvalidData, "plain"));
        match recovered {
            Error::Io(source) => assert_eq!(source.kind(), io::ErrorKind::InvalidData),
            other => panic!("expected Io, got {other:?}"),
        }
    }
}
