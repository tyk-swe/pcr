// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::{Deadline, Interrupted};
use packetcraftr_netio::tcp;
use std::{io, net::SocketAddr, sync::Arc};

pub(super) fn exchange<S: tcp::Stream>(
    stream: &mut S,
    endpoint: SocketAddr,
    profile: &crate::scan::profile::TcpProfile,
    deadline: &Deadline,
) -> super::Banner {
    let mut sent = 0usize;
    let mut response = Vec::new();
    let mut error = None;
    let mut exchange = || -> io::Result<()> {
        while sent < profile.request().len() {
            let remaining =
                packetcraftr_netio::deadline::remaining(deadline).map_err(interrupted)?;
            deadline
                .check_cancelled()
                .map_err(|source| interrupted(source.into()))?;
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "banner deadline expired",
                ));
            }
            if stream.peer_addr()? != endpoint {
                return Err(io::Error::other("TCP peer changed before banner write"));
            }
            stream.set_write_timeout(Some(
                remaining.min(packetcraftr_netio::deadline::POLL_INTERVAL),
            ))?;
            deadline.enforce().map_err(interrupted)?;
            let written = match stream.write(&profile.request()[sent..]) {
                Err(source)
                    if matches!(
                        source.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    deadline.enforce().map_err(interrupted)?;
                    continue;
                }
                result => result?,
            };
            if written > profile.request().len() - sent {
                return Err(io::Error::other(
                    "TCP provider returned an oversized write count",
                ));
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "banner request write returned zero",
                ));
            }
            sent += written;
        }
        while response.len() < profile.max_response() {
            let remaining =
                packetcraftr_netio::deadline::remaining(deadline).map_err(interrupted)?;
            deadline
                .check_cancelled()
                .map_err(|source| interrupted(source.into()))?;
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "banner deadline expired",
                ));
            }
            if stream.peer_addr()? != endpoint {
                return Err(io::Error::other("TCP peer changed before banner read"));
            }
            stream.set_read_timeout(Some(
                remaining.min(packetcraftr_netio::deadline::POLL_INTERVAL),
            ))?;
            deadline.enforce().map_err(interrupted)?;
            let mut buffer = [0u8; 4096];
            let available = buffer.len().min(profile.max_response() - response.len());
            let read = match stream.read(&mut buffer[..available]) {
                Err(source)
                    if matches!(
                        source.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    deadline.enforce().map_err(interrupted)?;
                    continue;
                }
                result => result?,
            };
            if read > available {
                return Err(io::Error::other(
                    "TCP provider returned an oversized read count",
                ));
            }
            if read == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..read]);
        }
        Ok(())
    };
    if let Err(source) = exchange() {
        error = Some(Arc::new(source));
    }
    super::Banner {
        request_bytes_written: sent,
        application: profile.evaluate(&response),
        response: bytes::Bytes::from(response),
        error,
    }
}

fn interrupted(source: Interrupted) -> io::Error {
    let kind = match source {
        Interrupted::Cancelled(_) => io::ErrorKind::Interrupted,
        Interrupted::Exceeded(_) => io::ErrorKind::TimedOut,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, source)
}
