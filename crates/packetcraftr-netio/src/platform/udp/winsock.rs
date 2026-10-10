// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{io, net::UdpSocket};

pub(crate) fn receive(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<(usize, bool)> {
    match socket.recv(buffer) {
        Ok(count) => Ok((count, count == buffer.len())),
        // Winsock recv fills the caller's buffer and discards the remainder
        // of an oversized unreliable datagram before reporting WSAEMSGSIZE.
        // https://learn.microsoft.com/windows/win32/api/winsock/nf-winsock-recv
        Err(source) if source.raw_os_error() == Some(10040) => Ok((buffer.len(), true)),
        Err(source) => Err(source),
    }
}
