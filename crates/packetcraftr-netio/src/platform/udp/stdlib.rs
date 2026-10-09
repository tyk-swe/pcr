// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{io, net::UdpSocket};

pub(crate) fn receive(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<(usize, bool)> {
    socket
        .recv(buffer)
        .map(|count| (count, count == buffer.len()))
}
