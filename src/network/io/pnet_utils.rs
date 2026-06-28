// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Result;
use pnet::transport::{
    transport_channel, TransportChannelType, TransportReceiver, TransportSender,
};
use std::io;

/// Open a transport channel with a user-friendly error message for permission issues.
pub fn open_transport_channel(
    buffer_size: usize,
    channel_type: TransportChannelType,
) -> Result<(TransportSender, TransportReceiver)> {
    transport_channel(buffer_size, channel_type).map_err(|e| {
        if e.kind() == io::ErrorKind::PermissionDenied {
            anyhow::anyhow!(
                "Operation not permitted: Packetcraft requires root privileges or CAP_NET_RAW capability to send raw packets."
            )
        } else {
            anyhow::Error::new(e).context("failed to open transport channel")
        }
    })
}
