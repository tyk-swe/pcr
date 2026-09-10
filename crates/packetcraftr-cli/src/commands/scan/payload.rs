// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::Path;

use bytes::Bytes;
use packetcraftr::scan::MAX_UDP_PAYLOAD_BYTES;
use packetcraftr_core::error::Kind;

use super::arguments::Transport;
use crate::errors::CliError;
use crate::input::{InputKind, read_bounded_file_allow_empty};

pub(super) fn read(
    transport: Transport,
    hex: Option<&str>,
    path: Option<&Path>,
) -> Result<Bytes, CliError> {
    if (hex.is_some() || path.is_some()) && !matches!(transport, Transport::Udp) {
        return Err(CliError::new(
            Kind::Cli,
            "--udp-payload-hex and --udp-payload-file require --transport udp",
        ));
    }
    if let Some(hex) = hex {
        // Bound both source text and decoded digits before parse_hex allocates
        // its compact representation. Allow customary separators and a prefix.
        let digits = hex
            .strip_prefix("0x")
            .or_else(|| hex.strip_prefix("0X"))
            .unwrap_or(hex);
        if hex.len() > MAX_UDP_PAYLOAD_BYTES * 4 + 2
            || digits
                .chars()
                .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
                .count()
                > MAX_UDP_PAYLOAD_BYTES * 2
        {
            return Err(CliError::new(
                Kind::Cli,
                "UDP payload exceeds 65507 bytes or its bounded hex representation",
            ));
        }
        return packetcraftr_core::protocol::raw::parse_hex(hex)
            .map_err(|source| CliError::new(Kind::Cli, source.to_string()));
    }
    if let Some(path) = path {
        return read_bounded_file_allow_empty(path, MAX_UDP_PAYLOAD_BYTES, InputKind::Frame)
            .map(Bytes::from);
    }
    Ok(Bytes::new())
}
