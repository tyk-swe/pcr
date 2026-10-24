// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::Arc;

use clap::Args;
use packetcraftr_core::{
    error::{Classification, Kind},
    layer::Id,
    protocol::builtin,
    registry::{Discriminator, Registry},
};

use crate::errors::CliError;

const MAX_BINDINGS: usize = 256;
const MAX_BINDING_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Default, Args)]
pub(crate) struct DecodeArgs {
    /// Decode a TCP port as TLS; repeatable shorthand for --decode-as tcp.port=PORT:tls.
    /// Changes per-frame decoding, not which TCP streams the TLS collector assembles.
    #[arg(long = "tls-port", value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub(crate) ports: Vec<u16>,
    /// Bind a port to a compatible codec, e.g. udp.port=5353:dns. TCP supports
    /// compatible built-in message codecs; see `reference protocols` for coverage.
    /// The same bindings select compatible child codecs during packet construction.
    /// Explicit bindings override the same built-in selector; conflicting
    /// declarations are rejected.
    #[arg(long = "decode-as", value_name = "TRANSPORT.port=PORT:PROTOCOL")]
    pub(crate) bindings: Vec<String>,
}

impl DecodeArgs {
    pub(crate) fn registry(&self) -> Result<Arc<Registry>, CliError> {
        if self.ports.len().saturating_add(self.bindings.len()) > MAX_BINDINGS
            || self
                .bindings
                .iter()
                .map(String::len)
                .fold(0_usize, usize::saturating_add)
                > MAX_BINDING_BYTES
        {
            return Err(error(
                "decode-as input exceeds 256 declarations or 65536 bytes",
            ));
        }
        let default = builtin::registry();
        if self.ports.is_empty() && self.bindings.is_empty() {
            return Ok(default);
        }
        let mut bindings = BTreeMap::new();
        for &port in &self.ports {
            insert(&mut bindings, "tcp", port, Id::new("tls"))?;
        }
        for source in &self.bindings {
            let invalid = || {
                error(format!(
                    "invalid decode-as {source:?}; use udp.port=5353:dns or tcp.port=4433:tls"
                ))
            };
            let (selector, target) = source.split_once('=').ok_or_else(invalid)?;
            let parent = match selector.trim().to_ascii_lowercase().as_str() {
                "tcp.port" => "tcp",
                "udp.port" => "udp",
                _ => return Err(invalid()),
            };
            let (port, child) = target.split_once(':').ok_or_else(invalid)?;
            let port = port.trim();
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid());
            }
            let port = port.parse::<u16>().map_err(|_| invalid())?;
            let child = default
                .protocol_named(child)
                .ok_or_else(|| error(format!("unknown decode-as protocol {child:?}")))?;
            if !packetcraftr_core::protocol::BuiltinProtocol::from_id(child).is_some_and(
                |protocol| {
                    let parent = packetcraftr_core::protocol::BuiltinProtocol::from_name(parent)
                        .expect("transport");
                    protocol.supports_transport(parent)
                },
            ) {
                return Err(error(format!(
                    "{child} cannot be decoded directly under {parent}"
                )));
            }
            insert(&mut bindings, parent, port, child)?;
        }
        builtin::registry_with(|builder| {
            for ((parent, port), child) in bindings {
                // The builder rejects changing an existing child's priority.
                if default.child_for(parent, Discriminator(u64::from(port))) != Some(child) {
                    builder.bind(parent, u64::from(port), child, i32::MAX)?;
                }
            }
            Ok(())
        })
        .map(Arc::new)
        .map_err(|source| {
            CliError::from_classification(
                Classification::new(
                    "cli.decode_as",
                    Kind::Usage,
                    Some("declare one compatible protocol per TCP or UDP port"),
                ),
                source.to_string(),
                packetcraftr_core::error::source_chain(&source),
            )
        })
    }
}

fn insert(
    bindings: &mut BTreeMap<(&'static str, u16), Id>,
    parent: &'static str,
    port: u16,
    child: Id,
) -> Result<(), CliError> {
    if port == 0 {
        return Err(error("decode-as ports must be within 1..=65535"));
    }
    if let Some(previous) = bindings.insert((parent, port), child)
        && previous != child
    {
        return Err(error(format!(
            "conflicting decode-as declarations for {parent}.port={port}: {previous} and {child}"
        )));
    }
    Ok(())
}

fn error(message: impl Into<String>) -> CliError {
    CliError::from_classification(
        Classification::new(
            "cli.decode_as",
            Kind::Usage,
            Some("declare one compatible protocol per TCP or UDP port"),
        ),
        message,
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_as_ports_are_unsigned_decimal_with_whitespace() {
        for port in ["+53", "-53", "", "0", "65536", "٥٣"] {
            let args = DecodeArgs {
                ports: vec![],
                bindings: vec![format!("udp.port={port}:dns")],
            };
            assert!(args.registry().is_err(), "{port}");
        }
        let args = DecodeArgs {
            ports: vec![],
            bindings: vec![" udp.port = 0053 :dns".into()],
        };
        assert!(args.registry().is_ok());
    }
}
