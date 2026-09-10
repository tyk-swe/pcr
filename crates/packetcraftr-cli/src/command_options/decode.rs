// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit, compatible port bindings for offline decoding.

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
    /// tls/raw; UDP supports dns/vxlan/geneve/raw. Explicit bindings override
    /// the same built-in selector; conflicting declarations are rejected.
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
            let port = port.trim().parse::<u16>().map_err(|_| invalid())?;
            let child = default
                .protocol_named(child)
                .ok_or_else(|| error(format!("unknown decode-as protocol {child:?}")))?;
            if !matches!(
                (parent, child.as_str()),
                ("tcp", "tls" | "raw") | ("udp", "dns" | "vxlan" | "geneve" | "raw")
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
                // Identical default mappings already have the desired result.
                if default.child_for(parent, Discriminator(u64::from(port))) != Some(child) {
                    builder.bind(parent, u64::from(port), child, i32::MAX)?;
                }
            }
            Ok(())
        })
        .map(Arc::new)
        .map_err(|source| error(source.to_string()))
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
            Kind::Cli,
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
    fn identical_declarations_are_idempotent_but_input_retention_is_bounded() {
        let args = DecodeArgs {
            ports: vec![4433, 4433],
            bindings: vec![
                "tcp.port=4433:tls".to_owned(),
                "tcp.port=443:tls".to_owned(),
            ],
        };
        let registry = args.registry().unwrap();
        assert_eq!(
            registry.child_for("tcp", Discriminator(4433)),
            Some(Id::new("tls"))
        );
        assert_eq!(
            registry.child_for("tcp", Discriminator(443)),
            Some(Id::new("tls"))
        );
        let too_many = DecodeArgs {
            ports: vec![443; MAX_BINDINGS + 1],
            ..DecodeArgs::default()
        };
        assert_eq!(
            too_many.registry().unwrap_err().classification.code,
            "cli.decode_as"
        );
        let too_long = DecodeArgs {
            bindings: vec!["x".repeat(MAX_BINDING_BYTES + 1)],
            ..DecodeArgs::default()
        };
        assert_eq!(
            too_long.registry().unwrap_err().classification.code,
            "cli.decode_as"
        );
    }
}
