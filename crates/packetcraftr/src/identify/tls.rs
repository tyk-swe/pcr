// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_netio::tls;

use super::{Error, MAX_OPERATION_BYTES};

/// Aggregate encrypted traffic and retained certificate allowances. Application
/// bytes remain charged separately to the ordinary identification limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsBudget {
    pub write_bytes: u64,
    pub read_bytes: u64,
    pub certificate_bytes: u64,
}

/// Explicit TLS wrapping for every selected TCP endpoint. A declared server
/// name selects SNI without resolution or certificate authentication. Numeric
/// targets without a declared name send no SNI.
#[derive(Clone, Debug)]
pub struct TlsSettings {
    pub server_name: Option<String>,
    pub connection: tls::Limits,
    pub operation: TlsBudget,
    pub host: TlsBudget,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            server_name: None,
            connection: tls::Limits::default(),
            operation: TlsBudget {
                write_bytes: 8 * 1024 * 1024,
                read_bytes: 8 * 1024 * 1024,
                certificate_bytes: 1024 * 1024,
            },
            host: TlsBudget {
                write_bytes: 1024 * 1024,
                read_bytes: 1024 * 1024,
                certificate_bytes: 128 * 1024,
            },
        }
    }
}

impl TlsSettings {
    pub(super) fn validate(&self) -> Result<(), Error> {
        self.connection
            .validate()
            .map_err(|source| Error::request(source.to_string()))?;
        if let Some(name) = &self.server_name {
            tls::ServerName::Declared(name.clone())
                .validate()
                .map_err(|source| Error::request(source.to_string()))?;
        }
        for budget in [self.operation, self.host] {
            if budget.write_bytes == 0
                || budget.read_bytes == 0
                || budget.write_bytes > MAX_OPERATION_BYTES
                || budget.read_bytes > MAX_OPERATION_BYTES
                || budget.certificate_bytes > MAX_OPERATION_BYTES
            {
                return Err(Error::request(
                    "TLS aggregate budgets exceed finite identification bounds",
                ));
            }
        }
        Ok(())
    }
}
