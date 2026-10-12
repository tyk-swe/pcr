// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr::identify::{TlsBudget, TlsSettings};

#[derive(Debug, clap::Args)]
#[group(id = "IdentificationTls")]
pub(crate) struct Args {
    /// Explicitly run the reviewed TCP probes inside TLS; certificates are unauthenticated observations.
    #[arg(long)]
    pub(crate) tls: bool,
    /// Operator-declared DNS name sent as SNI; never resolved or authenticated.
    #[arg(long, requires = "tls", value_name = "NAME")]
    server_name: Option<String>,
    /// Maximum encrypted bytes written per connection, including the handshake.
    #[arg(long, requires = "tls", default_value_t = 131_072)]
    pub(crate) tls_max_wire_write_bytes: usize,
    /// Maximum encrypted bytes read per connection, including the handshake.
    #[arg(long, requires = "tls", default_value_t = 131_072)]
    pub(crate) tls_max_wire_read_bytes: usize,
    /// Maximum TLS transport I/O steps per connection.
    #[arg(long, requires = "tls", default_value_t = 64)]
    pub(crate) tls_max_steps: usize,
    /// Maximum handshake duration within the connection and enclosing deadlines.
    #[arg(long, requires = "tls", default_value_t = 1_000)]
    pub(crate) tls_handshake_timeout_ms: u64,
    /// Maximum presented certificate DER bytes retained per connection.
    #[arg(long, requires = "tls", default_value_t = 65_536)]
    pub(crate) tls_max_certificate_bytes: usize,
    /// Maximum presented certificates retained per connection.
    #[arg(long, requires = "tls", default_value_t = 8)]
    pub(crate) tls_max_certificates: usize,
    /// Maximum encrypted bytes in each direction across the operation.
    #[arg(long, requires = "tls", default_value_t = 8 * 1024 * 1024)]
    pub(crate) tls_operation_max_wire_bytes: u64,
    /// Maximum encrypted bytes in each direction for one numeric host.
    #[arg(long, requires = "tls", default_value_t = 1024 * 1024)]
    pub(crate) tls_host_max_wire_bytes: u64,
    /// Maximum certificate DER bytes retained across the operation.
    #[arg(long, requires = "tls", default_value_t = 1024 * 1024)]
    pub(crate) tls_operation_max_certificate_bytes: u64,
    /// Maximum certificate DER bytes retained for one numeric host.
    #[arg(long, requires = "tls", default_value_t = 128 * 1024)]
    pub(crate) tls_host_max_certificate_bytes: u64,
}

impl Args {
    pub(crate) fn settings(self) -> Option<TlsSettings> {
        self.tls.then(|| TlsSettings {
            server_name: self.server_name,
            connection: packetcraftr_netio::tls::Limits {
                max_wire_bytes_sent: self.tls_max_wire_write_bytes,
                max_wire_bytes_read: self.tls_max_wire_read_bytes,
                max_steps: self.tls_max_steps,
                handshake_timeout: Duration::from_millis(self.tls_handshake_timeout_ms),
                max_certificates: self.tls_max_certificates,
                max_certificate_bytes: self.tls_max_certificate_bytes,
            },
            operation: TlsBudget {
                write_bytes: self.tls_operation_max_wire_bytes,
                read_bytes: self.tls_operation_max_wire_bytes,
                certificate_bytes: self.tls_operation_max_certificate_bytes,
            },
            host: TlsBudget {
                write_bytes: self.tls_host_max_wire_bytes,
                read_bytes: self.tls_host_max_wire_bytes,
                certificate_bytes: self.tls_host_max_certificate_bytes,
            },
        })
    }

    pub(crate) fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        if self.tls {
            crate::resources::declare!(settings, self, [
                tls_max_wire_write_bytes: Bytes @ Operation,
                tls_max_wire_read_bytes: Bytes @ Operation,
                tls_max_steps: Count @ Operation,
                tls_handshake_timeout_ms: Milliseconds @ Operation,
                tls_max_certificate_bytes: Bytes @ ResultRetention,
                tls_max_certificates: Count @ ResultRetention,
                tls_operation_max_wire_bytes: Bytes @ Operation,
                tls_host_max_wire_bytes: Bytes @ Operation,
                tls_operation_max_certificate_bytes: Bytes @ ResultRetention,
                tls_host_max_certificate_bytes: Bytes @ ResultRetention,
            ]);
        }
    }
}
