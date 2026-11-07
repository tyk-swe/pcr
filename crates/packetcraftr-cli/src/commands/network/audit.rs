// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::commands::security::{Bounds, invalid, publish, read};
use crate::commands::{CommandExit, Spec};
use crate::invocation::Invocation;
use crate::output::contract::{Command, Format};
use crate::{
    command_options::{Bounded, IdentificationPolicyArgs},
    errors::CliError,
    resources::Settings,
};
use clap::Args;
use std::{path::PathBuf, time::Duration};

#[derive(Debug, Args)]
struct Connection {
    /// Numeric IP:PORT; use `[IPv6]:PORT` for IPv6.
    endpoint: std::net::SocketAddr,
    /// Explicit TLS identity and SNI; never resolved to another target.
    #[arg(long)]
    server_name: Option<String>,
    /// PEM trust anchors replacing the bundled WebPKI roots.
    #[arg(long)]
    ca_file: Option<PathBuf>,
    #[arg(long, default_value_t = 5000)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 131072)]
    max_tls_write_bytes: usize,
    #[arg(long, default_value_t = 131072)]
    max_tls_read_bytes: usize,
    #[command(flatten)]
    policy: IdentificationPolicyArgs,
    #[command(flatten)]
    bounds: Bounds,
}
impl Bounded for Connection {
    fn max_duration(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}
impl Connection {
    fn request(
        &self,
        invocation: &Invocation,
    ) -> Result<packetcraftr::audit::TlsRequest, CliError> {
        self.bounds.core()?;
        let mut request = packetcraftr::audit::TlsRequest::new(self.endpoint);
        request.tls.server_name = self.server_name.clone();
        request.connection.timeout = self.max_duration();
        request.tls.limits.max_wire_bytes_sent = self.max_tls_write_bytes;
        request.tls.limits.max_wire_bytes_read = self.max_tls_read_bytes;
        request.tls.limits.handshake_timeout = self.max_duration();
        if let Some(path) = &self.ca_file {
            request.tls.trust = packetcraftr_netio::tls::TrustStore::from_pem(&read(
                invocation,
                path,
                1024 * 1024,
            )?)
            .map_err(invalid)?;
        }
        Ok(request)
    }
    fn resources(&self, s: &mut Settings<'_>) {
        self.bounds.resources(s);
        self.policy.budgets.resources(s);
        crate::resources::declare!(s, self, [ timeout_ms: Milliseconds @ Operation, max_tls_write_bytes: Bytes @ Operation, max_tls_read_bytes: Bytes @ ActiveState ]);
    }
}
#[derive(Debug, Args)]
pub(crate) struct AuditTls {
    #[command(flatten)]
    connection: Connection,
}
#[derive(Debug, Args)]
pub(crate) struct AuditHttp {
    #[command(flatten)]
    connection: Connection,
    /// Authenticate TLS before sending HTTP.
    #[arg(long)]
    tls: bool,
    /// Explicit HTTP Host header (does not alter the numeric target).
    #[arg(long)]
    host: Option<String>,
    #[arg(long, default_value = "/")]
    path: String,
    #[arg(long, default_value_t = 65535)]
    max_response_bytes: usize,
}
impl Spec for AuditTls {
    const PUBLISHED: &'static [PublishedType] = &[
        PublishedType {
            definition: "securitySuccess",
            command: "audit-tls",
            rust_types: &["crate::commands::security::output::Report"],
            events: &[],
            example: "examples/documents/output-audit-tls-complete.json",
        },
        PublishedType {
            definition: "securityStreamSuccess",
            command: "audit-tls",
            rust_types: &[
                "crate::commands::security::output::FindingRecord",
                "crate::commands::security::output::Report",
            ],
            events: &["complete", "finding"],
            example: "examples/documents/output-audit-tls-complete.json",
        },
    ];
    const FORMATS: &'static [Format] = crate::output::contract::TEXT_JSON_NDJSON;
    const CANCELLATION: bool = true;
    fn run_time(&self) -> Option<&dyn Bounded> {
        Some(&self.connection)
    }
    fn resources(&self, s: &mut Settings<'_>) {
        self.connection.resources(s);
    }
    fn run(self, i: &Invocation) -> Result<CommandExit, CliError> {
        let request = self.connection.request(i)?;
        let client = crate::system::client(
            i,
            packetcraftr_core::protocol::builtin::registry(),
            self.connection.policy.into_policy(),
            crate::system::Runtime::Workflow,
        );
        publish(
            i,
            Command::AuditTls,
            client.audit_tls(&request).map_err(CliError::classified)?,
            self.connection.bounds,
        )
    }
}
use crate::output::contract::PublishedType;

impl Spec for AuditHttp {
    const PUBLISHED: &'static [PublishedType] = &[
        PublishedType {
            definition: "securitySuccess",
            command: "audit-http",
            rust_types: &["crate::commands::security::output::Report"],
            events: &[],
            example: "examples/documents/output-audit-http-complete.json",
        },
        PublishedType {
            definition: "securityStreamSuccess",
            command: "audit-http",
            rust_types: &[
                "crate::commands::security::output::FindingRecord",
                "crate::commands::security::output::Report",
            ],
            events: &["complete", "finding"],
            example: "examples/documents/output-audit-http-complete.json",
        },
    ];
    const FORMATS: &'static [Format] = crate::output::contract::TEXT_JSON_NDJSON;
    const CANCELLATION: bool = true;
    fn run_time(&self) -> Option<&dyn Bounded> {
        Some(&self.connection)
    }
    fn resources(&self, s: &mut Settings<'_>) {
        self.connection.resources(s);
        crate::resources::declare!(s, self, [max_response_bytes: Bytes @ ActiveState]);
    }
    fn run(self, i: &Invocation) -> Result<CommandExit, CliError> {
        if !self.tls && (self.connection.server_name.is_some() || self.connection.ca_file.is_some())
        {
            return Err(invalid(
                "--server-name and --ca-file require --tls for HTTP audits",
            ));
        }
        let mut request = packetcraftr::audit::HttpRequest::new(self.connection.endpoint);
        let connection = self.connection.request(i)?;
        request.transport = if self.tls {
            packetcraftr::audit::HttpTransport::Tls(connection.tls)
        } else {
            connection
                .tls
                .validate(connection.connection.endpoint)
                .map_err(CliError::classified)?;
            packetcraftr::audit::HttpTransport::Plain
        };
        request.connection = connection.connection;
        request.host = self.host.unwrap_or_else(|| {
            self.connection
                .server_name
                .clone()
                .unwrap_or_else(|| self.connection.endpoint.to_string())
        });
        request.path = self.path;
        request.max_response_bytes = self.max_response_bytes;
        let client = crate::system::client(
            i,
            packetcraftr_core::protocol::builtin::registry(),
            self.connection.policy.into_policy(),
            crate::system::Runtime::Workflow,
        );
        publish(
            i,
            Command::AuditHttp,
            client.audit_http(&request).map_err(CliError::classified)?,
            self.connection.bounds,
        )
    }
}
