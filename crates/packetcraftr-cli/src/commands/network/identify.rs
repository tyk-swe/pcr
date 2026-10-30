// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
mod publication;
mod rendering;

use crate::output::envelope::Published;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr::identify as library;
use packetcraftr_core::document::{service_exclusions, service_probes};

use crate::command_options::Bounded;
use crate::errors::CliError;
use crate::input::{InputKind, read_bounded_file};
use crate::output::{self, contract::Format};
use crate::system::{Runtime, client};

use self::arguments::Args;

impl crate::commands::Spec for Args {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;

    fn run_time(&self) -> Option<&dyn Bounded> {
        Some(self)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_duration_ms: Milliseconds @ Operation,
            operation_timeout_ms: Milliseconds @ Operation,
            intensity: Count @ Operation,
            max_attempts: Count @ Operation,
            max_write_bytes: Bytes @ Operation,
            max_read_bytes: Bytes @ ResultRetention,
            host_timeout_ms: Milliseconds @ Operation,
            host_max_attempts: Count @ Operation,
            host_max_write_bytes: Bytes @ Operation,
            host_max_read_bytes: Bytes @ ResultRetention,
            connection_timeout_ms: Milliseconds @ Operation,
            connection_max_attempts: Count @ Operation,
            connection_max_write_bytes: Bytes @ Operation,
            connection_max_read_bytes: Bytes @ ResultRetention,
            probe_timeout_ms: Milliseconds @ Operation,
            probe_max_attempts: Count @ Operation,
            probe_max_write_bytes: Bytes @ Operation,
            probe_max_read_bytes: Bytes @ ResultRetention,
        ]);
        self.tls.resources(settings);
        self.policy.budgets.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        let format = invocation.format;
        let stream = &invocation.output;
        let corpus = match &self.corpus {
            Some(path) => Arc::new(
                service_probes::parse(&read_bounded_file(
                    path,
                    service_probes::MAX_DOCUMENT_BYTES,
                    InputKind::ServiceDocument,
                )?)
                .map_err(CliError::classified)?,
            ),
            None => library::builtin_corpus().map_err(CliError::classified)?,
        };
        let exclusions = if self.ignore_exclusions {
            let mut exclusions =
                (*library::builtin_exclusions().map_err(CliError::classified)?).clone();
            exclusions.entries.clear();
            exclusions.name = "operator-no-exclusions".to_owned();
            exclusions.version = "1.0.0".to_owned();
            Arc::new(exclusions)
        } else if let Some(path) = &self.exclusions {
            Arc::new(
                service_exclusions::parse(&read_bounded_file(
                    path,
                    service_exclusions::MAX_EXCLUSIONS_BYTES,
                    InputKind::ServiceDocument,
                )?)
                .map_err(CliError::classified)?,
            )
        } else {
            library::builtin_exclusions().map_err(CliError::classified)?
        };
        invocation.check()?;
        let mut request = library::Request::new(
            self.endpoints
                .into_iter()
                .map(|address| library::Endpoint {
                    address,
                    transport: self.transport.into(),
                })
                .collect(),
            corpus,
            exclusions,
        );
        request.tls = self.tls.settings();
        request.intensity = self.intensity;
        request.parent_deadline = invocation.deadline.clone();
        request.limits = library::Limits {
            operation: library::Limit {
                attempts: self.max_attempts,
                write_bytes: self.max_write_bytes,
                read_bytes: self.max_read_bytes,
                timeout: Duration::from_millis(self.operation_timeout_ms),
            },
            host: library::Limit {
                attempts: self.host_max_attempts,
                write_bytes: self.host_max_write_bytes,
                read_bytes: self.host_max_read_bytes,
                timeout: Duration::from_millis(self.host_timeout_ms),
            },
            connection: library::Limit {
                attempts: self.connection_max_attempts,
                write_bytes: self.connection_max_write_bytes,
                read_bytes: self.connection_max_read_bytes,
                timeout: Duration::from_millis(self.connection_timeout_ms),
            },
            probe: library::Limit {
                attempts: self.probe_max_attempts,
                write_bytes: self.probe_max_write_bytes,
                read_bytes: self.probe_max_read_bytes,
                timeout: Duration::from_millis(self.probe_timeout_ms),
            },
        };
        let policy = self.policy.into_policy();
        request.validate(&policy).map_err(CliError::classified)?;
        if format == Format::Ndjson {
            publication::validate_ndjson(&request)?;
        }
        let report = client(
            invocation,
            packetcraftr_core::protocol::builtin::registry(),
            policy,
            Runtime::Workflow,
        )
        .identify(&request)
        .map_err(CliError::classified)?;
        invocation.check()?;
        invocation.check()?;
        let report = output::identify::Report::try_from(report).map_err(CliError::classified)?;
        match format {
            Format::Text => rendering::render_text(invocation, &report, stream.presentation())?,
            Format::Json => crate::rendering::emit_published(
                invocation,
                output::contract::Command::Identify,
                Published::new(report, Vec::new()),
            )?,
            Format::Ndjson => {
                for record in &report.records {
                    invocation.check()?;
                    invocation.check()?;
                    stream.emit_published(Published::new(record, Vec::new()))?;
                }
                stream.complete_published(Published::new(
                    output::identify::Complete::from(report),
                    Vec::new(),
                ))?;
            }
            unsupported => unsupported.unreachable(),
        }
        Ok(crate::commands::CommandExit::SUCCESS)
    }
}
