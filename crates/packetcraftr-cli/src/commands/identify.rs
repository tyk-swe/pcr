// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod publication;
mod rendering;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr::identify as library;
use packetcraftr_core::document::{service_exclusions, service_probes};

use crate::command_options::Bounded;
use crate::errors::CliError;
use crate::input::{InputKind, read_bounded_file};
use crate::output::{self, contract::Format};
use crate::rendering::StreamEncoder;
use crate::system::{Runtime, client};

use self::arguments::Args;

impl super::Spec for Args {
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
        self.policy.resources(settings);
    }

    fn run(self, format: Format, stream: &StreamEncoder) -> Result<super::CommandExit, CliError> {
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
        crate::invocation::check()?;
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
        request.intensity = self.intensity;
        request.parent_deadline = crate::invocation::deadline();
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
            packetcraftr_core::protocol::builtin::registry(),
            policy,
            Runtime::Workflow,
        )
        .identify(&request)
        .map_err(CliError::classified)?;
        crate::cancellation::check()?;
        crate::invocation::check()?;
        let report = output::identify::Report::try_from(report).map_err(CliError::classified)?;
        match format {
            Format::Text => rendering::render_text(&report)?,
            Format::Json => crate::rendering::emit_aggregate(
                output::contract::Command::Identify,
                report,
                Vec::new(),
            )?,
            Format::Ndjson => {
                for record in &report.records {
                    crate::cancellation::check()?;
                    crate::invocation::check()?;
                    stream.emit_data(record, Vec::new())?;
                }
                stream.complete(output::identify::Complete::from(report), Vec::new())?;
            }
            unsupported => unsupported.unreachable(),
        }
        Ok(super::CommandExit::SUCCESS)
    }
}
