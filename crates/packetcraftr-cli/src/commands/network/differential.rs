// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
pub(in crate::commands) mod join;
mod rendering;
pub(in crate::commands) mod responder;

use packetcraftr::differential as lib;
use packetcraftr_core::error::Kind;

use crate::command_options::Bounded as _;
use crate::errors::CliError;
use crate::output;
use crate::output::contract::Format;
use crate::system::{Runtime, prepare_workflow};

use self::arguments::Args;

pub(super) fn parse_token(value: &str) -> Result<[u8; 16], CliError> {
    let bytes = value.as_bytes();
    if bytes.len() != 32 {
        return Err(CliError::new(
            Kind::Usage,
            "campaign token must be 32 hex characters",
        ));
    }
    let mut token = [0_u8; 16];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let text = std::str::from_utf8(pair)
            .map_err(|_| CliError::new(Kind::Usage, "campaign token must be 32 hex characters"))?;
        token[index] = u8::from_str_radix(text, 16)
            .map_err(|_| CliError::new(Kind::Usage, "campaign token must be 32 hex characters"))?;
    }
    Ok(token)
}

impl crate::commands::Spec for Args {
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.duration)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            repeats: Count @ Operation,
            payload_len: Bytes @ Operation,
        ]);
        self.timeout.resources(settings);
        self.duration.resources(settings);
        self.limits.resources(settings);
        self.policy.budgets.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        run(invocation, self).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

fn run(invocation: &crate::invocation::Invocation, arguments: Args) -> Result<(), CliError> {
    let token = match &arguments.token {
        Some(value) => parse_token(value)?,
        None if arguments.plan_only => lib::generate_token().map_err(CliError::classified)?,
        None => {
            return Err(CliError::new(
                Kind::Usage,
                "a live differential run requires --token from the plan-only run",
            ));
        }
    };
    let workflow = prepare_workflow(
        &arguments.route,
        arguments.policy.clone().into_policy(),
        arguments.timeout.timeout(),
        arguments.limits.clone().into_limits(),
    )?;
    let mut request = lib::Request::new(arguments.target, arguments.responder_port, token);
    request.source_port = arguments.source_port;
    request.spoof_source = arguments.spoof_source;
    request.repeats = arguments.repeats;
    request.payload_len = arguments.payload_len as usize;
    request.timeout = arguments.timeout.timeout();
    request.max_duration = arguments.duration.max_duration();
    request.route = workflow.route.clone();
    request.collection = workflow.collection.clone();
    request.plan_digest = arguments.plan_digest.clone();

    let client = workflow.client(invocation, Runtime::Workflow);
    let format = invocation.format;
    let stream = &invocation.output;

    if arguments.plan_only {
        if format == Format::Ndjson {
            return Err(CliError::new(
                Kind::Usage,
                "a plan-only differential run publishes one aggregate; use text or json output",
            ));
        }
        let summary = client
            .differential_plan(request)
            .map_err(CliError::classified)?;
        invocation.check()?;
        let plan =
            output::differential::PlanReport::from_summary(summary, &token, arguments.repeats);
        return match format {
            Format::Text => rendering::render_plan_text(invocation, &plan),
            Format::Json => crate::rendering::emit_published(
                invocation,
                output::contract::Command::Differential,
                output::envelope::Published::new(plan, Vec::new()),
            ),
            other => other.unreachable(),
        };
    }

    match format {
        Format::Ndjson => {
            let emit = crate::commands::execution::emitter(invocation, rendering::emit_event);
            let report = client
                .differential(request, emit)
                .map_err(CliError::classified)?;
            invocation.check()?;
            rendering::render_complete(report, stream)
        }
        Format::Text | Format::Json => {
            let collector = lib::Collector::default();
            let report = client
                .differential(request, collector.clone())
                .map_err(CliError::classified)?;
            let aggregate = collector.finish(report);
            invocation.check()?;
            let published =
                output::envelope::Published::<output::differential::Report>::try_from(aggregate)
                    .map_err(CliError::classified)?;
            match format {
                Format::Text => rendering::render_report_text(invocation, &published.result),
                Format::Json => crate::rendering::emit_published(
                    invocation,
                    output::contract::Command::Differential,
                    published,
                ),
                other => other.unreachable(),
            }
        }
        other => other.unreachable(),
    }
}
