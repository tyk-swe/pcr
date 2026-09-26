// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod rendering;

use crate::output::contract::AggregateFormat;

use crate::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::rendering::emit_aggregate;
use crate::system::prepare_plan;

impl super::Spec for Args {
    type Format = crate::output::contract::AggregateFormat;
    const CANCELLATION: bool = false;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.policy.resources(settings);
    }

    fn run(
        self,
        format: Self::Format,
        _stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(arguments: Args, format: AggregateFormat) -> Result<(), CliError> {
    let Args { route, policy } = arguments;
    let plan = prepare_plan(route, policy.into_policy())?;
    let route = plan
        .client
        .plan(
            &plan.packet,
            plan.destination,
            &plan.route,
            &crate::invocation::passive_lookup(),
        )
        .map_err(CliError::classified)?;
    let result = output::plan::Report::from(route);
    match format {
        AggregateFormat::Text => rendering::render_text(&result.plan),
        AggregateFormat::Json => {
            emit_aggregate(output::contract::Command::Plan, result, Vec::new())
        }
    }
}
