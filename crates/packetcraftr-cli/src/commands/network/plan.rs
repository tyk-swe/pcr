// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{
    DestinationAllowlistArgs, HostnameResolutionArgs, PublicDestinationArgs, RouteArgs,
};
use crate::errors::CliError;
use crate::output::{self, contract::Format};
use crate::rendering::{emit_aggregate, optional_display, write_stdout_line};
use crate::resources::Settings;
use crate::system::prepare_plan;

pub(crate) const AFTER_LONG_HELP: &str = r"Route planning is passive: it performs no packet transmission.

Example:
  packetcraftr network plan --packet 'ipv4(dst=192.0.2.53)/udp(dport=53)'";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) route: RouteArgs,
    #[command(flatten)]
    pub(crate) policy: PolicyArgs,
}

/// `plan`: passive, so it has no budget to spend.
#[derive(Clone, Debug, clap::Args)]
pub(crate) struct PolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    hostname_resolution: HostnameResolutionArgs,
    #[command(flatten)]
    destination_allowlist: DestinationAllowlistArgs,
}

impl PolicyArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        self.hostname_resolution.resources(settings);
    }

    pub(crate) fn into_policy(self) -> packetcraftr::policy::Policy {
        let mut policy = packetcraftr::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        self.destination_allowlist.apply_to(&mut policy);
        policy
    }
}

impl crate::commands::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
    ];
    const CANCELLATION: bool = false;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        self.policy.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        let format = invocation.format;
        let stream = &invocation.output;
        run(invocation, self, format, stream.presentation())
            .map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
    format: Format,
    presentation: crate::invocation::Presentation,
) -> Result<(), CliError> {
    let Args { route, policy } = arguments;
    let plan = prepare_plan(invocation, route, policy.into_policy())?;
    let route = plan
        .client
        .plan(
            &plan.packet,
            plan.destination,
            &plan.route,
            &invocation.passive_lookup(),
        )
        .map_err(CliError::classified)?;
    let result = output::plan::Report::from(route);
    match format {
        Format::Text => {
            render_text(invocation, &result.plan)?;
            presentation.details(invocation, "Route decision", &result.plan)
        }
        Format::Json => emit_aggregate(
            invocation,
            output::contract::Command::Plan,
            result,
            Vec::new(),
        ),
        other => other.unreachable(),
    }
}

fn render_text(
    invocation: &crate::invocation::Invocation,
    route: &output::network::Plan,
) -> Result<(), CliError> {
    write_stdout_line(
        invocation,
        format_args!(
            "interface={} index={} mode={} mtu={} link_type={}",
            route.decision.interface.name,
            route.decision.interface.index,
            route.mode,
            route.decision.mtu,
            route.decision.link_type
        ),
    )?;
    write_stdout_line(
        invocation,
        format_args!(
            "lookup_destination={} final_destination={} source={} next_hop={} destination_mac={}",
            optional_display(route.lookup_destination),
            optional_display(route.final_destination),
            optional_display(route.packet_source),
            optional_display(route.decision.next_hop),
            route
                .destination_mac
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unresolved".to_owned())
        ),
    )
}
