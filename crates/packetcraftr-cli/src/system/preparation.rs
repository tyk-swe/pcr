// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core as core;
use packetcraftr_netio as net;

use super::{Client, Runtime, client, route};
use crate::command_options::{RouteArgs, RouteSelectionArgs, SendArgs, TemplateArgs};
use crate::errors::CliError;
use crate::input::read_recipe;

pub(crate) trait LiveRequest {
    fn validate(&self) -> Result<(), CliError>;
    fn set_template(&mut self, template: core::template::Template);
    fn template(&self) -> &core::template::Template;
    fn budget_count(&self) -> Result<u64, CliError>;
    fn set_send(&mut self, send: packetcraftr::send::Options);
}

impl LiveRequest for packetcraftr::send::Request {
    fn validate(&self) -> Result<(), CliError> {
        Self::validate(self).map_err(CliError::classified)
    }

    fn set_template(&mut self, template: core::template::Template) {
        self.template = template;
    }

    fn template(&self) -> &core::template::Template {
        &self.template
    }

    fn budget_count(&self) -> Result<u64, CliError> {
        self.packet_count().map_err(CliError::classified)
    }

    fn set_send(&mut self, send: packetcraftr::send::Options) {
        self.send = send;
    }
}

impl LiveRequest for packetcraftr::exchange::Request {
    fn validate(&self) -> Result<(), CliError> {
        Self::validate(self).map_err(CliError::classified)
    }

    fn set_template(&mut self, template: core::template::Template) {
        self.template = template;
    }

    fn template(&self) -> &core::template::Template {
        &self.template
    }

    fn budget_count(&self) -> Result<u64, CliError> {
        let count = self
            .template
            .expansion_len()
            .map_err(CliError::classified)?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    fn set_send(&mut self, send: packetcraftr::send::Options) {
        self.send = send;
    }
}

pub(crate) fn placeholder() -> core::template::Template {
    core::template::Template::new(core::packet::Packet::new())
}

pub(crate) struct Prepared<R> {
    pub(crate) request: R,
    pub(crate) client: Client,
}

pub(crate) fn prepare_live<R: LiveRequest>(
    invocation: &crate::invocation::Invocation,
    send: SendArgs,
    template: TemplateArgs,
    mut request: R,
) -> Result<Prepared<R>, CliError> {
    let max_template_packets = template.max_template_packets;
    let axes = template.parse()?;
    // Options fail before recipe parsing can trigger hostname work.
    request.validate()?;
    let registry = core::protocol::builtin::registry();
    let packet = read_recipe(
        send.route.recipe,
        &registry,
        core::packet::DEFAULT_MAX_LAYERS,
    )?;
    request.set_template(axes.into_template(packet, &registry)?);
    let policy = send.policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let count = request.budget_count()?;
    policy
        .authorize(packetcraftr::policy::Operation::Wire(
            packetcraftr::policy::WireLimits::new(count, 0),
        ))
        .map_err(CliError::classified)?;
    let first = route::authorize_expanded_destinations(
        invocation,
        request.template(),
        max_template_packets,
        &policy,
    )?;
    let plan = route::options(&send.route.route)?;
    let destination = route::destination(invocation, send.route.destination, &first, &policy)?;
    request.set_send(packetcraftr::send::Options {
        destination,
        plan,
        build: core::build::Options {
            mode: send.mode.into(),
            ..core::build::Options::default()
        },
        allow_permissive_live: send.allow_permissive_live,
    });
    Ok(Prepared {
        request,
        client: client(invocation, registry, policy, Runtime::Client),
    })
}

pub(crate) struct Plan {
    pub(crate) client: Client,
    pub(crate) packet: core::packet::Packet,
    pub(crate) destination: Option<IpAddr>,
    pub(crate) route: packetcraftr::route::Options,
}

pub(crate) fn prepare_plan(
    invocation: &crate::invocation::Invocation,
    arguments: RouteArgs,
    policy: packetcraftr::policy::Policy,
) -> Result<Plan, CliError> {
    let RouteArgs {
        recipe,
        destination,
        route,
    } = arguments;
    let registry = core::protocol::builtin::registry();
    let packet = read_recipe(recipe, &registry, core::packet::DEFAULT_MAX_LAYERS)?;
    policy.validate().map_err(CliError::classified)?;
    // This check intentionally precedes interface discovery and route lookup.
    policy
        .authorize_packet_destinations(&packet)
        .map_err(CliError::classified)?;
    let route = route::options(&route)?;
    let destination = route::destination(invocation, destination, &packet, &policy)?;
    Ok(Plan {
        client: client(invocation, registry, policy, Runtime::Client),
        packet,
        destination,
        route,
    })
}

pub(crate) struct Workflow {
    policy: Arc<packetcraftr::policy::Policy>,
    pub(crate) route: packetcraftr::route::Options,
    pub(crate) collection: packetcraftr::exchange::Collection,
}

impl Workflow {
    pub(crate) fn client(
        &self,
        invocation: &crate::invocation::Invocation,
        runtime: Runtime,
    ) -> Client {
        client(
            invocation,
            core::protocol::builtin::registry(),
            Arc::clone(&self.policy),
            runtime,
        )
    }
}

pub(crate) fn collection(
    timeout: Duration,
    limits: net::capture::Limits,
) -> Result<packetcraftr::exchange::Collection, CliError> {
    let mut collection = packetcraftr::exchange::Collection {
        max_unmatched_frames: limits.max_frames,
        max_responses: limits.max_frames,
        capture: limits,
        ..packetcraftr::exchange::Collection::default()
    };
    collection.decode.limits.max_packet_size = limits.snap_length;
    packetcraftr::exchange::Request {
        // A zero window is left to the calling workflow's own limit error.
        timeout: timeout.max(Duration::from_nanos(1)),
        collection: collection.clone(),
        ..packetcraftr::exchange::Request::new(
            placeholder(),
            packetcraftr::send::Options::default(),
        )
    }
    .validate()
    .map_err(CliError::classified)?;
    Ok(collection)
}

/// Validates the policy, the interface selector, and the collection bounds,
/// in that order. The client resolves the selector only after it admits each
/// exchange, so a denied target never enumerates interfaces.
pub(crate) fn prepare_workflow(
    route: &RouteSelectionArgs,
    policy: packetcraftr::policy::Policy,
    timeout: Duration,
    queue_limits: net::capture::Limits,
) -> Result<Workflow, CliError> {
    policy.validate().map_err(CliError::classified)?;
    let route = route::options(route)?;
    Ok(Workflow {
        policy: Arc::new(policy),
        route,
        collection: collection(timeout, queue_limits)?,
    })
}
