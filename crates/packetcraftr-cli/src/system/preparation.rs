// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one pre-discovery preparation every live command runs: each check that
//! can refuse the operation runs before hostname work, in one order per
//! command family, policy is validated once, and the client is composed last.
//! The client resolves the interface selector after it admits each operation.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core as core;
use packetcraftr_netio as net;

use super::{Client, Runtime, client, exchange, route};
use crate::command_options::{RouteArgs, RouteSelectionArgs, SendArgs, TemplateArgs};
use crate::errors::CliError;
use crate::input::read_recipe;

/// A live command's request, as the shared preparation sees it. A command
/// builds it before the recipe is read, with a placeholder template the
/// preparation replaces.
pub(crate) trait LiveRequest {
    /// Checks the command's options before the recipe is read.
    fn validate(&self) -> Result<(), CliError>;
    /// Installs the packet set read from the recipe.
    fn set_template(&mut self, template: core::template::Template);
    fn template(&self) -> &core::template::Template;
    /// The packet count the count-only operation budget admits.
    fn budget_count(&self) -> Result<u64, CliError>;
    /// Installs the resolved per-packet send options.
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

    /// Counts the complete expansion times repetition.
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

    /// Counts one pass over the expansion.
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

/// The template a command's request carries until the recipe is read.
pub(crate) fn placeholder() -> core::template::Template {
    core::template::Template::new(core::packet::Packet::new())
}

/// The command's request, holding the packet set and resolved send options,
/// and a client bound to the validated policy.
pub(crate) struct Prepared<R> {
    pub(crate) request: R,
    pub(crate) client: Client,
}

/// Validates `request`, reads the recipe into its template, validates policy,
/// authorizes the budget count and every expanded destination, then resolves
/// the first packet's destination and composes the client.
pub(crate) fn prepare_live<R: LiveRequest>(
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
        core::layout::DEFAULT_MAX_LAYERS,
    )?;
    request.set_template(axes.into_template(packet));
    let policy = send.policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let count = request.budget_count()?;
    policy
        .authorize(packetcraftr::policy::Operation::Wire(
            packetcraftr::policy::WireLimits::new(count, 0),
        ))
        .map_err(CliError::classified)?;
    let first =
        route::authorize_expanded_destinations(request.template(), max_template_packets, &policy)?;
    let destination = route::destination(send.route.destination, &first, &policy)?;
    request.set_send(packetcraftr::send::Options {
        destination,
        plan: route::options(&send.route.route)?,
        build: core::build::Options {
            mode: send.mode.into(),
            ..core::build::Options::default()
        },
        allow_permissive_live: send.allow_permissive_live,
    });
    Ok(Prepared {
        request,
        client: client(registry, policy, Runtime::Client),
    })
}

/// One recipe packet with its resolved destination and requested route, and
/// the client that plans it.
pub(crate) struct Plan {
    pub(crate) client: Client,
    pub(crate) packet: core::packet::Packet,
    pub(crate) destination: Option<IpAddr>,
    pub(crate) route: packetcraftr::route::Options,
}

/// Reads one recipe, validates `policy`, and authorizes the packet's declared
/// destinations before hostname work, then composes the client.
pub(crate) fn prepare_plan(
    arguments: RouteArgs,
    policy: packetcraftr::policy::Policy,
) -> Result<Plan, CliError> {
    let RouteArgs {
        recipe,
        destination,
        route,
    } = arguments;
    let registry = core::protocol::builtin::registry();
    let packet = read_recipe(recipe, &registry, core::layout::DEFAULT_MAX_LAYERS)?;
    policy.validate().map_err(CliError::classified)?;
    // This check intentionally precedes interface discovery and route lookup.
    policy
        .authorize_packet_destinations(&packet)
        .map_err(CliError::classified)?;
    let destination = route::destination(destination, &packet, &policy)?;
    let route = route::options(&route)?;
    Ok(Plan {
        client: client(registry, policy, Runtime::Client),
        packet,
        destination,
        route,
    })
}

/// A probe workflow's validated policy, with the route and capture bounds
/// every exchange of the workflow runs under.
pub(crate) struct Workflow {
    policy: Arc<packetcraftr::policy::Policy>,
    /// The route every exchange of the workflow plans on.
    pub(crate) route: packetcraftr::route::Options,
    /// The capture bounds every exchange of the workflow collects under.
    pub(crate) collection: packetcraftr::exchange::Collection,
}

impl Workflow {
    /// Composes the client the workflow runs on, publishing its events on
    /// `runtime`.
    pub(crate) fn client(&self, runtime: Runtime) -> Client {
        client(
            core::protocol::builtin::registry(),
            Arc::clone(&self.policy),
            runtime,
        )
    }
}

/// Validates the policy, the interface selector, and the collection bounds,
/// in that order. The client resolves the selector only after it admits each
/// exchange, so a denied target never enumerates interfaces.
///
/// `max_template_packets` is how many packets one exchange may hold: one query
/// for `dns`, one probe for `scan` and each fuzz case, one attempt per hop for
/// `traceroute`.
pub(crate) fn prepare_workflow(
    route: &RouteSelectionArgs,
    policy: packetcraftr::policy::Policy,
    timeout: Duration,
    max_template_packets: usize,
    queue_limits: net::capture::Limits,
) -> Result<Workflow, CliError> {
    policy.validate().map_err(CliError::classified)?;
    let route = route::options(route)?;
    Ok(Workflow {
        policy: Arc::new(policy),
        route,
        collection: exchange::collection(timeout, max_template_packets, queue_limits)?,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser as _;

    use super::*;
    use crate::cli::Cli;
    use crate::commands::CommandLine;

    const INVALID_RECIPE: &str = "ipv4(dst=192.0.2.1";

    fn live_arguments(command: &str) -> (SendArgs, TemplateArgs) {
        let cli = Cli::try_parse_from(["packetcraftr", command, "--packet", INVALID_RECIPE])
            .expect("arguments parse");
        match cli.command {
            CommandLine::Send(arguments) => (arguments.send, arguments.template),
            CommandLine::Exchange(arguments) => (arguments.send, arguments.template),
            _ => panic!("live command"),
        }
    }

    fn send_request() -> packetcraftr::send::Request {
        packetcraftr::send::Request::new(placeholder(), packetcraftr::send::Options::default())
    }

    fn exchange_request() -> packetcraftr::exchange::Request {
        packetcraftr::exchange::Request::new(placeholder(), packetcraftr::send::Options::default())
    }

    fn error_message<O>(result: Result<Prepared<O>, CliError>) -> String {
        match result {
            Ok(_) => panic!("preparation must fail"),
            Err(error) => error.message,
        }
    }

    fn recipe_error() -> String {
        let recipe = crate::command_options::RecipeArgs {
            packet: Some(INVALID_RECIPE.to_owned()),
            packet_file: None,
            payload_file: None,
        };
        let registry = core::protocol::builtin::registry();
        match read_recipe(recipe, &registry, core::layout::DEFAULT_MAX_LAYERS) {
            Ok(_) => panic!("recipe must be invalid"),
            Err(error) => error.message,
        }
    }

    #[test]
    fn send_rejects_invalid_options_before_the_recipe() {
        let (send, template) = live_arguments("send");
        let request = packetcraftr::send::Request {
            repeat: 0,
            ..send_request()
        };
        let message = error_message(prepare_live(send, template, request));
        assert!(message.contains("repeat"), "{message}");
        assert_ne!(message, recipe_error());
    }

    #[test]
    fn exchange_rejects_invalid_options_before_the_recipe() {
        let (send, template) = live_arguments("exchange");
        let request = packetcraftr::exchange::Request {
            timeout: Duration::MAX,
            ..exchange_request()
        };
        let message = error_message(prepare_live(send, template, request));
        assert!(message.contains("timeout"), "{message}");
        assert_ne!(message, recipe_error());
    }

    #[test]
    fn valid_options_reach_the_invalid_recipe() {
        let (send, template) = live_arguments("send");
        assert_eq!(
            error_message(prepare_live(send, template, send_request())),
            recipe_error()
        );
        let (send, template) = live_arguments("exchange");
        assert_eq!(
            error_message(prepare_live(send, template, exchange_request())),
            recipe_error()
        );
    }
}
