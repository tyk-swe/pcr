// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core as core;
use packetcraftr_netio as net;

use super::{Client, Runtime, client, exchange, route};
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
    let first =
        route::authorize_expanded_destinations(request.template(), max_template_packets, &policy)?;
    let plan = route::options(&send.route.route)?;
    let destination = route::destination(send.route.destination, &first, &policy)?;
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
        client: client(registry, policy, Runtime::Client),
    })
}

pub(crate) struct Plan {
    pub(crate) client: Client,
    pub(crate) packet: core::packet::Packet,
    pub(crate) destination: Option<IpAddr>,
    pub(crate) route: packetcraftr::route::Options,
}

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
    let packet = read_recipe(recipe, &registry, core::packet::DEFAULT_MAX_LAYERS)?;
    policy.validate().map_err(CliError::classified)?;
    // This check intentionally precedes interface discovery and route lookup.
    policy
        .authorize_packet_destinations(&packet)
        .map_err(CliError::classified)?;
    let route = route::options(&route)?;
    let destination = route::destination(destination, &packet, &policy)?;
    Ok(Plan {
        client: client(registry, policy, Runtime::Client),
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
        collection: exchange::collection(timeout, queue_limits)?,
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

    const UNRESOLVABLE_HOST_BAD_INTERFACE: &[&str] = &[
        "--packet",
        "ipv4(dst=192.0.2.1)/udp(dport=9000)",
        "--destination",
        "host.invalid",
        "--allow-hostname-resolution",
        "--interface",
        "0",
    ];

    fn live_arguments(command: &str) -> (SendArgs, TemplateArgs) {
        live_arguments_with(command, &["--packet", INVALID_RECIPE])
    }

    fn live_arguments_with(command: &str, options: &[&str]) -> (SendArgs, TemplateArgs) {
        let cli = Cli::try_parse_from(
            ["packetcraftr", command]
                .into_iter()
                .chain(options.iter().copied()),
        )
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
        match read_recipe(recipe, &registry, core::packet::DEFAULT_MAX_LAYERS) {
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
    fn live_commands_reject_the_interface_before_resolving_the_destination() {
        for command in ["send", "exchange"] {
            let (send, template) = live_arguments_with(command, UNRESOLVABLE_HOST_BAD_INTERFACE);
            let message = match command {
                "send" => error_message(prepare_live(send, template, send_request())),
                _ => error_message(prepare_live(send, template, exchange_request())),
            };
            assert_eq!(message, "--interface index must be non-zero", "{command}");
        }
    }

    fn plan_error(options: &[&str]) -> CliError {
        let cli = Cli::try_parse_from(
            ["packetcraftr", "plan"]
                .into_iter()
                .chain(options.iter().copied()),
        )
        .expect("arguments parse");
        let CommandLine::Plan(arguments) = cli.command else {
            panic!("plan command");
        };
        match prepare_plan(arguments.route, arguments.policy.into_policy()) {
            Ok(_) => panic!("preparation must fail"),
            Err(error) => error,
        }
    }

    #[test]
    fn plan_rejects_the_interface_before_resolving_the_destination() {
        let error = plan_error(UNRESOLVABLE_HOST_BAD_INTERFACE);
        assert_eq!(error.message, "--interface index must be non-zero");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn plan_denies_the_destination_before_the_interface() {
        let error = plan_error(&[
            "--packet",
            "ipv4(dst=10.0.0.2)/udp(dport=9000)",
            "--allow-destination",
            "192.0.2.0/24",
            "--interface",
            "0",
        ]);
        assert_eq!(error.classification.code, "policy.destination_not_allowed");
        assert_eq!(error.exit_code(), 6);
    }

    #[test]
    fn live_axes_resolve_protocol_selectors_against_the_recipe() {
        let options = [
            "--packet",
            "vlan(vlan_id=7)/ipv4(dst=192.0.2.1)/udp(dport=9000)",
            "--axis",
            "UDP.dport=[1,2]",
            "--axis",
            "ipv4.ttl=[5]",
        ];
        for command in ["send", "exchange"] {
            let (send, template) = live_arguments_with(command, &options);
            let template = match command {
                "send" => prepare_live(send, template, send_request())
                    .map(|prepared| prepared.request.template),
                _ => prepare_live(send, template, exchange_request())
                    .map(|prepared| prepared.request.template),
            }
            .unwrap_or_else(|error| panic!("{command}: {}", error.message));
            let packets = template
                .expand(8)
                .expect("expansion fits")
                .collect::<Result<Vec<_>, _>>()
                .expect("axes apply");
            let fields = packets
                .iter()
                .map(|packet| {
                    (
                        packet.layer(1).and_then(|layer| layer.field("ttl")),
                        packet
                            .layer(2)
                            .and_then(|layer| layer.field("destination_port")),
                    )
                })
                .collect::<Vec<_>>();
            let field = |ttl: u64, port: u64| {
                (
                    Some(core::field::FieldValue::Unsigned(ttl)),
                    Some(core::field::FieldValue::Unsigned(port)),
                )
            };
            assert_eq!(fields, [field(5, 1), field(5, 2)], "{command}");
        }
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
