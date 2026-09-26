// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The pre-discovery preparation `send` and `exchange` share: every check
//! that can refuse the operation runs before hostname work, in one order, and
//! policy is validated once. The client resolves the interface selector after
//! it admits the operation.

use std::sync::Arc;

use packetcraftr_core as core;

use crate::command_options::{SendArgs, TemplateArgs};
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::system::{Client, client, prepare_expanded_route};

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
/// authorizes the budget count and every expanded destination, then prepares
/// the first packet's route.
pub(crate) fn prepare<R: LiveRequest>(
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
    let routed = prepare_expanded_route(
        request.template(),
        max_template_packets,
        send.route.destination,
        send.route.route,
        policy,
    )?;
    request.set_send(packetcraftr::send::Options {
        destination: routed.destination,
        plan: routed.options,
        build: core::build::Options {
            mode: send.mode.into(),
            ..core::build::Options::default()
        },
        allow_permissive_live: send.allow_permissive_live,
    });
    Ok(Prepared {
        request,
        client: client(Arc::clone(&registry), routed.policy, "client_progress"),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser as _;

    use super::*;
    use crate::cli::Cli;
    use crate::commands::Command;

    const INVALID_RECIPE: &str = "ipv4(dst=192.0.2.1";

    fn live_arguments(command: &str) -> (SendArgs, TemplateArgs) {
        let cli = Cli::try_parse_from(["packetcraftr", command, "--packet", INVALID_RECIPE])
            .expect("arguments parse");
        match cli.command {
            Command::Send(arguments) => (arguments.send, arguments.template),
            Command::Exchange(arguments) => (arguments.send, arguments.template),
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
        let message = error_message(prepare(send, template, request));
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
        let message = error_message(prepare(send, template, request));
        assert!(message.contains("timeout"), "{message}");
        assert_ne!(message, recipe_error());
    }

    #[test]
    fn valid_options_reach_the_invalid_recipe() {
        let (send, template) = live_arguments("send");
        assert_eq!(
            error_message(prepare(send, template, send_request())),
            recipe_error()
        );
        let (send, template) = live_arguments("exchange");
        assert_eq!(
            error_message(prepare(send, template, exchange_request())),
            recipe_error()
        );
    }
}
