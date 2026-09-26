// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The pre-discovery preparation `send` and `exchange` share: every check
//! that can refuse the operation runs before hostname or interface work, in
//! one order, and policy is validated once.

use std::sync::Arc;

use packetcraftr_core as core;

use crate::command_options::{SendArgs, TemplateArgs};
use crate::errors::CliError;
use crate::input::read_recipe;
use crate::system::{Client, client, prepare_expanded_route};

/// A live command's own options, as the shared preparation sees them.
pub(super) trait LiveOptions {
    /// Checks the command's options before the recipe is read.
    fn validate(&self) -> Result<(), CliError>;
    /// The packet count the count-only operation budget admits.
    fn budget_count(&self, template: &core::template::Template) -> Result<u64, CliError>;
    /// Installs the resolved per-packet send options.
    fn set_send(&mut self, send: packetcraftr::send::Options);
}

impl LiveOptions for packetcraftr::send::SetOptions {
    fn validate(&self) -> Result<(), CliError> {
        Self::validate(self).map_err(CliError::classified)
    }

    /// Counts the complete expansion times repetition.
    fn budget_count(&self, template: &core::template::Template) -> Result<u64, CliError> {
        self.validate_for(template).map_err(CliError::classified)
    }

    fn set_send(&mut self, send: packetcraftr::send::Options) {
        self.send = send;
    }
}

impl LiveOptions for packetcraftr::exchange::Options {
    fn validate(&self) -> Result<(), CliError> {
        Self::validate(self).map_err(CliError::classified)
    }

    /// Counts one pass over the expansion.
    fn budget_count(&self, template: &core::template::Template) -> Result<u64, CliError> {
        let count = template.expansion_len().map_err(CliError::classified)?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    fn set_send(&mut self, send: packetcraftr::send::Options) {
        self.send = send;
    }
}

/// The packet set, the command's options with resolved send options, and a
/// client bound to the validated policy.
pub(super) struct Prepared<O> {
    pub(super) template: core::template::Template,
    pub(super) options: O,
    pub(super) client: Client,
}

/// Validates `options`, reads the recipe into the template, validates policy,
/// authorizes the budget count and every expanded destination, then prepares
/// the first packet's route.
pub(super) fn prepare<O: LiveOptions>(
    send: SendArgs,
    template: TemplateArgs,
    mut options: O,
) -> Result<Prepared<O>, CliError> {
    let max_template_packets = template.max_template_packets;
    let axes = template.parse()?;
    // Options fail before recipe parsing can trigger hostname/interface work.
    options.validate()?;
    let registry = core::protocol::builtin::registry();
    let packet = read_recipe(
        send.route.recipe,
        &registry,
        core::layout::DEFAULT_MAX_LAYERS,
    )?;
    let template = axes.into_template(packet);
    let policy = send.policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let count = options.budget_count(&template)?;
    policy
        .authorize(packetcraftr::policy::Operation::Wire(
            packetcraftr::policy::WireLimits::new(count, 0),
        ))
        .map_err(CliError::classified)?;
    let routed = prepare_expanded_route(
        &template,
        max_template_packets,
        send.route.destination,
        send.route.route,
        policy,
    )?;
    options.set_send(packetcraftr::send::Options {
        destination: routed.destination,
        plan: routed.options,
        build: core::build::Options {
            mode: send.mode.into(),
            ..core::build::Options::default()
        },
        allow_permissive_live: send.allow_permissive_live,
    });
    Ok(Prepared {
        template,
        options,
        client: client(Arc::clone(&registry), routed.policy),
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
        let options = packetcraftr::send::SetOptions {
            repeat: 0,
            ..Default::default()
        };
        let message = error_message(prepare(send, template, options));
        assert!(message.contains("repeat"), "{message}");
        assert_ne!(message, recipe_error());
    }

    #[test]
    fn exchange_rejects_invalid_options_before_the_recipe() {
        let (send, template) = live_arguments("exchange");
        let options = packetcraftr::exchange::Options {
            timeout: Duration::MAX,
            ..Default::default()
        };
        let message = error_message(prepare(send, template, options));
        assert!(message.contains("timeout"), "{message}");
        assert_ne!(message, recipe_error());
    }

    #[test]
    fn valid_options_reach_the_invalid_recipe() {
        let (send, template) = live_arguments("send");
        let options = packetcraftr::send::SetOptions::default();
        assert_eq!(
            error_message(prepare(send, template, options)),
            recipe_error()
        );
        let (send, template) = live_arguments("exchange");
        let options = packetcraftr::exchange::Options::default();
        assert_eq!(
            error_message(prepare(send, template, options)),
            recipe_error()
        );
    }
}
