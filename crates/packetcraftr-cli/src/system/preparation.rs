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

pub(crate) trait LiveDraft {
    type Parameters: LiveParameters;
    const COMMAND: &'static str;
    fn plan_lines(&self, max_template_packets: usize) -> String;
    fn validate(self, max_template_packets: usize) -> Result<Self::Parameters, CliError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlanSummary {
    pub(crate) digest: String,
    pub(crate) packets: u64,
    pub(crate) wire_bytes: u64,
    pub(crate) destination: Option<IpAddr>,
    pub(crate) policy_digest: String,
}

struct PlanInputs<'a> {
    command: &'a str,
    template: &'a core::template::Template,
    registry: &'a Arc<core::registry::Registry>,
    build: &'a core::build::Options,
    policy: &'a packetcraftr::policy::Policy,
    destination: Option<IpAddr>,
    allow_permissive_live: bool,
    link_mode: net::link::Mode,
    plan_lines: &'a str,
    total_packets: u64,
    max_template_packets: usize,
}

fn needs_link_envelope(packet: &core::packet::Packet, registry: &core::registry::Registry) -> bool {
    packet.iter().enumerate().any(|(index, layer)| {
        let Some(padding) = core::layer::Padding::from_layer(layer) else {
            return false;
        };
        padding.outside_layer.is_none()
            && !packet
                .iter()
                .take(index)
                .any(|prior| registry.allows_trailing_padding(prior.protocol_id().as_str()))
    })
}

fn plan_summary(inputs: PlanInputs<'_>) -> Result<PlanSummary, CliError> {
    use sha2::{Digest, Sha256};

    let PlanInputs {
        command,
        template,
        registry,
        build,
        policy,
        destination,
        allow_permissive_live,
        link_mode,
        plan_lines,
        total_packets,
        max_template_packets,
    } = inputs;
    let policy_digest = policy.digest();
    let mut hasher = Sha256::new();
    hasher.update(
        format!(
            "packetcraftr.live-plan/v1\ncommand={command}\npolicy={policy_digest}\ndestination={}\nallow_permissive_live={allow_permissive_live}\nlink_mode={link_mode}\nbuild_mode={:?}\n{plan_lines}packets={total_packets}\n",
            destination.map_or_else(|| "-".to_owned(), |value| value.to_string()),
            build.mode,
        )
        .as_bytes(),
    );
    let builder = core::build::Builder::new(Arc::clone(registry));
    let mut pass_packets: u64 = 0;
    let mut pass_bytes: u64 = 0;
    for packet in template
        .expand(max_template_packets)
        .map_err(CliError::classified)?
    {
        let mut packet = packet.map_err(CliError::classified)?;
        // Route materialization inserts the link envelope before its first
        // build. Mirror that only where a link-padding layer needs it, so
        // planning never rejects a recipe the live path would materialize.
        if link_mode != net::link::Mode::Layer3 && needs_link_envelope(&packet, registry) {
            packet
                .insert(0, core::protocol::link::Ethernet::default())
                .map_err(CliError::classified)?;
        }
        let built = builder
            .build(packet, core::codec::Addresses::default(), build.clone())
            .map_err(CliError::classified)?;
        let length = u64::try_from(built.bytes.len()).unwrap_or(u64::MAX);
        hasher.update(length.to_be_bytes());
        hasher.update(&built.bytes);
        pass_packets += 1;
        pass_bytes = pass_bytes.checked_add(length).ok_or_else(|| {
            CliError::new(core::error::Kind::Internal, "plan wire bytes overflowed")
        })?;
    }
    let passes = total_packets.checked_div(pass_packets).unwrap_or(0);
    let wire_bytes = pass_bytes
        .checked_mul(passes)
        .ok_or_else(|| CliError::new(core::error::Kind::Internal, "plan wire bytes overflowed"))?;
    Ok(PlanSummary {
        digest: core::field::hex::compact_hex(&hasher.finalize()),
        packets: total_packets,
        wire_bytes,
        destination,
        policy_digest,
    })
}

/// Prints the plan for `--plan-only` (returning `true`) or refuses a live
/// run whose prepared plan does not reproduce `--plan-digest`.
pub(crate) fn enforce_plan_gate(
    invocation: &crate::invocation::Invocation,
    gate: &crate::command_options::PlanGateArgs,
    command: &str,
    plan: Option<&PlanSummary>,
) -> Result<bool, CliError> {
    if !gate.active() {
        return Ok(false);
    }
    let Some(plan) = plan else {
        return Err(CliError::new(
            core::error::Kind::Internal,
            "plan gate preparation lost its plan",
        ));
    };
    if gate.plan_only {
        if invocation.format != crate::output::contract::Format::Text {
            return Err(CliError::new(
                core::error::Kind::Usage,
                format!(
                    "--plan-only prints text only, not --output {}",
                    invocation.format
                ),
            ));
        }
        crate::terminal::emit_stdout_document(
            invocation,
            &format!(
                "command={command} plan_digest={} packets={} wire_bytes={} destination={} policy_digest={}\n",
                plan.digest,
                plan.packets,
                plan.wire_bytes,
                plan.destination
                    .map_or_else(|| "-".to_owned(), |value| value.to_string()),
                plan.policy_digest,
            ),
        )?;
        return Ok(true);
    }
    if let Some(presented) = &gate.plan_digest {
        let presented = presented.trim();
        let well_formed = presented.len() == 64
            && presented
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !well_formed || presented != plan.digest {
            return Err(CliError::from_classification(
                packetcraftr_core::error::Classification::new(
                    core::error::Code::PolicyPlanDigest,
                    core::error::Kind::Policy,
                    Some("rerun with --plan-only and present the digest it prints"),
                ),
                format!(
                    "plan digest mismatch: prepared plan is {}, presented {presented}",
                    plan.digest
                ),
                Vec::new(),
            ));
        }
    }
    Ok(false)
}

pub(crate) trait LiveParameters {
    type Request;
    fn budget_count(&self, template: &core::template::Template) -> Result<u64, CliError>;
    fn into_request(
        self,
        template: core::template::Template,
        send: packetcraftr::send::Options,
    ) -> Self::Request;
}

impl LiveParameters for packetcraftr::send::Parameters {
    type Request = packetcraftr::send::Request;

    fn budget_count(&self, template: &core::template::Template) -> Result<u64, CliError> {
        self.packet_count(template).map_err(CliError::classified)
    }

    fn into_request(
        self,
        template: core::template::Template,
        send: packetcraftr::send::Options,
    ) -> Self::Request {
        self.into_request(template, send)
    }
}

impl LiveParameters for packetcraftr::exchange::Parameters {
    type Request = packetcraftr::exchange::Request;

    fn budget_count(&self, template: &core::template::Template) -> Result<u64, CliError> {
        let count = template.expansion_len().map_err(CliError::classified)?;
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    fn into_request(
        self,
        template: core::template::Template,
        send: packetcraftr::send::Options,
    ) -> Self::Request {
        self.into_request(template, send)
    }
}

pub(crate) struct Prepared<R> {
    pub(crate) request: R,
    pub(crate) client: Client,
    pub(crate) plan: Option<PlanSummary>,
}

pub(crate) fn prepare_live<D: LiveDraft>(
    invocation: &crate::invocation::Invocation,
    send: SendArgs,
    template: TemplateArgs,
    draft: D,
    plan_gate_active: bool,
) -> Result<Prepared<<D::Parameters as LiveParameters>::Request>, CliError> {
    let max_template_packets = template.max_template_packets;
    let axes = template.parse()?;
    let draft_lines = draft.plan_lines(max_template_packets);
    // Options fail before recipe parsing can trigger hostname work.
    let parameters = draft.validate(max_template_packets)?;
    let registry = core::protocol::builtin::registry();
    let packet = read_recipe(
        &invocation.control,
        send.route.recipe,
        &registry,
        core::packet::DEFAULT_MAX_LAYERS,
    )?;
    let template = axes.into_template(packet, &registry)?;
    let policy = send.policy.into_policy();
    policy.validate().map_err(CliError::classified)?;
    let count = parameters.budget_count(&template)?;
    policy
        .authorize(packetcraftr::policy::Operation::Wire(
            packetcraftr::policy::WireLimits::new(count, 0),
        ))
        .map_err(CliError::classified)?;
    let first = route::authorize_expanded_destinations(
        invocation,
        &template,
        max_template_packets,
        &policy,
    )?;
    let route_plan = route::options(&send.route.route)?;
    let destination = route::destination(invocation, send.route.destination, &first, &policy)?;
    let build = core::build::Options {
        mode: send.mode.into(),
        ..core::build::Options::default()
    };
    let plan = plan_gate_active
        .then(|| {
            plan_summary(PlanInputs {
                command: D::COMMAND,
                template: &template,
                registry: &registry,
                build: &build,
                policy: &policy,
                destination,
                allow_permissive_live: send.allow_permissive_live,
                link_mode: route_plan.link_mode,
                plan_lines: &draft_lines,
                total_packets: count,
                max_template_packets,
            })
        })
        .transpose()?;
    let request = parameters.into_request(
        template,
        packetcraftr::send::Options {
            destination,
            plan: route_plan,
            build,
            allow_permissive_live: send.allow_permissive_live,
        },
    );
    Ok(Prepared {
        request,
        client: client(invocation, registry, policy, Runtime::Client),
        plan,
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
    let packet = read_recipe(
        &invocation.control,
        recipe,
        &registry,
        core::packet::DEFAULT_MAX_LAYERS,
    )?;
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
    let maximum = net::deadline::MAX_WAIT;
    // A zero window is left to the calling workflow's own limit error.
    if !timeout.is_zero() && core::budget::duration_violation(timeout, maximum) {
        return Err(CliError::classified(
            packetcraftr::exchange::Error::InvalidRequest {
                field: "timeout",
                message: format!("must be greater than zero and not exceed {maximum:?}"),
            },
        ));
    }
    let collection = packetcraftr::exchange::Collection {
        max_unmatched_frames: limits.max_frames,
        max_responses: limits.max_frames,
        capture: limits,
        decode: core::decode::Options {
            limits: core::packet::Limits {
                max_packet_size: limits.snap_length,
                ..core::packet::Limits::default()
            },
        },
    };
    collection.validate().map_err(CliError::classified)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::{
        layer::Padding,
        packet::Packet,
        protocol::{builtin, network::Ipv4, transport::Udp},
        template::Template,
    };

    fn padding_summary(link_mode: net::link::Mode) -> Result<PlanSummary, CliError> {
        let mut packet = Packet::default();
        packet.push(Ipv4 {
            destination: "192.0.2.9".parse().unwrap(),
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 12345,
            destination_port: 9,
            ..Udp::default()
        });
        packet.push(Padding::new(vec![0_u8; 4]));
        let template = Template::new(packet);
        let registry = builtin::registry();
        let build = core::build::Options::default();
        let policy = packetcraftr::policy::Policy::default();
        plan_summary(PlanInputs {
            command: "send",
            template: &template,
            registry: &registry,
            build: &build,
            policy: &policy,
            destination: None,
            allow_permissive_live: false,
            link_mode,
            plan_lines: "",
            total_packets: 1,
            max_template_packets: 10,
        })
    }

    #[test]
    fn plan_build_materializes_link_envelope_before_strict_validation() {
        let layer2 = padding_summary(net::link::Mode::Layer2).unwrap();
        assert_eq!(layer2.wire_bytes, 14 + 20 + 8 + 4);
        let auto = padding_summary(net::link::Mode::Auto).unwrap();
        assert_eq!(auto.wire_bytes, layer2.wire_bytes);
        assert_ne!(auto.digest, layer2.digest);
        assert!(padding_summary(net::link::Mode::Layer3).is_err());
    }
}
