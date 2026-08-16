// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded exchange expansion, planning, and packet materialization.

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_core::{
    Packet,
    build::{BuildContext, Builder, BuiltPacket},
    template::Template as PacketTemplate,
};
use packetcraftr_netio::{
    neighbor::Resolver as NeighborResolver,
    route::{
        Materialized as MaterializedRoute, Plan as PlannedRoute, Provider as RouteProvider,
        materialize,
    },
    transmit::Sender as PacketIo,
};

use crate::Client;
use crate::exchange::ExchangeOptions;
use crate::exchange::route_cache::ExchangeRouteProvider;
use crate::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    patch_builtin_ethernet, require_fixed_width_link_materialization,
};
use crate::planning::ensure_preparation_deadline;
use crate::policy::TrafficPolicyError;
use crate::send::ClientError;
use crate::validation::validate_mtu;

pub(crate) struct PlannedExchangePacket {
    pub(crate) packet: Packet,
    pub(crate) plan: PlannedRoute,
    pub(crate) build_context: BuildContext,
    pub(crate) preliminary_build: BuiltPacket,
}

pub(crate) struct PreparedExchangePacket {
    pub(crate) built: BuiltPacket,
    pub(crate) route: MaterializedRoute,
}

pub(crate) struct PreparedExchange {
    pub(crate) started: Instant,
    pub(crate) deadline: Instant,
    pub(crate) capture_limits: packetcraftr_netio::capture::Limits,
    pub(crate) options: ExchangeOptions,
    pub(crate) packets: Vec<PreparedExchangePacket>,
    pub(crate) packet_count: u64,
    pub(crate) total_bytes: u64,
}

impl<R, N, I> Client<R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo,
{
    pub(super) fn prepare_exchange(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
    ) -> Result<PreparedExchange, ClientError> {
        let started = Instant::now();
        let capture_limits = options.validate()?;
        let deadline = started
            .checked_add(options.timeout)
            .expect("validated bounded exchange timeout must fit Instant");
        let expansion_len = template
            .expansion_len()
            .map_err(|source| ClientError::Template {
                message: source.to_string(),
            })?;
        self.policy
            .authorize_operation(u64::try_from(expansion_len).unwrap_or(u64::MAX), 0)?;
        if expansion_len == 0 {
            return Err(ClientError::Template {
                message: "template expanded to no packets".to_owned(),
            });
        }
        let mut expanded_packets =
            template
                .expand(options.max_template_packets)
                .map_err(|source| ClientError::Template {
                    message: source.to_string(),
                })?;
        let packet_count = u64::try_from(expansion_len).unwrap_or(u64::MAX);
        let builder = Builder::new(Arc::clone(&self.registry));
        let routes = ExchangeRouteProvider::new(&self.routes);
        let mut planned_packets: Vec<PlannedExchangePacket> = Vec::with_capacity(expansion_len);
        let mut total_bytes = 0u64;
        loop {
            ensure_preparation_deadline(deadline)?;
            let Some(expanded_packet) = expanded_packets.next() else {
                break;
            };
            ensure_preparation_deadline(deadline)?;
            let mut packet_to_send = expanded_packet.map_err(|source| ClientError::Template {
                message: source.to_string(),
            })?;
            ensure_preparation_deadline(deadline)?;
            let plan = self.plan_with_provider(
                &packet_to_send,
                options.send.destination,
                &options.send.plan,
                &routes,
                Some(deadline),
            )?;
            ensure_preparation_deadline(deadline)?;
            // Route selection precedes all route-dependent materialization.
            materialize_network_fields(&mut packet_to_send, &plan)?;
            materialize_link_structure(&mut packet_to_send, &plan)?;
            ensure_preparation_deadline(deadline)?;
            let context = build_context(&plan);
            let preliminary = builder.build(
                packet_to_send.clone(),
                context.clone(),
                options.send.build.clone(),
            )?;
            ensure_preparation_deadline(deadline)?;
            validate_mtu(&preliminary, plan.route.mtu)?;
            self.authorize_built(&preliminary, options.send.allow_permissive_live)?;
            self.authorize_final_wire(&preliminary, &plan)?;
            total_bytes = total_bytes
                .checked_add(u64::try_from(preliminary.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(TrafficPolicyError::ByteLimit {
                    actual: u64::MAX,
                    limit: self.policy.max_bytes_per_operation,
                })?;
            self.policy.authorize_operation(packet_count, total_bytes)?;
            if let Some(first_packet) = planned_packets.first()
                && (first_packet.plan.route.interface != plan.route.interface
                    || first_packet.plan.mode != plan.mode)
            {
                return Err(ClientError::HeterogeneousExchangeRoute);
            }
            planned_packets.push(PlannedExchangePacket {
                packet: packet_to_send,
                plan,
                build_context: context,
                preliminary_build: preliminary,
            });
        }

        // Neighbor discovery is delayed until every packet has passed packet,
        // route, permissive-build, and aggregate byte-policy checks.
        let mut prepared_packets = Vec::with_capacity(planned_packets.len());
        for planned_packet in planned_packets {
            ensure_preparation_deadline(deadline)?;
            let PlannedExchangePacket {
                mut packet,
                plan,
                build_context,
                mut preliminary_build,
            } = planned_packet;
            let preliminary_len = preliminary_build.bytes.len();
            let route = materialize(plan, &self.neighbors)?;
            ensure_preparation_deadline(deadline)?;
            // Neighbor materialization is the only step that resolves link fields.
            let link_changed = materialize_link_fields(&mut packet, &route)?;
            let built = if link_changed {
                if patch_builtin_ethernet(&self.registry, &mut preliminary_build, &packet) {
                    preliminary_build
                } else {
                    ensure_preparation_deadline(deadline)?;
                    builder.build(packet, build_context, options.send.build.clone())?
                }
            } else {
                preliminary_build
            };
            ensure_preparation_deadline(deadline)?;
            self.authorize_built(&built, options.send.allow_permissive_live)?;
            // Every final materialized destination is authorized immediately
            // before capture arming and transmission can observe it.
            self.authorize_final_wire(&built, &route.plan)?;
            require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
            prepared_packets.push(PreparedExchangePacket { built, route });
        }

        Ok(PreparedExchange {
            started,
            deadline,
            capture_limits,
            options,
            packets: prepared_packets,
            packet_count,
            total_bytes,
        })
    }
}
