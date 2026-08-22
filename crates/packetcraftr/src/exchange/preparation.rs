// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded exchange expansion, planning, and packet materialization.

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_core::{
    Packet,
    build::{self, Builder, BuiltPacket},
    template,
};
use packetcraftr_netio::{capture, neighbor, route, transmit};

use crate::Client;
use crate::Error;
use crate::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    patch_builtin_ethernet, require_fixed_width_link_materialization,
};
use crate::mtu::validate_mtu;
use crate::planning::ensure_preparation_deadline;

use super::contract::Options;
use super::route_cache::CachedProvider;

pub(crate) struct PlannedPacket {
    pub(crate) packet: Packet,
    pub(crate) plan: route::Plan,
    pub(crate) build_context: build::Context,
    pub(crate) preliminary_build: BuiltPacket,
}

pub(crate) struct PreparedPacket {
    pub(crate) built: BuiltPacket,
    pub(crate) route: route::Materialized,
}

pub(crate) struct Prepared {
    pub(crate) started: Instant,
    pub(crate) deadline: Instant,
    pub(crate) capture_limits: capture::Limits,
    pub(crate) options: Options,
    pub(crate) packets: Vec<PreparedPacket>,
    pub(crate) packet_count: u64,
    pub(crate) total_bytes: u64,
}

impl<R, N, I> Client<R, N, I>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    pub(super) fn prepare_exchange(
        &self,
        template: &template::Template,
        options: Options,
    ) -> Result<Prepared, Error> {
        let started = Instant::now();
        let capture_limits = options.validate()?;
        let deadline = started
            .checked_add(options.timeout)
            .expect("validated bounded exchange timeout must fit Instant");
        let expansion_len = template.expansion_len().map_err(|source| Error::Template {
            message: source.to_string(),
        })?;
        self.policy
            .authorize_operation(u64::try_from(expansion_len).unwrap_or(u64::MAX), 0)?;
        if expansion_len == 0 {
            return Err(Error::Template {
                message: "template expanded to no packets".to_owned(),
            });
        }
        let expanded_packets = template
            .expand(options.max_template_packets)
            .map_err(|source| Error::Template {
                message: source.to_string(),
            })?;
        let packet_count = u64::try_from(expansion_len).unwrap_or(u64::MAX);
        let builder = Builder::new(Arc::clone(&self.registry));
        let routes = CachedProvider::new(&self.routes);
        let (planned_packets, total_bytes) = self.plan_packets(
            expanded_packets,
            packet_count,
            deadline,
            &options,
            &builder,
            &routes,
        )?;
        let packets = self.materialize_packets(planned_packets, deadline, &options, &builder)?;

        Ok(Prepared {
            started,
            deadline,
            capture_limits,
            options,
            packets,
            packet_count,
            total_bytes,
        })
    }

    fn plan_packets(
        &self,
        mut expanded_packets: impl ExactSizeIterator<Item = Result<Packet, template::Error>>,
        packet_count: u64,
        deadline: Instant,
        options: &Options,
        builder: &Builder,
        routes: &CachedProvider<'_, R>,
    ) -> Result<(Vec<PlannedPacket>, u64), Error> {
        let mut planned_packets: Vec<PlannedPacket> = Vec::with_capacity(expanded_packets.len());
        let mut total_bytes = 0u64;
        loop {
            ensure_preparation_deadline(deadline)?;
            let Some(expanded_packet) = expanded_packets.next() else {
                break;
            };
            ensure_preparation_deadline(deadline)?;
            let mut packet_to_send = expanded_packet.map_err(|source| Error::Template {
                message: source.to_string(),
            })?;
            ensure_preparation_deadline(deadline)?;
            let plan = self.plan_with_provider(
                &packet_to_send,
                options.send.destination,
                &options.send.plan,
                routes,
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
            validate_mtu(&preliminary, plan.decision.mtu)?;
            self.authorize_built(&preliminary, options.send.allow_permissive_live)?;
            self.authorize_final_wire(&preliminary, &plan)?;
            total_bytes = total_bytes
                .checked_add(u64::try_from(preliminary.bytes.len()).unwrap_or(u64::MAX))
                .ok_or(crate::policy::Error::ByteLimit {
                    actual: u64::MAX,
                    limit: self.policy.max_bytes_per_operation,
                })?;
            self.policy.authorize_operation(packet_count, total_bytes)?;
            if let Some(first_packet) = planned_packets.first()
                && (first_packet.plan.decision.interface != plan.decision.interface
                    || first_packet.plan.mode != plan.mode)
            {
                return Err(Error::HeterogeneousExchangeRoute);
            }
            planned_packets.push(PlannedPacket {
                packet: packet_to_send,
                plan,
                build_context: context,
                preliminary_build: preliminary,
            });
        }
        Ok((planned_packets, total_bytes))
    }

    fn materialize_packets(
        &self,
        planned_packets: Vec<PlannedPacket>,
        deadline: Instant,
        options: &Options,
        builder: &Builder,
    ) -> Result<Vec<PreparedPacket>, Error> {
        // Neighbor discovery is delayed until every packet has passed packet,
        // route, permissive-build, and aggregate byte-policy checks.
        let mut prepared_packets = Vec::with_capacity(planned_packets.len());
        for planned_packet in planned_packets {
            ensure_preparation_deadline(deadline)?;
            let PlannedPacket {
                mut packet,
                plan,
                build_context,
                mut preliminary_build,
            } = planned_packet;
            let preliminary_len = preliminary_build.bytes.len();
            let route = route::materialize(plan, &self.neighbors)?;
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
            prepared_packets.push(PreparedPacket { built, route });
        }
        Ok(prepared_packets)
    }
}
