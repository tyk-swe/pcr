// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded exchange expansion, planning, and packet materialization.

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_core::{Packet, build::Builder, template};
use packetcraftr_netio::{neighbor, route, transmit};

use crate::Client;
use crate::Error;
use crate::materialize::{PlannedPacket, PreparedPacket};
use crate::planning::ensure_preparation_deadline;

use super::contract::Options;
use super::route_cache::CachedProvider;

pub(crate) struct Prepared {
    pub(crate) started: Instant,
    pub(crate) deadline: Instant,
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
        // Both front doors reject a malformed policy identically: the
        // workflow seam does it in `PolicyAuthorizer::authorize_operation`.
        self.policy.validate()?;
        options.validate()?;
        let deadline = started
            .checked_add(options.timeout)
            .expect("validated bounded exchange timeout must fit Instant");
        let expansion_len = template.expansion_len();
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
            let packet_to_send = expanded_packet.map_err(|source| Error::Template {
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
            let planned = self.plan_and_authorize(
                packet_to_send,
                plan,
                builder,
                &options.send,
                Some(deadline),
            )?;
            total_bytes = total_bytes
                .checked_add(
                    u64::try_from(planned.preliminary_build.bytes.len()).unwrap_or(u64::MAX),
                )
                .ok_or(crate::policy::Error::ByteLimit {
                    actual: u64::MAX,
                    limit: self.policy.max_bytes_per_operation,
                })?;
            self.policy.authorize_operation(packet_count, total_bytes)?;
            if let Some(first_packet) = planned_packets.first()
                && (first_packet.plan.decision.interface != planned.plan.decision.interface
                    || first_packet.plan.mode != planned.plan.mode)
            {
                return Err(Error::HeterogeneousExchangeRoute);
            }
            planned_packets.push(planned);
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
            prepared_packets.push(self.materialize_and_authorize(
                planned_packet,
                builder,
                &options.send,
                Some(deadline),
            )?);
        }
        Ok(prepared_packets)
    }
}
