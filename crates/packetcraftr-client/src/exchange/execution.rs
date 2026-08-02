// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::exchange::route_cache::ExchangeRouteProvider;
use crate::send::execution::ensure_preparation_deadline;
use crate::*;

impl<R, N, I> Client<R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo + CaptureProvider,
{
    pub fn exchange(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
    ) -> Result<ExchangeResult, ClientError> {
        self.exchange_internal(template, options, None)
    }

    /// Exchange seam used by the bounded workflows to correlate responses to
    /// the request that produced them. Not part of the documented API.
    #[doc(hidden)]
    pub fn exchange_for_workflow(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
        mut matches_request: impl FnMut(
            usize,
            &Packet,
            &packetcraftr_packet::decode::DecodedPacket,
        ) -> bool,
    ) -> Result<ExchangeResult, ClientError> {
        self.exchange_internal(template, options, Some(&mut matches_request))
    }

    fn exchange_internal(
        &self,
        template: &PacketTemplate,
        options: ExchangeOptions,
        workflow_matcher: Option<&mut WorkflowResponseMatcher<'_>>,
    ) -> Result<ExchangeResult, ClientError> {
        let prepared = self.prepare_exchange(template, options)?;
        let transaction = self.arm_capture(prepared)?;
        transaction.execute(&self.io, workflow_matcher)
    }

    fn prepare_exchange(
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
        self.policy.authorize_operation(expansion_len as u64, 0)?;
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
        let packet_count = expansion_len as u64;
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
                .checked_add(preliminary.bytes.len() as u64)
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
            let route = self.planner.materialize(plan, &self.neighbors)?;
            ensure_preparation_deadline(deadline)?;
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

    fn arm_capture(
        &self,
        prepared: PreparedExchange,
    ) -> Result<
        ExchangeTransaction<<I as packetcraftr_net::capture::CaptureProvider>::Capture>,
        ClientError,
    > {
        let first_route = &prepared
            .packets
            .first()
            .expect("non-empty prepared exchange")
            .route
            .plan;
        ensure_preparation_deadline(prepared.deadline)?;
        let capture = self.io.arm_capture(first_route, prepared.capture_limits)?;
        Ok(ExchangeTransaction::new(
            Arc::clone(&self.registry),
            capture,
            prepared,
        ))
    }
}
