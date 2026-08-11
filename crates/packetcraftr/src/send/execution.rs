// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_core::{Packet, build::Builder};
use packetcraftr_netio::{
    capture::Statistics,
    neighbor::Resolver as NeighborResolver,
    route::{Provider as RouteProvider, materialize},
    transmit::{Frame as TransmissionFrame, Sender as PacketIo},
};

use crate::Client;
use crate::Stats;
use crate::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    patch_builtin_ethernet, require_fixed_width_link_materialization,
};
use crate::send::{ClientError, SendOptions, SendReport};
use crate::validation::validate_mtu;

impl<R, N, I> Client<R, N, I>
where
    R: RouteProvider,
    N: NeighborResolver,
    I: PacketIo,
{
    pub fn send(&self, packet: Packet, options: SendOptions) -> Result<SendReport, ClientError> {
        let started = Instant::now();
        self.policy.authorize_operation(1, 0)?;
        let plan = self.plan(&packet, options.destination, &options.plan)?;
        let mut packet_to_send = packet;
        materialize_network_fields(&mut packet_to_send, &plan)?;
        materialize_link_structure(&mut packet_to_send, &plan)?;
        let builder = Builder::new(Arc::clone(&self.registry));
        let context = build_context(&plan);
        // Validate all packet fields before neighbor discovery emits traffic.
        let mut preliminary = builder.build(
            packet_to_send.clone(),
            context.clone(),
            options.build.clone(),
        )?;
        validate_mtu(&preliminary, plan.route.mtu)?;
        self.authorize_built(&preliminary, options.allow_permissive_live)?;
        self.authorize_final_wire(&preliminary, &plan)?;
        self.policy
            .authorize_operation(1, preliminary.bytes.len() as u64)?;
        let preliminary_len = preliminary.bytes.len();
        let route = materialize(plan, &self.neighbors)?;
        let link_changed = materialize_link_fields(&mut packet_to_send, &route)?;
        let built = if link_changed {
            let built = if patch_builtin_ethernet(&self.registry, &mut preliminary, &packet_to_send)
            {
                preliminary
            } else {
                builder.build(packet_to_send, context, options.build)?
            };
            require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
            self.authorize_built(&built, options.allow_permissive_live)?;
            self.authorize_final_wire(&built, &route.plan)?;
            self.policy
                .authorize_operation(1, built.bytes.len() as u64)?;
            built
        } else {
            preliminary
        };
        // Link-layer synthesis is already included in the exact build. The
        // typed frame selects the matching native provider boundary.
        let io_report = self
            .io
            .send(TransmissionFrame::try_new(&built.bytes, &route)?)?;
        let sent = crate::SentPacket::try_new(built, route, io_report)?;
        let bytes_sent = sent.bytes_sent();
        Ok(SendReport {
            sent,
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: bytes_sent as u64,
                elapsed: started.elapsed(),
                capture: Statistics::default(),
            },
        })
    }
}
