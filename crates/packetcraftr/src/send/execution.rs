// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_core::{Packet, build::Builder};
use packetcraftr_netio::{
    capture::Statistics,
    route::materialize,
    transmit::{Frame as TransmissionFrame, Sender as PacketIo},
};

use crate::Client;
use crate::Error;
use crate::Stats;
use crate::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    require_fixed_width_link_materialization,
};
use crate::mtu::validate_mtu;
use crate::send::{Options, Report};

impl<R, N, I> Client<R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo,
{
    pub fn send(&self, packet: Packet, options: Options) -> Result<Report, Error> {
        let started = Instant::now();
        self.policy.authorize_operation(1, 0)?;
        let plan = self.plan(&packet, options.destination, &options.plan)?;
        let mut packet_to_send = packet;
        materialize_network_fields(&mut packet_to_send, &plan)?;
        materialize_link_structure(&mut packet_to_send, &plan)?;
        let builder = Builder::new(Arc::clone(&self.registry));
        let context = build_context(&plan);
        // Validate all packet fields before neighbor discovery emits traffic.
        let preliminary = builder.build(
            packet_to_send.clone(),
            context.clone(),
            options.build.clone(),
        )?;
        validate_mtu(&preliminary, plan.decision.mtu)?;
        self.authorize_built(&preliminary, options.allow_permissive_live)?;
        self.authorize_final_wire(&preliminary, &plan)?;
        self.policy.authorize_operation(
            1,
            u64::try_from(preliminary.bytes.len()).unwrap_or(u64::MAX),
        )?;
        let preliminary_len = preliminary.bytes.len();
        let route = materialize(plan, &self.neighbors)?;
        let link_changed = materialize_link_fields(&mut packet_to_send, &route)?;
        let built = if link_changed {
            let built = builder.build(packet_to_send, context, options.build)?;
            require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
            self.authorize_built(&built, options.allow_permissive_live)?;
            self.authorize_final_wire(&built, &route.plan)?;
            self.policy
                .authorize_operation(1, u64::try_from(built.bytes.len()).unwrap_or(u64::MAX))?;
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
        Ok(Report {
            sent,
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: u64::try_from(bytes_sent).unwrap_or(u64::MAX),
                elapsed: started.elapsed(),
                capture: Statistics::default(),
            },
        })
    }
}
