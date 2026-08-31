// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::Instant;

use packetcraftr_core::{Packet, build::Builder};
use packetcraftr_netio::{
    capture::Statistics,
    transmit::{Frame as TransmissionFrame, Sender as PacketIo},
};

use crate::Client;
use crate::Error;
use crate::Stats;
use crate::send::{Options, Report};

impl<R, N, I> Client<R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo,
{
    pub fn send(&self, packet: Packet, options: Options) -> Result<Report, Error> {
        let started = Instant::now();
        // Both front doors reject a malformed policy identically: the
        // workflow seam does it in `PolicyAuthorizer::authorize_operation`.
        self.policy.validate()?;
        self.policy.authorize_operation(1, 0)?;
        let plan = self.plan(&packet, options.destination, &options.plan)?;
        let builder = Builder::new(Arc::clone(&self.registry));
        // Validate and authorize every packet field before neighbor discovery
        // emits traffic.
        let planned = self.plan_and_authorize(packet, plan, &builder, &options, None)?;
        self.policy.authorize_operation(
            1,
            u64::try_from(planned.preliminary_build.bytes.len()).unwrap_or(u64::MAX),
        )?;
        let prepared = self.materialize_and_authorize(planned, &builder, &options, None)?;
        // Link-layer synthesis is already included in the exact build. The
        // typed frame selects the matching native provider boundary.
        let io_report = self.io.send(TransmissionFrame::try_new(
            &prepared.built.bytes,
            &prepared.route,
        )?)?;
        let sent = crate::SentPacket::try_new(prepared.built, prepared.route, io_report)?;
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
