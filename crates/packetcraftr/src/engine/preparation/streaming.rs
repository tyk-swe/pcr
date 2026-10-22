// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Streaming preparation using one operation's cumulative admission budget.

use super::admission::Budget;
use super::construction::PreparedPacket;
use super::{Clock, Error, Packet, PacketProviders, Stages, TransmitProviders, route};
use crate::evidence::SentPacket;

pub(crate) struct Streaming<'c, P, K> {
    pub(super) stages: Stages<'c, P, K>,
    pub(super) budget: Budget,
}

impl<P: TransmitProviders, K: Clock> Streaming<'_, P, K> {
    pub(crate) fn check(&self) -> Result<(), Error> {
        self.stages.check()
    }

    pub(crate) fn prepare_layer3(&mut self, packet: Packet) -> Result<PreparedPacket, Error> {
        let admitted = self.stages.admit(
            &mut self.budget,
            packet,
            self.stages.client.providers.route_provider(),
        )?;
        self.stages.materialize_using(admitted, |plan, _| {
            if plan.mode != packetcraftr_netio::link::Mode::Layer3
                || plan.needs_neighbor_resolution()
            {
                return Err(route::Error::Layer3Unsupported);
            }
            Ok(route::Materialized {
                plan,
                neighbor_resolution: None,
            })
        })
    }

    pub(crate) fn transmit(&self, packet: PreparedPacket) -> Result<SentPacket, Error> {
        packet.transmit(self.stages.client.providers.transmit_provider(), || {
            self.stages.check()
        })
    }
}

impl<P: PacketProviders, K: Clock> Streaming<'_, P, K> {
    pub(crate) fn prepare(&mut self, packet: Packet) -> Result<PreparedPacket, Error> {
        let admitted = self.stages.admit(
            &mut self.budget,
            packet,
            TransmitProviders::route_provider(self.stages.client.providers.as_ref()),
        )?;
        self.stages.materialize(admitted)
    }
}
