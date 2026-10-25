// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic packet construction and the final prepared-packet handoff.

use super::materialize::{
    build_context, materialize_link_fields, materialize_link_structure, materialize_network_fields,
    require_fixed_width_link_materialization,
};
use super::{Error, route};
use crate::evidence::SentPacket;
use bytes::Bytes;
use packetcraftr_core::{
    build::{self, Builder, BuiltPacket},
    codec,
    packet::Packet,
};
use packetcraftr_netio::{Error as LiveIoError, transmit};

pub(crate) struct PreparedPacket {
    pub(super) built: BuiltPacket,
    pub(super) route: route::Materialized,
}

impl PreparedPacket {
    pub(crate) fn built(&self) -> &BuiltPacket {
        &self.built
    }

    pub(crate) fn route(&self) -> &route::Materialized {
        &self.route
    }

    pub(crate) fn transmit<I, E>(
        self,
        io: &I,
        check: impl FnOnce() -> Result<(), E>,
    ) -> Result<SentPacket, E>
    where
        I: transmit::Provider + ?Sized,
        E: From<LiveIoError>,
    {
        let report = {
            let frame =
                transmit::Outbound::try_new(&self.built.bytes, self.route.transmit_route())?;
            check()?;
            io.send(frame)?
        };
        Ok(SentPacket::try_new(self.built, self.route, report)?)
    }
}

/// Deterministic: no provider is consulted and nothing is authorized, so the
/// result is only a reference for bytes that were prepared elsewhere.
pub(crate) fn exact_bytes(
    builder: &Builder,
    options: &build::Options,
    mut packet: Packet,
    route: &route::Materialized,
) -> Result<Bytes, Error> {
    let rules = Materializer { builder, options };
    let unchecked = || Ok(());
    let (context, preliminary) = rules.preliminary(&mut packet, &route.plan, unchecked)?;
    let built = rules.link(packet, route, context, preliminary, unchecked)?;
    Ok(built.bytes)
}

pub(super) struct Materializer<'a> {
    pub(super) builder: &'a Builder,
    pub(super) options: &'a build::Options,
}

impl Materializer<'_> {
    pub(super) fn preliminary(
        &self,
        packet: &mut Packet,
        plan: &route::Plan,
        check: impl Fn() -> Result<(), Error>,
    ) -> Result<(codec::Addresses, BuiltPacket), Error> {
        materialize_network_fields(packet, plan)?;
        materialize_link_structure(packet, plan)?;
        check()?;
        let context = build_context(plan);
        let built = self
            .builder
            .build(packet.clone(), context.clone(), self.options.clone())?;
        Ok((context, built))
    }

    pub(super) fn link(
        &self,
        mut packet: Packet,
        route: &route::Materialized,
        context: codec::Addresses,
        preliminary: BuiltPacket,
        check: impl Fn() -> Result<(), Error>,
    ) -> Result<BuiltPacket, Error> {
        let preliminary_len = preliminary.bytes.len();
        let built = if materialize_link_fields(&mut packet, route)? {
            check()?;
            self.builder.build(packet, context, self.options.clone())?
        } else {
            preliminary
        };
        require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
        Ok(built)
    }
}
