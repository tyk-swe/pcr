// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//! Operation-local protocol bindings make each explicit profile's wire intent
//! agree with strict building. The original client and registry remain intact.
use super::Batch;
use crate::Client;
use packetcraftr_core::{
    error::BoundaryError,
    layer::Id,
    registry::{Discriminator, Registry},
};
use packetcraftr_netio::{capture, neighbor, route, transmit};
use std::{collections::BTreeMap, net::IpAddr, sync::Arc};
pub(super) fn configured(
    base: &Arc<Registry>,
    batches: &[Batch],
) -> Result<Arc<Registry>, BoundaryError> {
    let mut mappings = BTreeMap::new();
    for batch in batches {
        if let Some(profile) = &batch.probe.udp_profile
            && let Some(port) = batch.probe.endpoint.port()
        {
            let child = Id::new(if profile.raw_payload() { "raw" } else { "dns" });
            if mappings
                .insert(port, child)
                .is_some_and(|previous| previous != child)
            {
                return Err(BoundaryError::from_error(super::profile::Error(
                    "conflicting wire profiles for one UDP port",
                )));
            }
        }
    }
    let overrides: Vec<_> = mappings
        .into_iter()
        .filter(|(port, child)| {
            base.child_for("udp", Discriminator(u64::from(*port))) != Some(*child)
        })
        .collect();
    if overrides.is_empty() {
        return Ok(base.clone());
    }
    let mut builder = base.to_builder();
    for (port, child) in overrides {
        builder
            .bind("udp", u64::from(port), child, i32::MAX)
            .map_err(|error| {
                BoundaryError::new(
                    error.to_string(),
                    packetcraftr_core::error::Classification::new(
                        "cli.udp_profile",
                        packetcraftr_core::error::Kind::Cli,
                        None,
                    ),
                    Vec::new(),
                )
            })?;
    }
    builder.build().map(Arc::new).map_err(|error| {
        BoundaryError::new(
            error.to_string(),
            packetcraftr_core::error::Classification::new(
                "cli.udp_profile",
                packetcraftr_core::error::Kind::Cli,
                None,
            ),
            Vec::new(),
        )
    })
}
pub(super) struct Routes<'a, R>(&'a R);
pub(super) struct Neighbors<'a, N>(&'a N);
pub(super) struct Io<'a, I>(&'a I);
impl<R: route::Provider> route::Provider for Routes<'_, R> {
    type Error = R::Error;
    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface: Option<&packetcraftr_netio::interface::Id>,
        source: Option<IpAddr>,
    ) -> Result<route::Decision, Self::Error> {
        self.0
            .lookup_with_preferences(destination, interface, source)
    }
}
impl<N: neighbor::Resolver> neighbor::Resolver for Neighbors<'_, N> {
    fn resolve(
        &self,
        request: &neighbor::Request,
    ) -> Result<neighbor::Resolution, neighbor::Error> {
        self.0.resolve(request)
    }
}
impl<I: transmit::Sender> transmit::Sender for Io<'_, I> {
    fn send(
        &self,
        frame: transmit::Frame<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        self.0.send(frame)
    }
}
impl<I: capture::Provider> capture::Provider for Io<'_, I> {
    type Capture = I::Capture;
    fn arm_capture(
        &self,
        request: &capture::Request,
    ) -> Result<Self::Capture, packetcraftr_netio::Error> {
        self.0.arm_capture(request)
    }
}
pub(super) fn client<R, N, I>(
    client: &Client<R, N, I>,
    registry: Arc<Registry>,
) -> Client<Routes<'_, R>, Neighbors<'_, N>, Io<'_, I>> {
    Client {
        registry,
        routes: Routes(&client.routes),
        neighbors: Neighbors(&client.neighbors),
        io: Io(&client.io),
        policy: client.policy.clone(),
        runtime: client.runtime.clone(),
        cancellation: client.cancellation.clone(),
    }
}
