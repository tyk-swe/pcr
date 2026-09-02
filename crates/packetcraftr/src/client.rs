// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use crate::progress::Runtime;
use packetcraftr_core::build::BuiltPacket;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::registry::Registry;
use packetcraftr_netio::transmit::Sender as PacketIo;
use packetcraftr_netio::{Error as LiveIoError, link::Mode as LinkMode};

use crate::Error;
use crate::authorization::{WireAuthorizationError, authorize_permissive_live, authorize_wire};
use crate::policy::Policy;

/// High-level composition of packet construction, passive route planning,
/// explicit neighbor materialization, policy, and packet I/O.
#[derive(Debug)]
pub struct Client<R, N, I> {
    pub(crate) registry: Arc<Registry>,
    pub(crate) routes: R,
    pub(crate) neighbors: N,
    pub(crate) io: I,
    pub(crate) policy: Policy,
    /// Owns the worker budget behind
    /// [`exchange_with_events`](Self::exchange_with_events). It starts no
    /// thread until an exchange actually publishes events, and scoping it here
    /// keeps one client's publication failures out of every other client.
    pub(crate) runtime: Runtime,
}

impl<R, N, I> Client<R, N, I>
where
    R: packetcraftr_netio::route::Provider,
    N: packetcraftr_netio::neighbor::Resolver,
    I: PacketIo,
{
    pub fn new(registry: Arc<Registry>, routes: R, neighbors: N, io: I, policy: Policy) -> Self {
        Self {
            registry,
            routes,
            neighbors,
            io,
            policy,
            runtime: Runtime::default(),
        }
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }
}

/// The client's own authorization seam.
///
/// `send`, `exchange`, and `plan` never take an injected
/// [`Authorizer`](crate::authorization::Authorizer); they apply the [`Policy`]
/// this client owns through the two methods below. Both are named for what
/// they authorize — the built packet's declared destinations, and the exact
/// built bytes against the selected route — so neither can be mistaken for the
/// same-named workflow trait method.
impl<R, N, I> Client<R, N, I> {
    /// The traffic policy this client applies to every operation it runs.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Authorizes the destinations a built packet declares, plus the two
    /// permissive-live approvals when the build needed them.
    pub(crate) fn authorize_built_packet(
        &self,
        built: &BuiltPacket,
        allow_permissive_live: bool,
    ) -> Result<(), Error> {
        self.policy.authorize_packet_destinations(&built.packet)?;
        if built.requires_live_opt_in {
            authorize_permissive_live(&self.policy, allow_permissive_live)?;
        }
        Ok(())
    }

    /// Authorizes the exact bytes that would reach the wire against the route
    /// that was selected for them, decoding them with the trusted registry.
    pub(crate) fn authorize_built_wire(
        &self,
        built: &BuiltPacket,
        route: &packetcraftr_netio::route::Plan,
    ) -> Result<(), Error> {
        let link_type = match route.mode {
            LinkMode::Layer2 => route.decision.link_type,
            LinkMode::Layer3 => LinkType::RAW,
            LinkMode::Auto => return Err(LiveIoError::UnresolvedLinkMode.into()),
        };
        authorize_wire(&self.policy, link_type, &built.bytes, Some(route)).map_err(
            |error| -> Error {
                match error {
                    WireAuthorizationError::Decode(error) => {
                        crate::policy::Error::InvalidPacketSemantics {
                            reason: error.to_string(),
                        }
                    }
                    WireAuthorizationError::Policy(error) => error,
                }
                .into()
            },
        )
    }
}
