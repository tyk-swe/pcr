// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Authorization of built packets and their final wire representation.

use std::sync::{Arc, OnceLock};

use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::{
    build::BuiltPacket,
    decode::{Dissector, Options as DecodeOptions},
    registry::Registry,
};
use packetcraftr_netio::{
    Error as LiveIoError, link::Mode as LinkMode, route::Plan as PlannedRoute,
};

use crate::Client;
use crate::Error;
use crate::policy::Error as PolicyError;

impl<R, N, I> Client<R, N, I> {
    pub(crate) fn authorize_built(
        &self,
        built: &BuiltPacket,
        allow_permissive_live: bool,
    ) -> Result<(), Error> {
        self.policy.authorize_packet_destinations(&built.packet)?;
        if built.requires_live_opt_in {
            if !allow_permissive_live {
                return Err(Error::PermissiveLiveOptInRequired);
            }
            if !self.policy.allow_permissive_packets {
                return Err(PolicyError::PermissivePacket.into());
            }
        }
        Ok(())
    }

    pub(crate) fn authorize_final_wire(
        &self,
        built: &BuiltPacket,
        route: &PlannedRoute,
    ) -> Result<(), Error> {
        let link_type = match route.mode {
            LinkMode::Layer2 => route.decision.link_type,
            LinkMode::Layer3 => LinkType::RAW,
            LinkMode::Auto => return Err(LiveIoError::UnresolvedLinkMode.into()),
        };
        static REGISTRY: OnceLock<Result<Arc<Registry>, String>> = OnceLock::new();
        let registry = REGISTRY
            .get_or_init(|| {
                packetcraftr_core::protocol::builtin::registry()
                    .map(Arc::new)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|reason| PolicyError::InvalidPacketSemantics {
                reason: reason.clone(),
            })?;
        if registry.root_for_link_type(link_type.0).is_none() {
            return Err(PolicyError::InvalidPacketSemantics {
                reason: format!(
                    "final-wire authorization does not support link type {}",
                    link_type.0
                ),
            }
            .into());
        }
        let frame = Frame::new(
            std::time::SystemTime::UNIX_EPOCH,
            link_type,
            built.bytes.clone(),
        )
        .map_err(|error| PolicyError::InvalidPacketSemantics {
            reason: error.to_string(),
        })?;
        let decoded = Dissector::new(Arc::clone(registry))
            .decode(frame, DecodeOptions::default())
            .map_err(|error| PolicyError::InvalidPacketSemantics {
                reason: error.to_string(),
            })?;
        self.policy.authorize_packet_destinations(&decoded.packet)?;
        Ok(())
    }
}
