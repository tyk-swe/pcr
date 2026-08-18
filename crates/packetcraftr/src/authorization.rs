// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Authorization of built packets and their final wire representation.

use std::sync::{Arc, OnceLock};

use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::{build::BuiltPacket, decode::Dissector, registry::Registry};
use packetcraftr_netio::{Error as LiveIoError, link::Mode as LinkMode};

use crate::Client;
use crate::Error;

impl<R, N, I> Client<R, N, I> {
    pub(crate) fn authorize_built(
        &self,
        built: &BuiltPacket,
        confirm_live_opt_in: bool,
    ) -> Result<(), Error> {
        self.policy.authorize_packet_destinations(&built.packet)?;
        if built.requires_live_opt_in {
            if !confirm_live_opt_in {
                return Err(Error::LiveOptInRequired);
            }
            if !self.policy.allow_live_opt_in_packets {
                return Err(crate::policy::Error::LiveOptInPacket.into());
            }
        }
        Ok(())
    }

    pub(crate) fn authorize_final_wire(
        &self,
        built: &BuiltPacket,
        route: &packetcraftr_netio::route::Plan,
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
            .map_err(|reason| crate::policy::Error::InvalidPacketSemantics {
                reason: reason.clone(),
            })?;
        if registry.root_for_link_type(link_type.0).is_none() {
            return Err(crate::policy::Error::InvalidPacketSemantics {
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
        .map_err(|error| crate::policy::Error::InvalidPacketSemantics {
            reason: error.to_string(),
        })?;
        let decoded = Dissector::new(Arc::clone(registry))
            .decode(frame, packetcraftr_core::decode::Options::default())
            .map_err(|error| crate::policy::Error::InvalidPacketSemantics {
                reason: error.to_string(),
            })?;
        self.policy.authorize_packet_destinations(&decoded.packet)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use packetcraftr_core::Packet;
    use packetcraftr_core::build::{Builder, Context, Mode, Options};
    use packetcraftr_core::layer::Raw;

    use crate::{Client, Error, policy};

    fn built_packet(mode: Mode) -> packetcraftr_core::build::BuiltPacket {
        let registry =
            Arc::new(packetcraftr_core::protocol::builtin::registry().expect("built-in registry"));
        let mut packet = Packet::new();
        packet.push(Raw::new(vec![1, 2, 3]));
        Builder::new(registry)
            .build(
                packet,
                Context::default(),
                Options {
                    mode,
                    ..Options::default()
                },
            )
            .expect("raw packet builds")
    }

    fn client(policy: policy::Policy) -> Client<(), (), ()> {
        Client {
            registry: Arc::new(
                packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
            ),
            routes: (),
            neighbors: (),
            io: (),
            policy,
        }
    }

    #[test]
    fn packets_requiring_live_opt_in_need_both_independent_gates() {
        let built = built_packet(Mode::Permissive);
        let denied = client(policy::Policy::default());

        assert!(matches!(
            denied.authorize_built(&built, false),
            Err(Error::LiveOptInRequired)
        ));
        assert!(matches!(
            denied.authorize_built(&built, true),
            Err(Error::Policy(policy::Error::LiveOptInPacket))
        ));

        let allowed = client(policy::Policy {
            allow_live_opt_in_packets: true,
            ..policy::Policy::default()
        });
        assert!(matches!(
            allowed.authorize_built(&built, false),
            Err(Error::LiveOptInRequired)
        ));
        allowed
            .authorize_built(&built, true)
            .expect("both live opt-in gates allow the packet");
    }

    #[test]
    fn ordinary_strict_packets_need_neither_live_opt_in_gate() {
        let built = built_packet(Mode::Strict);
        let client = client(policy::Policy::default());

        client
            .authorize_built(&built, false)
            .expect("ordinary strict packet needs no live opt-in");
    }

    #[test]
    fn live_opt_in_gate_defaults_are_false() {
        assert!(!policy::Policy::default().allow_live_opt_in_packets);
        assert!(!crate::send::Options::default().confirm_live_opt_in);
        assert!(!crate::fuzz::LiveOptions::default().confirm_live_opt_in);
    }
}
