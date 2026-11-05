// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(
    unsafe_code,
    reason = "the socket address must be checked as a Linux sockaddr_ll"
)]

use std::mem::size_of;

use crate::Error;
use crate::interface::Id;
use crate::platform::transmit::namespace::{ExecutionContext, Reuse};
use crate::platform::transmit::session::{Backend as SessionBackend, Preparation};
use crate::transmit::{Layer2Frame, Outbound, Provider, Report, SystemProvider};

pub(super) struct Backend {
    context: ExecutionContext,
}

impl Backend {
    pub(super) fn new() -> Self {
        Self {
            context: ExecutionContext::capture(),
        }
    }
}

impl SessionBackend for Backend {
    type Key = Id;
    type Packet<'a> = Layer2Frame<'a>;
    type Resource = pcap::Capture<pcap::Active>;

    fn prepare<'a>(
        &self,
        outbound: Outbound<'a>,
    ) -> Result<Preparation<Id, Layer2Frame<'a>>, Error> {
        let Reuse::Verified = self.context.verify()? else {
            return Ok(Preparation::Fallback);
        };
        let Outbound::Layer2(frame) = outbound else {
            return Ok(Preparation::Fallback);
        };
        let interface = &frame.route().decision.interface;
        crate::platform::interface::verify_identity(interface)?;
        super::validate_length(frame)?;
        Ok(Preparation::Reusable {
            key: interface.clone(),
            packet: frame,
        })
    }

    fn open(&self, frame: &Layer2Frame<'_>) -> Result<Option<Self::Resource>, Error> {
        let capture = super::open(*frame)?;
        crate::platform::interface::verify_identity(&frame.route().decision.interface)?;
        let socket = socket2::SockRef::from(&capture);
        let Ok(address) = socket.local_addr() else {
            return Ok(None);
        };
        if address.family() != libc::AF_PACKET as libc::sa_family_t
            || address.len() < size_of::<libc::sockaddr_ll>() as libc::socklen_t
            || socket.r#type().ok() != Some(socket2::Type::RAW)
        {
            return Ok(None);
        }
        let mut storage = address.as_storage();
        // SAFETY: the family and length establish a fully initialized sockaddr_ll.
        let packet = unsafe { storage.view_as::<libc::sockaddr_ll>() };
        if u32::try_from(packet.sll_ifindex).ok() != Some(frame.route().decision.interface.index) {
            return Ok(None);
        }
        Ok(Some(capture))
    }

    fn send(&self, capture: &mut Self::Resource, frame: Layer2Frame<'_>) -> Result<Report, Error> {
        super::submit(capture, frame)
    }

    fn fallback(&self, outbound: Outbound<'_>) -> Result<Report, Error> {
        SystemProvider.send(outbound)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use packetcraftr_core::frame::LinkType;

    use super::*;
    use crate::platform::transmit::namespace::tests::thread_root;
    use crate::{
        link::{Capability, Mode},
        route::{Decision, Scope, SelectionReason},
        transmit::Route,
    };

    fn decision() -> Decision {
        Decision {
            interface: Id {
                name: "test0".to_owned(),
                index: u32::MAX,
            },
            source_mac: None,
            selected_source: None,
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Link,
            mtu: 1500,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        }
    }

    fn frame() -> Bytes {
        Bytes::from_static(&[0; 60])
    }

    fn outbound<'a>(bytes: &'a Bytes, decision: &'a Decision) -> Outbound<'a> {
        Outbound::try_new(
            bytes,
            Route {
                decision,
                mode: Mode::Layer2,
                lookup_destination: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn missing_snapshot_selects_one_shot_send() {
        let empty_root = tempfile::tempdir().unwrap();
        let backend = Backend {
            context: ExecutionContext::capture_at(empty_root.path()),
        };
        let (bytes, decision) = (frame(), decision());
        assert!(matches!(
            backend.prepare(outbound(&bytes, &decision)),
            Ok(Preparation::Fallback)
        ));
    }

    #[test]
    fn changed_context_rejects_before_any_send() {
        let root = thread_root();
        let backend = Backend {
            context: ExecutionContext::capture_at(root.path()),
        };
        std::fs::remove_file(root.path().join("status")).unwrap();
        let (bytes, decision) = (frame(), decision());
        assert!(matches!(
            backend.prepare(outbound(&bytes, &decision)),
            Err(Error::Privilege { .. })
        ));
    }
}
