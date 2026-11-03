// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(
    unsafe_code,
    reason = "the socket address must be checked as a Linux sockaddr_ll"
)]

use std::mem::size_of;

use crate::Error;
use crate::interface::Id;
use crate::platform::transmit::namespace::ExecutionContext;
use crate::transmit::session::Backend as SessionBackend;
use crate::transmit::{Outbound, Provider, Report, SystemProvider};

pub(crate) struct Backend {
    context: Result<ExecutionContext, Error>,
}

impl Backend {
    pub(crate) fn new() -> Self {
        Self {
            context: ExecutionContext::capture(),
        }
    }
}

impl SessionBackend for Backend {
    type Key = Id;
    type Resource = pcap::Capture<pcap::Active>;

    fn key(&self, outbound: Outbound<'_>) -> Result<Option<Id>, Error> {
        self.context.as_ref().map_err(Clone::clone)?.verify()?;
        let Outbound::Layer2(frame) = outbound else {
            return Ok(None);
        };
        let interface = &frame.route().decision.interface;
        crate::platform::verify_interface_identity(interface)?;
        super::validate_length(frame)?;
        Ok(Some(interface.clone()))
    }

    fn open(&self, outbound: Outbound<'_>) -> Result<Option<Self::Resource>, Error> {
        let Outbound::Layer2(frame) = outbound else {
            return Ok(None);
        };
        let capture = super::open(frame)?;
        crate::platform::verify_interface_identity(&frame.route().decision.interface)?;
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

    fn send(&self, capture: &mut Self::Resource, outbound: Outbound<'_>) -> Result<Report, Error> {
        let Outbound::Layer2(frame) = outbound else {
            unreachable!()
        };
        super::submit(capture, frame)
    }

    fn fallback(&self, outbound: Outbound<'_>) -> Result<Report, Error> {
        SystemProvider.send(outbound)
    }
}
