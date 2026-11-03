// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(
    unsafe_code,
    reason = "the socket address must be checked as a Linux sockaddr_ll"
)]

use std::os::unix::fs::MetadataExt;
use std::{fs::File, mem::size_of};

use packetcraftr_core::error::Source;

use crate::Error;
use crate::interface::Id;
use crate::transmit::session::Backend as SessionBackend;
use crate::transmit::{Outbound, Provider, Report, SystemProvider};

pub(crate) struct Backend {
    namespace: Result<Namespace, Error>,
}

struct Namespace {
    _file: File,
    device: u64,
    inode: u64,
}

impl Backend {
    pub(crate) fn new() -> Self {
        let namespace = (|| {
            let file = File::open("/proc/thread-self/ns/net").map_err(namespace_error)?;
            let metadata = file.metadata().map_err(namespace_error)?;
            Ok(Namespace {
                _file: file,
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        })();
        Self { namespace }
    }
}

fn namespace_error(source: std::io::Error) -> Error {
    Error::Send {
        message: "cannot verify the transmission session network namespace".to_owned(),
        source: Some(Source::new(source)),
    }
}

impl SessionBackend for Backend {
    type Key = Id;
    type Resource = pcap::Capture<pcap::Active>;

    fn key(&self, outbound: Outbound<'_>) -> Result<Option<Id>, Error> {
        let namespace = self.namespace.as_ref().map_err(Clone::clone)?;
        let current = std::fs::metadata("/proc/thread-self/ns/net").map_err(namespace_error)?;
        if current.dev() != namespace.device || current.ino() != namespace.inode {
            return Err(Error::Send {
                message: "transmission session network namespace changed".to_owned(),
                source: None,
            });
        }
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
