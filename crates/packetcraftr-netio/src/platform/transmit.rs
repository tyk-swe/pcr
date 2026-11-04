// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(pcap_backend)]
mod libpcap;
#[cfg(all(target_os = "linux", native_send))]
mod namespace;
#[cfg(npcap_backend)]
mod npcap;
#[cfg(native_layer3)]
mod raw_ip;
#[cfg(any(test, all(target_os = "linux", native_send)))]
#[forbid(unsafe_code)]
mod session;

use crate::Error;
#[cfg(not(native_layer2))]
use crate::transmit::Layer2Frame;
#[cfg(not(native_layer3))]
use crate::transmit::Layer3Frame;
#[cfg(not(all(target_os = "linux", pcap_backend)))]
use crate::transmit::SystemProvider;
use crate::transmit::{Outbound, Provider, Report};
#[cfg(any(not(native_layer2), not(native_layer3)))]
use crate::{NativeCapability, Unsupported};

#[cfg(pcap_backend)]
use libpcap::send_layer2;
#[cfg(npcap_backend)]
use npcap::send_layer2;
#[cfg(native_layer3)]
use raw_ip::send_layer3;

pub(crate) fn send(outbound: Outbound<'_>) -> Result<Report, Error> {
    match outbound {
        Outbound::Layer2(frame) => {
            #[cfg(native_layer2)]
            super::interface::verify_identity(&frame.route().decision.interface)?;
            send_layer2(frame)
        }
        Outbound::Layer3(frame) => {
            #[cfg(native_layer3)]
            super::interface::verify_identity(&frame.route().decision.interface)?;
            send_layer3(frame)
        }
    }
}

pub(crate) fn session() -> Box<dyn Provider> {
    #[cfg(all(target_os = "linux", pcap_backend))]
    let fallback = libpcap::session();
    #[cfg(not(all(target_os = "linux", pcap_backend)))]
    let fallback = SystemProvider;

    #[cfg(all(target_os = "linux", native_layer3))]
    {
        raw_ip::session::wrap(fallback)
    }
    #[cfg(not(all(target_os = "linux", native_layer3)))]
    {
        Box::new(fallback)
    }
}

#[cfg(not(native_layer2))]
fn send_layer2(_frame: Layer2Frame<'_>) -> Result<Report, Error> {
    Err(Unsupported::unbuilt(
        NativeCapability::Transmission(crate::link::Mode::Layer2),
        cfg!(feature = "native-layer2"),
        "native-layer2",
        "Layer 2 injection",
    )
    .into())
}

#[cfg(not(native_layer3))]
fn send_layer3(_frame: Layer3Frame<'_>) -> Result<Report, Error> {
    Err(Unsupported::unbuilt(
        NativeCapability::Transmission(crate::link::Mode::Layer3),
        cfg!(feature = "native-layer3"),
        "native-layer3",
        "raw IP transmission",
    )
    .into())
}
