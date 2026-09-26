// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The system transmit provider refuses a layer whose backend this build
//! doesn't include. Each test runs only in builds without that layer, such as
//! `--no-default-features --features native-layer3` for Layer 2.

#![cfg(not(all(native_layer2, native_layer3)))]

use std::net::{IpAddr, Ipv4Addr};

use bytes::Bytes;
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::{
    Error,
    interface::Id as InterfaceId,
    link::{Capability, Mode},
    route::{Decision, Scope, SelectionReason},
    transmit::{self, Outbound, Provider as _, Route},
};

fn decision() -> Decision {
    Decision {
        interface: InterfaceId {
            name: "fixture0".to_owned(),
            index: 4,
        },
        source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
        selected_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))),
        preferred_source: None,
        next_hop: None,
        selection_reason: SelectionReason::OnLink,
        destination_scope: Scope::Global,
        mtu: 1_500,
        capability: Capability::Layer2AndLayer3,
        link_type: LinkType::ETHERNET,
    }
}

fn send(mode: Mode) -> Error {
    let decision = decision();
    let bytes = Bytes::from_static(&[0x45, 0, 0, 20]);
    let route = Route {
        decision: &decision,
        mode,
        lookup_destination: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
    };
    let outbound = Outbound::try_new(&bytes, route).expect("mode is resolved");
    transmit::SystemProvider
        .send(outbound)
        .expect_err("this build has no backend for the layer")
}

fn assert_capability_refusal(error: &Error, capability: &str) {
    assert!(
        matches!(error, Error::Unsupported { message, source: None } if message.contains(capability)),
        "{error:?}"
    );
    let classification = error.classification();
    assert_eq!(classification.code, "capability.unsupported");
    assert_eq!(classification.kind, Kind::Capability);
}

#[cfg(not(native_layer2))]
#[test]
fn a_build_without_layer2_refuses_a_layer2_frame_with_a_capability_error() {
    assert_capability_refusal(&send(Mode::Layer2), "Layer 2 injection");
}

#[cfg(not(native_layer3))]
#[test]
fn a_build_without_layer3_refuses_a_layer3_packet_with_a_capability_error() {
    assert_capability_refusal(&send(Mode::Layer3), "raw IP transmission");
}
