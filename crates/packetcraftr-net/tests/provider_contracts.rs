// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use packetcraftr_core::frame::LinkType;
use packetcraftr_net::{
    Error, capture,
    link::{Capability, MacAddress, Mode},
    route::{Decision, InterfaceId, Options, Planner, Provider, Scope, SelectionReason},
};
use packetcraftr_packet::{Packet, layer::Raw};
use packetcraftr_protocol::link::Ethernet;

struct PassiveRoutes {
    interface_calls: AtomicUsize,
}

impl Provider for PassiveRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error> {
        panic!("destination-free planning must not perform an IP route lookup")
    }

    fn lookup_interface(&self, interface: &InterfaceId) -> Result<Option<Decision>, Self::Error> {
        self.interface_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(Decision {
            interface: interface.clone(),
            source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
            selected_address: None,
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::InterfaceOnly,
            destination_scope: Scope::Link,
            mtu: 1_500,
            capability: Capability::Layer2,
            link_type: LinkType::ETHERNET,
        }))
    }
}

#[test]
fn capture_queue_limits_reject_zero_oversize_and_inconsistent_values() {
    let defaults = capture::Limits::default();
    assert_eq!(
        defaults.validate().expect("defaults must be valid"),
        defaults
    );

    assert!(matches!(
        capture::Limits {
            max_frames: 0,
            ..defaults
        }
        .validate(),
        Err(Error::InvalidCaptureQueueLimit {
            field: "max_frames",
            ..
        })
    ));
    assert!(matches!(
        capture::Limits {
            max_bytes: 8,
            snap_length: 9,
            ..defaults
        }
        .validate(),
        Err(Error::InvalidCaptureQueueLimit {
            field: "snap_length",
            ..
        })
    ));
}

#[test]
fn capture_statistics_validate_and_classify_loss() {
    assert!(matches!(
        capture::Statistics {
            dropped_bytes: 1,
            ..capture::Statistics::default()
        }
        .validate(),
        Err(Error::InvalidCaptureStatistics { .. })
    ));

    let overflow = capture::Statistics {
        dropped_frames: 2,
        dropped_bytes: 10,
        overflow_events: 1,
        ..capture::Statistics::default()
    };
    assert!(overflow.validate().is_ok());
    assert!(matches!(
        overflow.evidence_loss_error(),
        Some(Error::CaptureQueueOverflow {
            dropped_frames: 2,
            overflow_events: 1,
            ..
        })
    ));
}

#[test]
fn destination_free_layer2_planning_uses_only_the_requested_interface() {
    let mut packet = Packet::new();
    packet.push(Ethernet {
        destination: [2, 0, 0, 0, 0, 2],
        ..Ethernet::default()
    });
    packet.push(Raw::new(vec![1_u8]));
    let interface = InterfaceId {
        name: "test0".to_owned(),
        index: 7,
    };
    let provider = PassiveRoutes {
        interface_calls: AtomicUsize::new(0),
    };

    let plan = Planner
        .plan(
            &packet,
            None,
            &Options {
                link_mode: Mode::Layer2,
                interface: Some(interface.clone()),
                preferred_source: None,
            },
            &provider,
        )
        .expect("explicit Layer 2 interface must plan passively");

    assert_eq!(provider.interface_calls.load(Ordering::SeqCst), 1);
    assert_eq!(plan.route.interface, interface);
    assert_eq!(plan.mode, Mode::Layer2);
    assert_eq!(plan.destination_mac, Some(MacAddress([2, 0, 0, 0, 0, 2])));
    assert!(!plan.needs_neighbor_resolution());
}
