// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Cancellation stops a live campaign before its first case reaches any
//! provider.

mod common;

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use bytes::Bytes;
use packetcraftr::policy::Policy;
use packetcraftr::{Client, fuzz};
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::codec::{self, LayerCodec};
use packetcraftr_core::error::Classified;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::fuzz as packet_fuzz;
use packetcraftr_core::layer::{Id, Layer, Raw};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr_core::registry::Registry;

use common::{RecordingRoutes, RecordingTransmit, Steps};

/// Runs `request` on a client over `registry` whose every provider records
/// into the returned steps, sharing `signal`, publishing either to a
/// collector or to a sink that must never be reached. Returns the error, the
/// recorded provider steps, and how many captures were armed.
fn run_cancelled(
    registry: Arc<Registry>,
    signal: Cancellation,
    request: fuzz::Request,
    progressive: bool,
) -> (fuzz::Error, Vec<common::Step>, usize) {
    let steps = Steps::default();
    let io = RecordingTransmit::new(steps.clone());
    let mut providers = common::providers(RecordingRoutes(steps.clone()), io.clone());
    providers.interface.steps = steps.clone();
    let client = Client::new(registry, Policy::default(), providers).with_cancellation(signal);
    let error = if progressive {
        client
            .fuzz(request, |_| {
                panic!("a cancelled campaign must not publish a case")
            })
            .unwrap_err()
    } else {
        client
            .fuzz(request, fuzz::Collector::default())
            .unwrap_err()
    };
    (error, steps.take(), io.armed())
}

#[test]
fn cancellation_at_entry_prevents_the_first_live_case() {
    for progressive in [false, true] {
        let signal = Cancellation::default();
        signal.cancel();
        let campaign = packet_fuzz::Request {
            cases: 1,
            strategies: vec![packet_fuzz::Strategy::BitFlip],
            targets: vec!["2.bytes".parse().unwrap()],
            ..packet_fuzz::Request::default()
        };
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(192, 0, 2, 2),
                ..Ipv4::default()
            })
            .push(Udp {
                destination_port: 9,
                ..Udp::default()
            })
            .push(Raw::new(vec![1, 2, 3]));
        let request = fuzz::Request {
            timeout: Duration::from_millis(1),
            ..fuzz::Request::new(campaign, packet)
        };
        let (error, steps, armed) = run_cancelled(
            packetcraftr_core::protocol::builtin::registry(),
            signal,
            request,
            progressive,
        );
        assert_eq!(steps, [], "progressive={progressive}");
        assert_eq!(armed, 0);
        assert_eq!(error.classification().code, "io.cancelled");
    }
}

#[derive(Debug)]
struct CancellingCodec {
    inner: Arc<dyn LayerCodec>,
    signal: Cancellation,
    builds: Arc<AtomicUsize>,
}

impl LayerCodec for CancellingCodec {
    fn protocol_id(&self) -> &'static Id {
        self.inner.protocol_id()
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &codec::LayerEncodeContext<'_>,
    ) -> Result<codec::EncodedLayer, codec::Error> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        let encoded = self.inner.encode(layer, payload, context)?;
        self.signal.cancel();
        Ok(encoded)
    }

    fn decode(
        &self,
        input: Bytes,
        context: &codec::LayerDecodeContext<'_>,
    ) -> Result<codec::DecodedLayer, codec::Error> {
        self.inner.decode(input, context)
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, codec::Error> {
        self.inner.make_layer(fields)
    }
}

#[test]
fn cancellation_during_preparation_stops_generation_before_live_budget_validation() {
    for progressive in [false, true] {
        for cases in [1, 3] {
            let signal = Cancellation::default();
            let builds = Arc::new(AtomicUsize::new(0));
            let mut registry = Registry::builder();
            registry
                .register_codec(
                    CancellingCodec {
                        inner: packetcraftr_core::protocol::builtin::registry()
                            .codec("raw")
                            .unwrap()
                            .clone(),
                        signal: signal.clone(),
                        builds: builds.clone(),
                    },
                    &[],
                )
                .unwrap();
            let campaign = packet_fuzz::Request {
                cases,
                strategies: vec![packet_fuzz::Strategy::BitFlip],
                targets: vec!["0.bytes".parse().unwrap()],
                limits: packet_fuzz::Limits {
                    max_duration: Duration::from_secs(60),
                    ..packet_fuzz::Limits::default()
                },
                ..packet_fuzz::Request::default()
            };
            let mut packet = Packet::new();
            packet.push(Raw::new(vec![1, 2, 3]));
            let request = fuzz::Request {
                // Preparation plus even one live case would exceed the budget.
                timeout: campaign.limits.max_duration,
                ..fuzz::Request::new(campaign, packet)
            };
            let (error, steps, armed) = run_cancelled(
                Arc::new(registry.build().unwrap()),
                signal,
                request,
                progressive,
            );
            assert_eq!(builds.load(Ordering::SeqCst), 1);
            assert_eq!(steps, []);
            assert_eq!(armed, 0);
            assert_eq!(error.classification().code, "io.cancelled");
        }
    }
}
