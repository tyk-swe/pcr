// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use packetcraftr::dns;
use packetcraftr::policy::Policy;
use packetcraftr::target::{Family, Hostname, Resolver};
use packetcraftr::{Client, ProviderSet};
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::error::{BoundaryError, Classified};

/// Answers every hostname after cancelling the client's signal, counting
/// each resolution.
#[derive(Clone)]
struct CancellingResolver {
    signal: Cancellation,
    resolutions: Arc<AtomicUsize>,
}

impl Resolver for CancellingResolver {
    fn resolve(
        &self,
        _hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, packetcraftr::target::Error> {
        self.resolutions.fetch_add(1, Ordering::SeqCst);
        self.signal.cancel();
        Ok(vec![Ipv4Addr::new(192, 0, 2, 53).into()])
    }
}

#[test]
fn cancellation_before_authorization_or_during_resolution_prevents_dns_execution() {
    for (edns, transport) in [
        None,
        Some(dns::EdnsRequest {
            udp_payload_size: 1232,
            dnssec_ok: true,
        }),
    ]
    .into_iter()
    .flat_map(|edns| {
        [
            dns::TransportMode::Udp,
            dns::TransportMode::UdpThenTcp,
            dns::TransportMode::Tcp,
        ]
        .map(|transport| (edns, transport))
    }) {
        for progressive in [false, true] {
            for cancel_during_resolution in [true, false] {
                let signal = Cancellation::default();
                let request = dns::Request {
                    server: "dns.example.test".parse().unwrap(),
                    address_family: Family::Any,
                    server_port: 53,
                    source_port: 40_000,
                    query_name: "example.test".to_owned(),
                    query_type: dns::QueryType::A,
                    transaction_id: 0x1234,
                    recursion_desired: true,
                    edns,
                    transport,
                    attempts: 1,
                    timeout: Duration::from_secs(1),
                    queries_per_second: None,
                    limits: dns::Limits::default(),
                    route: Default::default(),
                    collection: Default::default(),
                };
                let resolutions = Arc::new(AtomicUsize::new(0));
                let base = common::providers(common::FixedRoutes, common::NeverTransmit);
                let connects = base.tcp.steps.clone();
                let client = Client::new(
                    packetcraftr_core::protocol::builtin::registry(),
                    Policy {
                        allow_hostname_resolution: true,
                        ..Policy::default()
                    },
                    ProviderSet {
                        route: base.route,
                        interface: base.interface,
                        capture: base.capture,
                        transmit: base.transmit,
                        tcp: base.tcp,
                        resolver: CancellingResolver {
                            signal: signal.clone(),
                            resolutions: Arc::clone(&resolutions),
                        },
                    },
                )
                .with_cancellation(signal.clone());
                if !cancel_during_resolution {
                    signal.cancel();
                }
                let error = if progressive {
                    client
                        .dns(request, |_: dns::Event| -> Result<(), BoundaryError> {
                            panic!("cancelled DNS operation must not publish an event")
                        })
                        .unwrap_err()
                } else {
                    client.dns(request, dns::Collector::default()).unwrap_err()
                };
                assert_eq!(
                    resolutions.load(Ordering::SeqCst),
                    usize::from(cancel_during_resolution)
                );
                assert!(connects.take().is_empty(), "no TCP query started");
                assert_eq!(error.classification().code, "io.cancelled");
            }
        }
    }
}
