// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use packetcraftr::dns;
use packetcraftr::policy::Policy;
use packetcraftr::target::{Hostname, Resolver};
use packetcraftr::{Client, ProviderSet};
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::error::{BoundaryError, Classified};

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
fn early_cancel_prevents_dns_execution() {
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
                let case = format!(
                    "transport={transport:?}, edns={edns:?}, progressive={progressive}, \
                     cancel_during_resolution={cancel_during_resolution}"
                );
                let signal = Cancellation::default();
                let request = dns::Request {
                    server: "dns.example.test".parse().unwrap(),
                    edns,
                    transport,
                    timeout: Duration::from_secs(1),
                    ..common::dns::tcp_request("example.test")
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
                        udp: (),
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
                    usize::from(cancel_during_resolution),
                    "{case}"
                );
                assert!(connects.take().is_empty(), "no TCP query started: {case}");
                assert_eq!(error.classification().code, "io.cancelled", "{case}");
            }
        }
    }
}

#[test]
fn blocked_owned_resolvers_retain_finite_admission_after_caller_cancellation() {
    use packetcraftr::target::BlockingResolver;
    use packetcraftr_core::budget::Deadline;
    use std::sync::{Condvar, Mutex, mpsc};
    use std::time::Instant;

    struct Gated {
        gate: Arc<(Mutex<bool>, Condvar)>,
        entered: mpsc::Sender<()>,
    }
    impl Resolver for Gated {
        fn resolve(
            &self,
            _: &Hostname,
            _: usize,
        ) -> Result<Vec<IpAddr>, packetcraftr::target::Error> {
            self.entered.send(()).unwrap();
            let (mutex, cv) = &*self.gate;
            let mut released = mutex.lock().unwrap();
            while !*released {
                released = cv.wait(released).unwrap();
            }
            Ok(vec![Ipv4Addr::new(192, 0, 2, 53).into()])
        }
    }
    const CHILD: &str = "PCR_BLOCKED_RESOLVER_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "dns_cancellation_contracts::blocked_owned_resolvers_retain_finite_admission_after_caller_cancellation", "--test-threads=1"])
            .env(CHILD, "1").status().unwrap();
        assert!(status.success());
        return;
    }
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (entered, starts) = mpsc::channel();
    let resolver = BlockingResolver::new(Gated {
        gate: Arc::clone(&gate),
        entered,
    });
    for active in 1..=packetcraftr_netio::resolution::MAX_PENDING_LOOKUPS {
        let resolver = resolver.clone();
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(10)).with_cancellation(Some(signal.clone()));
        let (done, result) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            done.send(resolver.resolve_controlled(
                &"dns.example.test".parse().unwrap(),
                16,
                &deadline,
            ))
            .unwrap();
        });
        starts.recv_timeout(Duration::from_secs(5)).unwrap();
        signal.cancel();
        let returned = result.recv_timeout(Duration::from_secs(2));
        if returned.is_err() {
            *gate.0.lock().unwrap() = true;
            gate.1.notify_all();
        }
        let error = returned
            .expect("caller stops waiting while resolver remains gated")
            .unwrap_err();
        assert_eq!(error.classification().code, "io.cancelled");
        caller.join().unwrap();
        let snapshot = packetcraftr_netio::resolution::snapshot();
        assert_eq!(snapshot.active, active);
        assert_eq!(snapshot.cleanup_retaining_capacity, active);
        assert_eq!(
            packetcraftr_netio::resources::native_snapshot().active,
            active
        );
    }
    let error = resolver
        .resolve_controlled(
            &"dns.example.test".parse().unwrap(),
            16,
            &Deadline::new(Duration::from_secs(1)),
        )
        .unwrap_err();
    assert_eq!(error.classification().code, "io.hostname_resolution");
    assert!(
        starts.try_recv().is_err(),
        "refused lookup must not execute"
    );
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    let end = Instant::now() + Duration::from_secs(5);
    while packetcraftr_netio::resources::native_snapshot().active != 0 {
        assert!(
            Instant::now() < end,
            "finished resolvers release native capacity"
        );
        std::thread::yield_now();
    }
    assert_eq!(packetcraftr_netio::resolution::snapshot().active, 0);
    assert_eq!(
        packetcraftr_netio::resolution::snapshot().cleanup_retaining_capacity,
        0
    );
}
