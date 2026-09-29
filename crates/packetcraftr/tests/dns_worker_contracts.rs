// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::Duration;

use packetcraftr::Client;
use packetcraftr::dns;
use packetcraftr::policy::Policy;
use packetcraftr::target::{Family, Target};
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::error::Classified;
use packetcraftr_netio::{resources, tcp};

struct Blocked {
    entered: mpsc::Sender<(thread::ThreadId, bool, usize)>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl tcp::Provider for Blocked {
    type Stream = tcp::SystemStream;

    fn connect(&self, _: SocketAddr, deadline: &Deadline) -> Result<Self::Stream, tcp::Error> {
        self.entered
            .send((
                thread::current().id(),
                deadline.cancellation().is_some(),
                resources::tcp_connect_snapshot().active,
            ))
            .unwrap();
        let _ = self
            .release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5));
        Err(io::Error::from(io::ErrorKind::TimedOut).into())
    }
}

#[test]
fn dns_connects_are_admitted_and_cancellation_releases_the_workflow() {
    let (entered, started) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let (completed, result) = mpsc::channel();
    let signal = Cancellation::default();
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        common::providers(common::FixedRoutes, common::NeverTransmit).with_tcp(Blocked {
            entered,
            release: Mutex::new(blocked),
        }),
    )
    .with_cancellation(signal.clone());
    let workflow = thread::spawn(move || {
        let outcome = client.dns(
            dns::Request {
                server: Target::Address(Ipv4Addr::LOCALHOST.into()),
                address_family: Family::Any,
                server_port: 53,
                source_port: 40000,
                query_name: "example.test".to_owned(),
                query_type: dns::QueryType::A,
                transaction_id: 0x1234,
                recursion_desired: true,
                edns: None,
                transport: dns::TransportMode::Tcp,
                attempts: 1,
                timeout: Duration::from_secs(3),
                queries_per_second: None,
                limits: dns::Limits::default(),
                route: Default::default(),
                collection: Default::default(),
            },
            dns::Collector::default(),
        );
        completed.send(outcome).unwrap();
    });
    let (provider_thread, has_cancellation, active) =
        started.recv_timeout(Duration::from_secs(2)).unwrap();
    signal.cancel();
    let outcome = result.recv_timeout(Duration::from_secs(2));
    let retained = resources::tcp_connect_snapshot().cleanup_retaining_capacity;
    drop(release);
    let workflow_thread = workflow.thread().id();
    workflow.join().unwrap();
    let error = outcome
        .expect("cancellation must release the workflow while connect is blocked")
        .unwrap_err();
    assert_eq!(error.classification().code, "io.cancelled");
    assert_ne!(provider_thread, workflow_thread);
    assert!(has_cancellation, "the provider keeps the client's signal");
    assert_eq!(active, 1);
    assert_eq!(
        retained, 1,
        "a stalled call keeps its admission through cleanup"
    );
}
