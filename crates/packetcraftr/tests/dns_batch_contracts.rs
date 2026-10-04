// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;

use std::cell::Cell;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;

use packetcraftr::dns::{self, batch};
use packetcraftr::policy::Policy;
use packetcraftr::{Client, ProviderSet};
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::error::Classified;
use packetcraftr_netio::tcp;

use common::dns::tcp_request as request;
use common::{Step, Steps};

#[derive(Clone, Default)]
struct SilentTcp {
    steps: Steps,
    cancel_on_read: Option<Cancellation>,
}

impl tcp::Provider for SilentTcp {
    type Stream = SilentStream;

    fn connect(
        &self,
        endpoint: SocketAddr,
        _deadline: &Deadline,
    ) -> Result<SilentStream, tcp::Error> {
        self.steps.push(Step::Connect(endpoint));
        Ok(SilentStream {
            endpoint,
            read_timeout: Cell::new(None),
            cancel_on_read: self.cancel_on_read.clone(),
        })
    }
}

struct SilentStream {
    endpoint: SocketAddr,
    read_timeout: Cell<Option<Duration>>,
    cancel_on_read: Option<Cancellation>,
}

impl io::Read for SilentStream {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        if let Some(signal) = &self.cancel_on_read {
            signal.cancel();
        }
        thread::sleep(self.read_timeout.get().unwrap_or_default());
        Err(io::ErrorKind::TimedOut.into())
    }
}

impl io::Write for SilentStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl tcp::Stream for SilentStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.endpoint)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 50_000))
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.read_timeout.set(timeout);
        Ok(())
    }

    fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

type Providers = ProviderSet<
    common::FixedRoutes,
    common::Interfaces,
    common::NeverTransmit,
    common::NeverTransmit,
    SilentTcp,
    common::ScriptedResolver,
>;

fn client(policy: Policy) -> (Client<Providers>, Steps) {
    client_with(policy, None)
}

fn client_with(policy: Policy, cancel_on_read: Option<Cancellation>) -> (Client<Providers>, Steps) {
    let steps = Steps::default();
    let providers = common::providers(common::FixedRoutes, common::NeverTransmit)
        .with_tcp(SilentTcp {
            steps: steps.clone(),
            cancel_on_read,
        })
        .with_resolver(common::ScriptedResolver {
            steps: steps.clone(),
        });
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        providers,
    );
    (client, steps)
}

fn batch(questions: impl IntoIterator<Item = dns::Request>) -> batch::Request {
    batch::Request {
        questions: questions.into_iter().collect(),
    }
}

fn framed_query_bytes(request: &dns::Request) -> u64 {
    dns::wire::encode_query(
        &request.query_name,
        request.query_type,
        request.transaction_id,
        request.recursion_desired,
        request.edns,
    )
    .unwrap()
    .len() as u64
        + 2
}

#[test]
fn batches_authorize_before_disc() {
    let questions = [request("a"), request("longer.example.test"), request("z")];
    let total = questions.iter().map(framed_query_bytes).sum::<u64>();
    let policy = Policy {
        max_bytes_per_operation: total - 1,
        ..Policy::default()
    };
    assert!(
        questions
            .iter()
            .all(|question| framed_query_bytes(question) <= policy.max_bytes_per_operation)
    );
    let (client, steps) = client(policy);
    let error = client
        .dns_batch(batch(questions), batch::Collector::default())
        .unwrap_err();
    assert_eq!(error.classification().code, "policy.traffic_byte_limit");
    assert!(steps.take().is_empty(), "nothing is resolved or connected");
}

#[test]
fn pre_cancel_question_unattempted() {
    let signal = Cancellation::default();
    signal.cancel();
    let (client, steps) = client(Policy::default());
    let report = client
        .with_cancellation(signal)
        .dns_batch(
            batch([request("first.test"), request("never.test")]),
            batch::Collector::default(),
        )
        .unwrap();
    assert_eq!(report.status_counts(), (0, 0, 2));
    assert_eq!(report.stats, packetcraftr::Stats::default());
    assert!(steps.take().is_empty());
}
