// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use packetcraftr::dns::{self, batch};
use packetcraftr::policy::Policy;
use packetcraftr::target::{Family, Target};
use packetcraftr::{Client, ProviderSet};
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Kind};
use packetcraftr_netio::tcp;

use common::{Step, Steps};

/// A TCP provider whose every connection accepts the query and then times
/// out waiting for the response prefix, recording [`Step::Connect`].
#[derive(Clone, Default)]
struct SilentTcp(Steps);

impl tcp::Provider for SilentTcp {
    type Stream = SilentStream;

    fn connect(
        &self,
        endpoint: SocketAddr,
        _deadline: &Deadline,
    ) -> Result<SilentStream, tcp::Error> {
        self.0.push(Step::Connect(endpoint));
        Ok(SilentStream(endpoint))
    }
}

struct SilentStream(SocketAddr);

impl io::Read for SilentStream {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
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
        Ok(self.0)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 50_000))
    }

    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
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

/// A client over `policy` whose DNS-over-TCP queries all time out after the
/// query is written, and which never transmits UDP. The steps record every
/// TCP connection and every resolution.
fn client(policy: Policy) -> (Client<Providers>, Steps) {
    let base = common::providers(common::FixedRoutes, common::NeverTransmit);
    let steps = Steps::default();
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        ProviderSet {
            route: base.route,
            interface: base.interface,
            capture: base.capture,
            transmit: base.transmit,
            tcp: SilentTcp(steps.clone()),
            resolver: common::ScriptedResolver {
                steps: steps.clone(),
                ..base.resolver
            },
        },
    );
    (client, steps)
}

fn connects(steps: &Steps) -> usize {
    steps
        .take()
        .iter()
        .filter(|step| matches!(step, Step::Connect(_)))
        .count()
}

fn request(name: &str) -> dns::Request {
    dns::Request {
        server: Target::Address(Ipv4Addr::LOCALHOST.into()),
        address_family: Family::Any,
        server_port: 53,
        source_port: 40000,
        query_name: name.to_owned(),
        query_type: dns::QueryType::A,
        transaction_id: 0x1234,
        recursion_desired: true,
        edns: None,
        transport: dns::TransportMode::Tcp,
        attempts: 1,
        timeout: Duration::from_secs(1),
        queries_per_second: None,
        limits: dns::Limits::default(),
        route: Default::default(),
        collection: Default::default(),
    }
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
fn batches_authorize_combined_retry_and_transport_units_before_discovery() {
    for (transport, per_question_units) in [
        (dns::TransportMode::Udp, 2),
        (dns::TransportMode::Tcp, 4),
        (dns::TransportMode::UdpThenTcp, 6),
    ] {
        let mut question = request("a");
        question.transport = transport;
        question.attempts = 2;
        question.edns = Some(dns::EdnsRequest {
            udp_payload_size: 1232,
            dnssec_ok: true,
        });
        // Each question alone fits; the batch's combined units do not.
        let (client, steps) = client(Policy {
            max_packets_per_operation: 3 * per_question_units - 1,
            ..Policy::default()
        });
        let error = client
            .dns_batch(
                batch([question.clone(), question.clone(), question]),
                batch::Collector::default(),
            )
            .unwrap_err();
        assert_eq!(error.classification().code, "policy.traffic_unit_limit");
        assert!(steps.take().is_empty(), "nothing is resolved or connected");
    }
}

#[test]
fn batches_authorize_combined_query_bytes_before_discovery() {
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
fn batch_output_failure_prevents_later_retries_and_questions() {
    let mut first = request("first.test");
    first.attempts = 2;
    let (client, steps) = client(Policy::default());
    let error = client
        .dns_batch(
            batch([first, request("second.test"), request("third.test")]),
            |_: batch::Event| -> Result<(), BoundaryError> {
                Err(BoundaryError::new(
                    "output failed",
                    Classification::new("io.test_output", Kind::Io, None),
                    Vec::new(),
                ))
            },
        )
        .unwrap_err();
    assert!(matches!(error, dns::Error::Output { .. }));
    assert_eq!(error.classification().code, "io.test_output");
    assert_eq!(connects(&steps), 1, "only the first query ran");
}

#[test]
fn the_collector_joins_each_completed_question_with_its_own_events() {
    let mut first = request("first.test");
    first.attempts = 2;
    let (client, _steps) = client(Policy::default());
    let collector = batch::Collector::default();
    let report = client
        .dns_batch(batch([first, request("second.test")]), collector.clone())
        .unwrap();
    assert_eq!(report.status_counts(), (2, 0, 0));
    let aggregate = collector.finish(report).unwrap();
    let attempts = aggregate
        .questions
        .iter()
        .map(|question| question.result.as_ref().unwrap().attempts().len())
        .collect::<Vec<_>>();
    assert_eq!(attempts, [2, 1]);
    assert_eq!(
        aggregate.questions[1]
            .result
            .as_ref()
            .unwrap()
            .report()
            .query_name,
        "second.test."
    );
}

#[test]
fn batch_cancellation_during_retry_wait_retains_confirmed_traffic() {
    #[derive(Clone)]
    struct CancellingClock(Cancellation);
    impl packetcraftr::clock::Clock for CancellingClock {
        type Error = io::Error;

        fn sleep(&self, _: Duration, _: &Deadline) -> Result<(), Self::Error> {
            self.0.cancel();
            Err(io::Error::other("interrupted clock"))
        }
    }

    let mut first = request("first.test");
    first.attempts = 2;
    let expected_bytes = framed_query_bytes(&first);
    let signal = Cancellation::default();
    let (client, steps) = client(Policy::default());
    let client = client
        .with_cancellation(signal.clone())
        .with_clock(CancellingClock(signal));
    let report = client
        .dns_batch(
            batch([first, request("never.test")]),
            batch::Collector::default(),
        )
        .unwrap();
    assert_eq!(report.status_counts(), (0, 1, 1));
    assert!(matches!(
        report.questions[0].error,
        Some(dns::Error::Cancelled(_))
    ));
    assert_eq!(report.stats.bytes, expected_bytes);
    assert_eq!(connects(&steps), 1);
}

#[test]
fn a_pre_cancelled_batch_leaves_every_question_unattempted() {
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

#[test]
fn batch_rejects_mixed_server_identity_before_authorization() {
    for change_port in [false, true] {
        let mut second = request("second.test");
        if change_port {
            second.server_port = 5353;
        } else {
            second.server = Target::Address(Ipv4Addr::new(127, 0, 0, 2).into());
        }
        let (client, steps) = client(Policy {
            max_packets_per_operation: 0,
            ..Policy::default()
        });
        let error = client
            .dns_batch(
                batch([request("first.test"), second]),
                batch::Collector::default(),
            )
            .unwrap_err();
        assert_eq!(error.classification().code, "cli.dns_limit");
        assert!(steps.take().is_empty());
    }
}

#[derive(Clone, Default)]
struct RecordingClock(std::sync::Arc<std::sync::Mutex<Vec<Duration>>>);

impl RecordingClock {
    fn delays(&self) -> Vec<Duration> {
        self.0.lock().unwrap().clone()
    }
}

impl packetcraftr::clock::Clock for RecordingClock {
    type Error = std::convert::Infallible;

    fn sleep(&self, delay: Duration, _: &Deadline) -> Result<(), Self::Error> {
        self.0.lock().unwrap().push(delay);
        Ok(())
    }
}

#[test]
fn rate_intervals_are_shared_across_single_attempt_questions() {
    let mut questions = [request("a"), request("b"), request("c")];
    for question in &mut questions {
        question.queries_per_second = Some(2);
    }
    let clock = RecordingClock::default();
    let (client, steps) = client(Policy::default());
    let report = client
        .with_clock(clock.clone())
        .dns_batch(batch(questions), batch::Collector::default())
        .unwrap();
    assert_eq!(report.status_counts(), (3, 0, 0));
    assert_eq!(clock.delays(), [Duration::from_millis(500); 2]);
    assert!(report.stats.elapsed >= Duration::from_secs(1));
    assert_eq!(connects(&steps), 3);
}

#[test]
fn the_shared_deadline_can_prevent_an_interquestion_wait() {
    let mut questions = [request("a"), request("b")];
    for question in &mut questions {
        question.queries_per_second = Some(1);
        question.timeout = Duration::from_millis(50);
        question.limits.max_duration = Duration::from_millis(500);
    }
    let expected_bytes = framed_query_bytes(&questions[0]);
    let clock = RecordingClock::default();
    let (client, steps) = client(Policy::default());
    let report = client
        .with_clock(clock.clone())
        .dns_batch(batch(questions), batch::Collector::default())
        .unwrap();
    assert_eq!(report.status_counts(), (1, 0, 1));
    assert_eq!(report.stats.bytes, expected_bytes);
    assert_eq!(connects(&steps), 1);
    assert!(clock.delays().is_empty());
}
