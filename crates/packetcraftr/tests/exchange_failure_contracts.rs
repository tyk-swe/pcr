// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Faults at external-effect boundaries use existing provider contracts.
mod support;

use packetcraftr::{Client, exchange, policy::Policy};
use packetcraftr_core::{
    budget::Cancellation,
    error::{BoundaryError, Classification, Classified, Kind},
    field::FieldValue,
    layer::Raw,
    packet::Packet,
    protocol::{builtin, network::Ipv4, transport::Udp},
    template::Template,
};
use packetcraftr_netio::{Error, capture, link::Mode, transmit};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    None,
    Start,
    Ready,
    PartialSend,
    Receive,
    Shutdown,
    CancelReady,
    Callback,
    CallbackAndShutdown,
}
#[derive(Default)]
struct State {
    ready: bool,
    /// Every frame handed to the sender, in transmission order.
    sent: Vec<Vec<u8>>,
    shutdowns: usize,
    reads: usize,
}
struct Io {
    fault: Fault,
    state: Arc<Mutex<State>>,
    signal: Cancellation,
}
struct Capture {
    fault: Fault,
    state: Arc<Mutex<State>>,
    signal: Cancellation,
    metadata: capture::Metadata,
}
fn injected() -> Error {
    Error::Capture {
        message: "injected provider failure".to_owned(),
        source: None,
    }
}
impl transmit::Sender for Io {
    fn send(&self, frame: transmit::Frame<'_>) -> Result<transmit::Report, Error> {
        let mut state = self.state.lock().unwrap();
        assert!(state.ready, "capture must be ready before any transmission");
        assert!(
            !self.signal.is_cancelled(),
            "cancelled exchange transmitted"
        );
        state.sent.push(frame.bytes().to_vec());
        let count = frame.bytes().len() - usize::from(self.fault == Fault::PartialSend);
        Ok(transmit::Submission::start().complete(count, frame.bytes().clone()))
    }
}
impl capture::Provider for Io {
    type Capture = Capture;
    fn arm_capture(&self, request: &capture::Request) -> Result<Capture, Error> {
        if self.fault == Fault::Start {
            return Err(injected());
        }
        Ok(Capture {
            fault: self.fault,
            state: self.state.clone(),
            signal: self.signal.clone(),
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: packetcraftr_core::frame::LinkType::IPV4,
                snap_length: request.limits.snap_length,
            },
        })
    }
}
impl capture::Session for Capture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _: Duration) -> Result<(), Error> {
        if self.fault == Fault::Ready {
            return Err(injected());
        }
        if self.fault == Fault::CancelReady {
            self.signal.cancel();
        }
        self.state.lock().unwrap().ready = true;
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<capture::Captured>, Error> {
        let mut state = self.state.lock().unwrap();
        state.reads += 1;
        if self.fault == Fault::Receive && !state.sent.is_empty() {
            return Err(injected());
        }
        drop(state);
        std::thread::sleep(timeout);
        Ok(None)
    }
    fn shutdown(&mut self) -> Result<(), Error> {
        self.state.lock().unwrap().shutdowns += 1;
        if matches!(self.fault, Fault::Shutdown | Fault::CallbackAndShutdown) {
            Err(injected())
        } else {
            Ok(())
        }
    }
    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
    }
}

type FixtureClient = Client<support::FixedRoutes, support::NeverNeighbors, Io>;

fn fixture(fault: Fault) -> (FixtureClient, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State::default()));
    let signal = Cancellation::default();
    let client = Client::new(
        builtin::registry(),
        support::FixedRoutes,
        support::NeverNeighbors,
        Io {
            fault,
            state: state.clone(),
            signal: signal.clone(),
        },
        Policy::default(),
    )
    .with_cancellation(signal);
    (client, state)
}

fn query_packet() -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        destination: "192.0.2.1".parse().unwrap(),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 40000,
        destination_port: 9999,
        ..Udp::default()
    });
    packet.push(Raw::new(b"query".to_vec()));
    packet
}

fn layer3_options() -> exchange::Options {
    let mut options = exchange::Options {
        timeout: Duration::from_secs(1),
        ..exchange::Options::default()
    };
    options.send.plan.link_mode = Mode::Layer3;
    options
}

fn callback_failure() -> BoundaryError {
    BoundaryError::new(
        "injected callback failure",
        Classification::new("io.fixture", Kind::Io, None),
        Vec::new(),
    )
}

#[test]
fn phase_failures_never_report_success_or_skip_capture_cleanup() {
    for (fault, expected_sends, expected_shutdowns) in [
        (Fault::Start, 0, 0),
        (Fault::Ready, 0, 1),
        (Fault::PartialSend, 1, 1),
        (Fault::Receive, 1, 1),
        (Fault::Shutdown, 1, 1),
        (Fault::CancelReady, 0, 1),
        (Fault::Callback, 1, 1),
    ] {
        let (client, state) = fixture(fault);
        let result = client.exchange_with_events(
            &Template::new(query_packet()),
            layer3_options(),
            move |_| {
                if fault == Fault::Callback {
                    Err(callback_failure())
                } else {
                    Ok(())
                }
            },
        );
        assert!(
            result.is_err(),
            "{fault:?} must leave an incomplete exchange"
        );
        let state = state.lock().unwrap();
        assert_eq!(state.sent.len(), expected_sends, "{fault:?}: {result:?}");
        assert_eq!(state.shutdowns, expected_shutdowns, "{fault:?}: {result:?}");
    }
}

/// An output failure stops the exchange before its next send, and a capture
/// shutdown failure during that cleanup is reported alongside it rather than
/// replacing it.
#[test]
fn cleanup_failure_after_an_output_error_reports_both_without_a_further_send() {
    let (client, state) = fixture(Fault::CallbackAndShutdown);
    let template = Template::new(query_packet()).axis(
        1,
        "destination_port",
        vec![FieldValue::Unsigned(9999), FieldValue::Unsigned(10000)],
    );
    let error = client
        .exchange_with_events(&template, layer3_options(), |_| Err(callback_failure()))
        .expect_err("output failure must fail the exchange");

    assert!(
        matches!(
            error,
            packetcraftr::Error::ExchangeOutputAndCaptureShutdown { .. }
        ),
        "{error:?}"
    );
    assert_eq!(error.classification().code, "io.fixture");
    let causes = error.causes();
    assert!(
        causes
            .iter()
            .any(|cause| cause.contains("injected provider failure")),
        "{causes:?}"
    );
    let state = state.lock().unwrap();
    assert_eq!(state.sent.len(), 1, "no send follows the output failure");
    assert_eq!(state.shutdowns, 1);
}

/// Each scan probe reaches the wire with its own destination port, sequence
/// number, and IPv4 identification, so responses correlate to one probe.
#[test]
fn scan_materializes_distinct_correlated_identities_per_probe() {
    use packetcraftr::{
        clock::SystemClock,
        policy::PolicyAuthorizer,
        probe::{ExchangeExecutor, Transport},
        progress::Runtime,
        scan,
        target::{Family, Target},
    };

    let (client, state) = fixture(Fault::None);
    let policy = Policy::default();
    let mut authorizer = PolicyAuthorizer::for_packets(&policy);
    let registry = Arc::clone(client.registry());
    let mut executor = ExchangeExecutor::new(
        &client,
        exchange::Options {
            max_template_packets: 1,
            ..layer3_options()
        },
    );
    let request = scan::Request {
        target: Target::Address("10.0.0.2".parse().unwrap()),
        transport: Transport::Tcp,
        address_family: Family::Any,
        ports: vec![80, 81, 82],
        attempts: 1,
        timeout: Duration::from_millis(100),
        probes_per_second: None,
        limits: scan::Limits::default(),
    };
    scan::run_with_events(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut SystemClock,
        &Runtime::default(),
        |_| Ok(()),
    )
    .expect("timed-out probes still complete the scan");

    let state = state.lock().unwrap();
    assert_eq!(state.sent.len(), 3);
    let mut identifications = Vec::new();
    for (index, frame) in state.sent.iter().enumerate() {
        assert_eq!(frame[0], 0x45, "probe {index} is a plain IPv4 frame");
        assert_eq!(
            u16::from_be_bytes([frame[22], frame[23]]),
            80 + u16::try_from(index).unwrap(),
            "probe {index} destination port"
        );
        assert_eq!(
            u32::from_be_bytes([frame[24], frame[25], frame[26], frame[27]]),
            u32::try_from(index).unwrap(),
            "probe {index} TCP sequence"
        );
        identifications.push(u16::from_be_bytes([frame[4], frame[5]]));
    }
    identifications.sort_unstable();
    identifications.dedup();
    assert_eq!(identifications.len(), 3, "IPv4 identifications must differ");
}
