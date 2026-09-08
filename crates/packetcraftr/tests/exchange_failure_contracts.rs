// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Faults at external-effect boundaries use existing provider contracts.
mod support;

use packetcraftr::{Client, exchange, policy::Policy};
use packetcraftr_core::{
    Packet,
    budget::Cancellation,
    layer::Raw,
    protocol::{builtin, network::Ipv4, transport::Udp},
    template::Template,
};
use packetcraftr_netio::{Error, capture, link::Mode, transmit};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    Start,
    Ready,
    PartialSend,
    Receive,
    Shutdown,
    CancelReady,
    Callback,
}
#[derive(Default)]
struct State {
    ready: bool,
    sends: usize,
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
        state.sends += 1;
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
        if self.fault == Fault::Receive && state.sends > 0 {
            return Err(injected());
        }
        drop(state);
        std::thread::sleep(timeout);
        Ok(None)
    }
    fn shutdown(&mut self) -> Result<(), Error> {
        self.state.lock().unwrap().shutdowns += 1;
        if self.fault == Fault::Shutdown {
            Err(injected())
        } else {
            Ok(())
        }
    }
    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
    }
}

#[test]
fn phase_failures_never_report_success_or_skip_capture_cleanup() {
    use packetcraftr_core::error::{BoundaryError, Classification, Kind};
    for (fault, expected_sends, expected_shutdowns) in [
        (Fault::Start, 0, 0),
        (Fault::Ready, 0, 1),
        (Fault::PartialSend, 1, 1),
        (Fault::Receive, 1, 1),
        (Fault::Shutdown, 1, 1),
        (Fault::CancelReady, 0, 1),
        (Fault::Callback, 1, 1),
    ] {
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
        let mut options = exchange::Options {
            timeout: Duration::from_secs(1),
            ..exchange::Options::default()
        };
        options.send.plan.link_mode = Mode::Layer3;
        let result = client.exchange_with_events(&Template::new(packet), options, move |_| {
            if fault == Fault::Callback {
                Err(BoundaryError::new(
                    "injected callback failure",
                    Classification::new("io.fixture", Kind::Io, None),
                    Vec::new(),
                ))
            } else {
                Ok(())
            }
        });
        assert!(
            result.is_err(),
            "{fault:?} must leave an incomplete exchange"
        );
        let state = state.lock().unwrap();
        assert_eq!(state.sends, expected_sends, "{fault:?}: {result:?}");
        assert_eq!(state.shutdowns, expected_shutdowns, "{fault:?}: {result:?}");
    }
}
